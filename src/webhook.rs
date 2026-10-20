//! DumpLedger webhook receiver support: signature verification for the
//! daemon's `POST /webhooks` route and boot-time self-registration over the
//! WH2 webhook-admin bearer token (dump-ledger `docs/webhook-notifications.md`).
//!
//! The feed follower remains the resumable truth; the webhook is a
//! low-latency tap. Events are applied through the same idempotent
//! [`crate::sync::apply_event`] path the follower uses, so redelivery needs
//! no extra dedupe state. The webhook never advances the feed cursor.

use std::time::Duration;

use sha2::Digest;

use crate::client::LedgerClient;
use crate::config::Config;
use crate::state::Store;
use crate::types::{AnalyzerError, Result};
use crate::wire::WebhookSubscription;

/// Secret/table keys in the migration-2 `secrets` store.
const SUBSCRIPTION_ID_KEY: &str = "webhook.subscription_id";
const SECRET_KEY: &str = "webhook.secret";

/// Cadence for retrying registration after a failure. Registration is an
/// optimization over the feed follower, so a slow retry is sufficient and a
/// misconfigured admin token never hot-loops.
const REGISTRATION_RETRY: Duration = Duration::from_secs(300);

/// HMAC-SHA256 of `message` keyed by `key` (RFC 2104; sha2 is already a
/// dependency, so no new manifest entry).
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = sha2::Sha256::digest(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for (i, byte) in key_block.iter().enumerate() {
        ipad[i] = byte ^ 0x36;
        opad[i] = byte ^ 0x5c;
    }
    let mut inner = sha2::Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = sha2::Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

/// Verifies a `X-DumpLedger-Signature-256` header value against the raw body
/// in constant time. The header shape is `sha256=<64 lowercase hex>`.
pub fn verify_signature(secret: &str, body: &[u8], header: &str) -> bool {
    let Some(hex_digest) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex_decode(hex_digest) else {
        return false;
    };
    let actual = hmac_sha256(secret.as_bytes(), body);
    expected
        .iter()
        .zip(actual.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn hex_decode(text: &str) -> std::result::Result<[u8; 32], ()> {
    if text.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16).ok_or(())?;
        let lo = (pair[1] as char).to_digit(16).ok_or(())?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

/// The stored webhook signing secret, when registration has completed.
pub fn stored_secret(store: &Store) -> Result<Option<String>> {
    store
        .secrets()
        .get(SECRET_KEY)
        .map_err(|err| AnalyzerError::State(format!("reading webhook secret: {err}")))
}

/// Ensures the daemon's subscription exists at the ledger and the signing
/// secret is stored locally. Idempotent: an existing subscription for our
/// URL is reused when its secret is on record, otherwise rotated
/// (delete + create) because the ledger never reveals secrets after creation.
pub async fn ensure_subscription(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
) -> Result<WebhookSubscription> {
    let url = config
        .webhook_url
        .as_deref()
        .ok_or_else(|| AnalyzerError::Config("DUMP_ANALYZER_WEBHOOK_URL is required".into()))?;
    let admin = config.webhook_admin_token.as_ref().ok_or_else(|| {
        AnalyzerError::Config("DUMP_ANALYZER_WEBHOOK_ADMIN_TOKEN is required".into())
    })?;

    let existing = client
        .list_webhooks(admin)
        .await?
        .subscriptions
        .into_iter()
        .find(|subscription| subscription.url == url);
    let have_secret = stored_secret(store)?.is_some();
    if let Some(found) = existing {
        if have_secret {
            return Ok(found);
        }
        // Secret is unrecoverable server-side: rotate the subscription.
        client.delete_webhook(admin, &found.id).await?;
    }
    let created = client
        .create_webhook(admin, url, &config.webhook_actions)
        .await?;
    let secrets = store.secrets();
    secrets
        .set(SECRET_KEY, &created.secret)
        .and_then(|_| secrets.set(SUBSCRIPTION_ID_KEY, &created.subscription.id))
        .map_err(|err| AnalyzerError::State(format!("persisting webhook secret: {err}")))?;
    Ok(created.subscription)
}

/// Retries [`ensure_subscription`] on a slow cadence until it succeeds or the
/// daemon shuts down. Runs detached; the feed follower carries the truth
/// while registration is outstanding.
pub async fn registration_loop(
    client: LedgerClient,
    store: Store,
    config: Config,
    shutdown: crate::sync::CancellationToken,
) {
    loop {
        match ensure_subscription(&client, &store, &config).await {
            Ok(subscription) => {
                tracing::info!(
                    id = %subscription.id,
                    url = %subscription.url,
                    "webhook subscription active"
                );
                return;
            }
            Err(err) => {
                tracing::warn!(
                    %err,
                    retry_in_ms = REGISTRATION_RETRY.as_millis() as u64,
                    "webhook self-registration failed; retrying"
                );
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(REGISTRATION_RETRY) => {}
                }
            }
        }
    }
}
