//! Catalog sync and the event-feed follower (task B2;
//! docs/analyzer-design.md "Module design" and "Correctness and
//! idempotency"; specs/DumpAnalyzer.tla `Discover`, `Purge`, `FollowFeed`).
//!
//! Two read-side entry points feed the local job table; neither executes
//! work:
//!
//! * [`initial_scan`] walks `GET /api/v1/dumps` with keyset pagination and
//!   records one `triage` job per dump that is `available` with a sealed
//!   content hash (spec: `Discover`).
//! * [`follow_feed`] resumes `GET /api/v1/events` from the persisted
//!   `event_cursor` with the pinned server-side `actions` filter
//!   ([`FEED_ACTIONS`]), applies each page's dump-lifecycle events, and
//!   persists the page cursor before sleeping. An empty page whose
//!   `nextCursor` equals the request cursor is the sleep signal
//!   (`config.poll_interval`); a [`CancellationToken`] stops the loop
//!   promptly through `tokio::select!`.
//!
//! # Event application
//!
//! The audit vocabulary is open (the feed's `action` is a bounded string, not
//! a contract enum), so actions are classified by the dump-lifecycle keywords
//! they carry:
//!
//! * *intake/seal family* (`BeginUpload`, `SealUpload`, `PromoteObject`,
//!   `MarkQuarantined`, `AcceptDump`, …) — the dump's catalog entry is re-read
//!   (`GET /api/v1/dumps/:dumpId`) and a job is upserted only when the dump is
//!   `available` with a content hash. The event carries the `dumpId` but not
//!   the sealed sha256 the job identity pins, and the catalog entry is
//!   authoritative for both; the gate also makes seal-before-accept sequences
//!   harmless no-ops.
//! * *purge/delete family* (`BeginPurge`, `FinishPurge`, `RejectDump`, …) —
//!   every local job row for that dump becomes `dropped` (spec: `Purge`,
//!   `NoJobForPurgedDump`). The event carries only the `dumpId`, so the
//!   matching identities are found by scanning the job table's phases.
//! * everything else is ignored.
//!
//! The server-side `actions` filter ([`FEED_ACTIONS`]) narrows the wire to
//! the dump-lifecycle family; the keyword classifier stays as the local
//! safety net for events that arrive anyway (a server ignoring the filter,
//! or a future action the pinned list has not learned yet). Symbol-store
//! actions (`SealSymbol`/`PurgeSymbol`) and `RecordAnalysis` are ignored by
//! it: they never carry a `dumpId` and cannot change dump schedulability.
//!
//! Application is idempotent: `upsert_discovered` inserts once per identity
//! and `drop_job` is a phase write that tolerates repetition, so replaying a
//! page (after a crash between apply and cursor persist, or when the server
//! re-delivers an unchanged page) is harmless.
//!
//! # Cursor discipline
//!
//! The cursor is persisted *after* a page's events are applied. The design
//! document's "persisted before the events it covers are applied" sentence
//! reads the other way; the task contract and at-least-once execution settle
//! it: applying first means a crash in the window replays the page (safe,
//! idempotent) instead of losing events. [`CursorStore::set_monotonic`]
//! rejects any backward move, so a regressing server surfaces as
//! [`AnalyzerError::State`] instead of silently corrupting the position.

use tokio::sync::watch;

use crate::client::LedgerClient;
use crate::config::Config;
use crate::state::Store;
use crate::types::{AnalyzerError, JobIdentity, JobPhase, Result};
use crate::wire::{DumpCatalogQuery, DumpPhase, EventFeedEntry};

/// The only v1 analysis kind (docs/analyzer-design.md, "Purpose and scope").
pub const KIND_TRIAGE: &str = "triage";

/// Persisted name of the event-feed cursor (`CursorMonotonic` in
/// specs/DumpAnalyzer.tla).
pub const EVENT_CURSOR: &str = "event_cursor";

/// Server-side `actions` filter for the event feed (R3; analyzer guide,
/// "Follow changes"). Each entry maps to the guide's vocabulary:
///
/// | Filter entry | Analyzer guide, "Follow changes" |
/// |---|---|
/// | `AcceptDump` | "Dump passed inspection and is `available` — bytes retrievable" |
/// | `RejectDump` | "Dump failed validation; `detail` carries the reason" (drop) |
/// | `BeginPurge` / `FinishPurge` | "Retention started / bytes gone (analyses cascade-deleted)" (drop) |
/// | `SealUpload` | full vocabulary (http-api.md's example filter): upload sealed, sha256 pinned |
/// | `PromoteObject` | full vocabulary: sealed object promoted into the vault |
/// | `MarkQuarantined` | full vocabulary: sealed dump quarantined |
///
/// `SealUpload`/`PromoteObject`/`MarkQuarantined` keep the intake family
/// broad on purpose: none of them makes a dump `available` by itself, but
/// the `get_dump` availability gate is the real guard and a superfluous
/// event costs one catalog lookup. The guide's `SealSymbol`/`PurgeSymbol`
/// and `RecordAnalysis` rows are deliberately not subscribed: they never
/// carry a `dumpId` and cannot change dump schedulability.
///
/// Order is part of the wire contract (the client joins on `,` in this
/// order); `tests/sync.rs` pins the exact string.
pub const FEED_ACTIONS: [&str; 7] = [
    "AcceptDump",
    "RejectDump",
    "BeginPurge",
    "FinishPurge",
    "SealUpload",
    "PromoteObject",
    "MarkQuarantined",
];

/// Every phase a purge sweep inspects. `dropped` is omitted because it is
/// already the purge terminal state; `done`/`failed` are included because the
/// spec's `Purge` maps *every* non-`none` job for a purged dump to `dropped`.
const PURGE_SCAN_PHASES: [JobPhase; 8] = [
    JobPhase::Discovered,
    JobPhase::Claimed,
    JobPhase::Fetching,
    JobPhase::Staged,
    JobPhase::Analyzing,
    JobPhase::Reporting,
    JobPhase::Done,
    JobPhase::Failed,
];

/// One-way shutdown flag observed by [`follow_feed`].
///
/// `tokio-util` is not an approved dependency, so this is a small wrapper
/// over a `tokio::sync::watch` channel: cloning shares the flag,
/// [`CancellationToken::cancel`] flips it once, and
/// [`CancellationToken::cancelled`] resolves once it is set. Both
/// [`CancellationToken::is_cancelled`] and `cancelled` are cancel-safe, which
/// is what lets `tokio::select!` drop a half-sent request without losing the
/// flag.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    sender: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

impl CancellationToken {
    /// Creates a token in the running (not cancelled) state.
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self { sender, receiver }
    }

    /// Requests shutdown. Idempotent and safe to call from any task.
    pub fn cancel(&self) {
        // `send` fails only when every receiver is gone; the token itself
        // holds one for its whole lifetime.
        let _ = self.sender.send(true);
    }

    /// Whether [`Self::cancel`] has been called.
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Resolves once the token is cancelled (or every sender is dropped).
    pub async fn cancelled(&self) {
        let mut receiver = self.receiver.clone();
        loop {
            if *receiver.borrow_and_update() {
                return;
            }
            if receiver.changed().await.is_err() {
                // All senders are gone; treat that as shutdown too.
                return;
            }
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// One keyset-paginated pass over `GET /api/v1/dumps` (spec: `Discover`).
///
/// Every dump that comes back `available` with a sealed `sha256` is recorded
/// as a `triage` job pinned to that hash and the configured analyzer version.
/// Returns the number of newly inserted jobs; identities that already have a
/// row in any phase are left untouched (the local row is the dedup marker).
///
/// The scan filters `phase=available` server-side and re-checks the same gate
/// client-side, so a server that ignored the filter could still never
/// schedule a not-yet-sealed dump. Pagination follows `nextCursor` to
/// exhaustion and fails with [`AnalyzerError::Decode`] when the cursor stops
/// advancing (a repeated cursor would otherwise loop forever).
///
/// # Errors
///
/// Propagates the client's `Transport`/`Server`/`Decode` errors and
/// [`AnalyzerError::State`] from the local store.
pub async fn initial_scan(client: &LedgerClient, store: &Store, config: &Config) -> Result<u64> {
    let jobs = store.jobs();
    let query = DumpCatalogQuery {
        phase: Some(DumpPhase::Available),
        ..DumpCatalogQuery::default()
    };
    let mut cursor: Option<String> = None;
    let mut inserted = 0_u64;
    loop {
        let page = client.get_dumps(&query, cursor.as_deref()).await?;
        for entry in &page.dumps {
            let Some(identity) = triage_identity(
                &entry.dump_id,
                entry.phase,
                entry.sha256.as_deref(),
                &config.version,
            ) else {
                continue;
            };
            if jobs.upsert_discovered(&identity)? {
                inserted += 1;
            }
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        if cursor.as_deref() == Some(next.as_str()) {
            return Err(AnalyzerError::Decode(
                "GET /api/v1/dumps: nextCursor did not advance".to_owned(),
            ));
        }
        cursor = Some(next);
    }
    tracing::info!(inserted, "initial catalog scan completed");
    Ok(inserted)
}

/// Follows `GET /api/v1/events` from the persisted cursor until `shutdown`
/// is cancelled (spec: `FollowFeed`).
///
/// Each poll applies its page's events in order and then persists
/// `nextCursor` with [`CursorStore::set_monotonic`](crate::state::CursorStore::set_monotonic).
/// The request carries the pinned [`FEED_ACTIONS`] filter, so the server
/// pages only dump-lifecycle events; the local classifier remains the safety
/// net if a server ignores the filter.
/// A page with no events, or a `nextCursor` that did not advance, sleeps for
/// `config.poll_interval`; a page with events loops immediately so a burst is
/// drained without waiting a full interval. Returns `Ok(())` on shutdown.
///
/// # Errors
///
/// Propagates client errors and store errors. On any error the cursor for the
/// failing page is not advanced, so the page is re-fetched and re-applied
/// after the caller retries; application is idempotent.
pub async fn follow_feed(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
    shutdown: &CancellationToken,
) -> Result<()> {
    let cursors = store.cursors();
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let since = cursors.get(EVENT_CURSOR)?;
        let page = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            response = client.get_events(since.as_deref(), Some(&FEED_ACTIONS), None, None) => response?,
        };
        let advanced = since.as_deref() != Some(page.next_cursor.as_str());
        for event in &page.events {
            if !apply_event(client, store, config, event, shutdown).await? {
                // Shutdown mid-page: leave the cursor where it was so the
                // whole page is replayed on the next start.
                return Ok(());
            }
        }
        // Apply, then persist: a crash in between replays the page, which is
        // harmless because every application is idempotent (at-least-once
        // execution, exactly-once effect).
        cursors.set_monotonic(EVENT_CURSOR, &page.next_cursor)?;
        if page.events.is_empty() || !advanced {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                () = tokio::time::sleep(config.poll_interval) => {}
            }
        }
    }
}

/// Applies one feed event. Returns `false` when shutdown arrived while the
/// event was being resolved (the caller must then not persist the cursor).
async fn apply_event(
    client: &LedgerClient,
    store: &Store,
    config: &Config,
    event: &EventFeedEntry,
    shutdown: &CancellationToken,
) -> Result<bool> {
    let Some(dump_id) = event.dump_id.as_deref() else {
        return Ok(true);
    };
    if is_purge_action(&event.action) {
        let dropped = drop_dump_jobs(store, dump_id)?;
        tracing::debug!(dump_id, action = %event.action, dropped, "applied purge event");
        return Ok(true);
    }
    if !is_intake_action(&event.action) {
        return Ok(true);
    }
    let lookup = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(false),
        result = client.get_dump(dump_id) => result,
    };
    let detail = match lookup {
        Ok(detail) => detail,
        Err(AnalyzerError::Server {
            status: 404 | 410, ..
        }) => {
            // The dump vanished (purged or rejected) between the event and
            // the catalog read; there is nothing to schedule.
            tracing::debug!(dump_id, action = %event.action, "dump vanished before scheduling");
            return Ok(true);
        }
        Err(err) => return Err(err),
    };
    match triage_identity(
        &detail.dump_id,
        detail.phase,
        detail.sha256.as_deref(),
        &config.version,
    ) {
        Some(identity) => {
            let inserted = store.jobs().upsert_discovered(&identity)?;
            tracing::debug!(dump_id, action = %event.action, inserted, "scheduled dump from feed");
        }
        None => {
            tracing::debug!(dump_id, action = %event.action, "dump not schedulable yet; ignored");
        }
    }
    Ok(true)
}

/// Moves every local job row for `dump_id` to `dropped` (spec: `Purge`).
///
/// Purge events carry only the dump id, so the identities are resolved by
/// scanning the job table; the local table is small (one writer process) and
/// phase history is never kept, so the sweep is bounded by the phase set.
/// Returns how many rows were dropped. An unknown dump is a no-op, never an
/// error: the event may arrive for a dump this analyzer never scheduled.
fn drop_dump_jobs(store: &Store, dump_id: &str) -> Result<u64> {
    let jobs = store.jobs();
    let mut dropped = 0_u64;
    for phase in PURGE_SCAN_PHASES {
        for (identity, _attempts) in jobs.jobs_in_phase(phase)? {
            if identity.dump_id == dump_id {
                jobs.drop_job(&identity)?;
                dropped += 1;
            }
        }
    }
    Ok(dropped)
}

/// Builds the v1 job identity for a dump, or `None` when the dump is not
/// schedulable: the catalog phase must be `available` and the sealed `sha256`
/// must be present (the spec's `Discover` guard). The wire decoders already
/// enforce the sha256 shape.
fn triage_identity(
    dump_id: &str,
    phase: DumpPhase,
    sha256: Option<&str>,
    analyzer_version: &str,
) -> Option<JobIdentity> {
    if phase != DumpPhase::Available {
        return None;
    }
    Some(JobIdentity {
        dump_id: dump_id.to_owned(),
        input_sha256: sha256?.to_owned(),
        kind: KIND_TRIAGE.to_owned(),
        analyzer_version: analyzer_version.to_owned(),
    })
}

/// Actions that invalidate dump work: the ledger's purge/delete family
/// (`BeginPurge`, `FinishPurge`, `RejectDump`, …), matched
/// ASCII-case-insensitively on the action keyword.
///
/// Symbol-store actions (`SealSymbol`, `PurgeSymbol`, `IngestSymbol`) are
/// excluded even though `PurgeSymbol` carries a "purge" keyword: they never
/// carry a `dumpId` and cannot invalidate dump work.
fn is_purge_action(action: &str) -> bool {
    let action = action.to_ascii_lowercase();
    if action.contains("symbol") {
        return false;
    }
    action.contains("purge") || action.contains("delete") || action.contains("reject")
}

/// Actions that can make a dump schedulable: the intake/seal family
/// (`BeginUpload`, `SealUpload`, `PromoteObject`, `MarkQuarantined`,
/// `AcceptDump`, …). The catalog re-read gates on `available`, so a generous
/// family costs only a lookup, never a premature job.
///
/// `SealSymbol` is excluded for the same reason as in [`is_purge_action`]:
/// symbol-store events are not dump lifecycle.
fn is_intake_action(action: &str) -> bool {
    let action = action.to_ascii_lowercase();
    if action.contains("symbol") {
        return false;
    }
    action.contains("accept")
        || action.contains("intake")
        || action.contains("seal")
        || action.contains("upload")
        || action.contains("promote")
        || action.contains("quarantine")
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::time::Duration;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn classifies_dump_lifecycle_actions() {
        for action in [
            "BeginUpload",
            "SealUpload",
            "AcceptDump",
            "PromoteObject",
            "MarkQuarantined",
            "intake",
        ] {
            assert!(is_intake_action(action), "expected intake: {action}");
            assert!(!is_purge_action(action), "expected not purge: {action}");
        }
        for action in [
            "BeginPurge",
            "FinishPurge",
            "RejectDump",
            "DeleteDump",
            "delete",
        ] {
            assert!(is_purge_action(action), "expected purge: {action}");
            assert!(!is_intake_action(action), "expected not intake: {action}");
        }
        for action in ["AuthorizeDownload", "SetRetention", "IssueToken"] {
            assert!(!is_intake_action(action), "expected ignored: {action}");
            assert!(!is_purge_action(action), "expected ignored: {action}");
        }
    }

    /// The server-side filter is a pinned wire string: exact spelling,
    /// exact order, comma-joined by the client.
    #[test]
    fn feed_actions_pin_the_guide_vocabulary_in_order() {
        assert_eq!(
            FEED_ACTIONS.join(","),
            "AcceptDump,RejectDump,BeginPurge,FinishPurge,SealUpload,PromoteObject,MarkQuarantined"
        );
    }

    /// Exact spellings from the analyzer guide's "Follow changes" table: the
    /// dump-lifecycle actions land in their families, symbol-store actions
    /// and `RecordAnalysis` are ignored.
    #[test]
    fn guide_vocabulary_lands_in_the_intended_families() {
        for action in [
            "AcceptDump",
            "SealUpload",
            "PromoteObject",
            "MarkQuarantined",
        ] {
            assert!(is_intake_action(action), "expected intake: {action}");
            assert!(!is_purge_action(action), "expected not purge: {action}");
        }
        for action in ["RejectDump", "BeginPurge", "FinishPurge"] {
            assert!(is_purge_action(action), "expected purge: {action}");
            assert!(!is_intake_action(action), "expected not intake: {action}");
        }
        for action in ["SealSymbol", "PurgeSymbol", "RecordAnalysis"] {
            assert!(!is_intake_action(action), "expected ignored: {action}");
            assert!(!is_purge_action(action), "expected ignored: {action}");
        }
    }

    #[test]
    fn identity_requires_available_phase_and_pinned_hash() {
        let identity = triage_identity("dump_A", DumpPhase::Available, Some(SHA), "1.2.3")
            .expect("available dump with hash is schedulable");
        assert_eq!(identity.dump_id, "dump_A");
        assert_eq!(identity.input_sha256, SHA);
        assert_eq!(identity.kind, KIND_TRIAGE);
        assert_eq!(identity.analyzer_version, "1.2.3");

        assert!(triage_identity("dump_A", DumpPhase::Sealed, Some(SHA), "1.2.3").is_none());
        assert!(triage_identity("dump_A", DumpPhase::Available, None, "1.2.3").is_none());
    }

    #[tokio::test]
    async fn cancellation_token_flags_and_resolves() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        let pending = token.cancelled();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), pending)
                .await
                .is_err(),
            "an uncancelled token must not resolve"
        );
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), token.cancelled())
            .await
            .expect("a cancelled token resolves immediately");
    }
}
