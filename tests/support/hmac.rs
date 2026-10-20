//! Independent RFC 2104 HMAC-SHA256 for the webhook tests.
//!
//! Written from the RFC (64-byte block, `0x36`/`0x5c` pads, keys longer than
//! the block hashed first) instead of reusing the daemon's private helper, so
//! the tests cross-check the implementation against a second construction.
//! `tests/webhook.rs` anchors this helper to an RFC 4231 vector.

use sha2::{Digest, Sha256};

const BLOCK_BYTES: usize = 64;

/// HMAC-SHA256 over `message` keyed by `key`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0_u8; BLOCK_BYTES];
    let mut opad = [0_u8; BLOCK_BYTES];
    for (index, byte) in key_block.iter().enumerate() {
        ipad[index] = byte ^ 0x36;
        opad[index] = byte ^ 0x5c;
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

/// The `X-DumpLedger-Signature-256` header value for `body`.
pub fn signature_header(key: &[u8], body: &[u8]) -> String {
    format!("sha256={}", hex::encode(hmac_sha256(key, body)))
}
