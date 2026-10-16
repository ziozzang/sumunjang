//! Administrative actor identity for audit records.
//!
//! The Hangang console broker can sign each dispatched request with an actor
//! assertion (`x-hopae-delegation` + `x-hopae-delegation-mac`, HMAC-SHA-256 over
//! the encoded assertion) when the Guard binding sets `delegate_actor: true`.
//! The broker uses the binding credential as the HMAC key and also sends it as the
//! bearer credential, so Sumunjang verifies the assertion with its admin
//! credential and needs no extra secret. The assertion binds method, path, body
//! digest, a single-use nonce and a ten-second freshness window. A present but
//! invalid assertion is refused; it is never downgraded to an anonymous actor.
//! Without an assertion the actor is the shared admin credential.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub const ASSERTION_HEADER: &str = "x-hopae-delegation";
pub const MAC_HEADER: &str = "x-hopae-delegation-mac";
const FRESHNESS_SECS: u64 = 10;
const NONCE_RETENTION_SECS: u64 = 30;
const MAX_NONCES: usize = 65_536;

/// Who performed an administrative operation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Actor {
    /// `delegated` (signed Hangang console actor), `credential` (shared admin
    /// bearer credential), `kubernetes` (native source authority) or `local`
    /// (startup configuration files).
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub name: String,
    /// `hangang` for delegated actors, otherwise `sumunjang` or `kubernetes`.
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// SHA-256 of the request body, correlating with the host plugin journal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_sha256: Option<String>,
}
impl Actor {
    pub fn credential() -> Self {
        Self {
            kind: "credential",
            id: None,
            name: "admin-credential".into(),
            issuer: "sumunjang".into(),
            client_ip: None,
            request_sha256: None,
        }
    }
    pub fn local() -> Self {
        Self {
            kind: "local",
            id: None,
            name: "local-configuration".into(),
            issuer: "sumunjang".into(),
            client_ip: None,
            request_sha256: None,
        }
    }
    pub fn kubernetes(source: &str) -> Self {
        Self {
            kind: "kubernetes",
            id: None,
            name: source.chars().take(128).collect(),
            issuer: "kubernetes".into(),
            client_ip: None,
            request_sha256: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assertion {
    #[serde(default)]
    authority: Option<String>,
    actor_id: i64,
    actor_name: String,
    timestamp: u64,
    nonce: String,
    method: String,
    path: String,
    body_sha256: String,
    #[allow(dead_code)]
    handle_sha256: String,
    client_ip: String,
    #[allow(dead_code)]
    user_agent: Option<String>,
}

/// Bounded single-use nonce memory shared by the HTTP router.
#[derive(Clone, Default)]
pub struct Nonces(Arc<Mutex<HashMap<String, u64>>>);
impl Nonces {
    fn admit(&self, nonce: &str, now: u64) -> Result<(), &'static str> {
        let mut seen = self.0.lock().map_err(|_| "delegation state unavailable")?;
        if seen.len() >= MAX_NONCES {
            seen.retain(|_, t| now.saturating_sub(*t) <= NONCE_RETENTION_SECS);
        }
        if seen.len() >= MAX_NONCES {
            return Err("delegation replay capacity reached");
        }
        if seen.insert(nonce.to_owned(), now).is_some() {
            return Err("delegated actor assertion replayed");
        }
        Ok(())
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Verify a delegated actor assertion for one request.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    encoded: &str,
    signature: &str,
    key: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
    nonces: &Nonces,
) -> Result<Actor, &'static str> {
    const INVALID: &str = "invalid delegated actor assertion";
    if encoded.len() > 2048 || signature.len() > 64 {
        return Err(INVALID);
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| INVALID)?;
    let tag = URL_SAFE_NO_PAD.decode(signature).map_err(|_| INVALID)?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::verify(&key, &bytes, &tag).map_err(|_| INVALID)?;
    let a: Assertion = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    if a.actor_id < 0
        || (a.actor_id == 0 && a.actor_name != "system")
        || a.actor_name.is_empty()
        || a.actor_name.len() > 64
        || a.actor_name.chars().any(char::is_control)
        || a.authority.as_deref().is_some_and(|v| v != "hangang")
        || a.nonce.len() != 32
        || !a.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        || a.body_sha256.len() != 64
        || a.client_ip.parse::<std::net::IpAddr>().is_err()
    {
        return Err(INVALID);
    }
    if a.timestamp.abs_diff(now) > FRESHNESS_SECS {
        return Err("delegated actor assertion expired");
    }
    if a.method != method || a.path != path || a.body_sha256 != sha256_hex(body) {
        return Err("delegated actor assertion does not match request");
    }
    nonces.admit(&a.nonce, now)?;
    Ok(Actor {
        kind: "delegated",
        id: Some(a.actor_id),
        name: a.actor_name,
        issuer: "hangang".into(),
        client_ip: Some(a.client_ip),
        request_sha256: Some(a.body_sha256),
    })
}

#[cfg(test)]
pub(crate) fn sign_for_test(
    key: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
) -> (String, String) {
    let nonce: String = (0..32)
        .map(|i| char::from(b"0123456789abcdef"[(now as usize + i * 7 + body.len()) % 16]))
        .collect();
    let json = serde_json::json!({"authority":"hangang","actor_id":7,"actor_name":"operator","timestamp":now,
        "nonce":nonce,"method":method,"path":path,"body_sha256":sha256_hex(body),
        "handle_sha256":sha256_hex(b""),"client_ip":"192.0.2.10","user_agent":null});
    let bytes = serde_json::to_vec(&json).unwrap();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&key, &bytes);
    (
        URL_SAFE_NO_PAD.encode(bytes),
        URL_SAFE_NO_PAD.encode(tag.as_ref()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assertion_binds_key_request_freshness_and_single_use() {
        let nonces = Nonces::default();
        let (e, s) = sign_for_test(b"admin-test-token", "PUT", "/v1/rules", b"{}", 100);
        let ok = verify(
            &e,
            &s,
            b"admin-test-token",
            "PUT",
            "/v1/rules",
            b"{}",
            100,
            &nonces,
        )
        .unwrap();
        assert_eq!(
            (ok.kind, ok.name.as_str(), ok.id),
            ("delegated", "operator", Some(7))
        );
        // Replay of the same nonce is refused.
        assert!(
            verify(
                &e,
                &s,
                b"admin-test-token",
                "PUT",
                "/v1/rules",
                b"{}",
                100,
                &nonces
            )
            .is_err()
        );
        let (e, s) = sign_for_test(b"admin-test-token", "PUT", "/v1/rules", b"{}", 101);
        for (key, method, path, body, now) in [
            (
                &b"wrong-key-wrong-key"[..],
                "PUT",
                "/v1/rules",
                &b"{}"[..],
                101,
            ),
            (b"admin-test-token", "POST", "/v1/rules", b"{}", 101),
            (b"admin-test-token", "PUT", "/v1/policy", b"{}", 101),
            (b"admin-test-token", "PUT", "/v1/rules", b"{\"x\":1}", 101),
            (b"admin-test-token", "PUT", "/v1/rules", b"{}", 120),
        ] {
            assert!(verify(&e, &s, key, method, path, body, now, &nonces).is_err());
        }
        assert!(
            verify(
                &e,
                &s,
                b"admin-test-token",
                "PUT",
                "/v1/rules",
                b"{}",
                101,
                &nonces
            )
            .is_ok()
        );
    }
}
