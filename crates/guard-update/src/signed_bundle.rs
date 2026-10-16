//! Domain-separated Ed25519 envelopes for signed data bundles (for example the
//! offline ASN prefix catalog). The signature covers
//! `"<domain>\0" || payload`, so a release-manifest signature can never be
//! replayed as a data bundle (or vice versa) even under a shared key; operators
//! should still use a dedicated bundle key. Verification never reserializes the
//! payload.
use crate::update::TrustKey;
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    domain: String,
    payload: String,
    signature: String,
}

fn message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 1 + payload.len());
    m.extend_from_slice(domain.as_bytes());
    m.push(0);
    m.extend_from_slice(payload);
    m
}

/// Sign exact payload bytes under `domain`; returns the JSON envelope.
pub fn sign(domain: &str, payload: &[u8], key: &SigningKey, max: usize) -> Result<Vec<u8>> {
    ensure!(!domain.is_empty() && domain.len() <= 64, "invalid domain");
    let signature = key.sign(&message(domain, payload));
    let encoded = serde_json::to_vec(&Envelope {
        domain: domain.into(),
        payload: STANDARD.encode(payload),
        signature: STANDARD.encode(signature.to_bytes()),
    })?;
    ensure!(encoded.len() <= max, "signed bundle exceeds size bound");
    Ok(encoded)
}

/// Verify an envelope for `domain` and return the exact signed payload bytes.
pub fn verify(domain: &str, encoded: &[u8], key: &TrustKey, max: usize) -> Result<Vec<u8>> {
    ensure!(encoded.len() <= max, "signed bundle exceeds size bound");
    let envelope: Envelope =
        serde_json::from_slice(encoded).context("invalid signed bundle envelope")?;
    ensure!(envelope.domain == domain, "signed bundle domain mismatch");
    let payload = STANDARD
        .decode(&envelope.payload)
        .context("bundle payload is not valid base64")?;
    let signature = Signature::from_slice(
        &STANDARD
            .decode(&envelope.signature)
            .context("bundle signature is not valid base64")?,
    )
    .context("bundle signature must be exactly 64 bytes")?;
    key.verifying_key()
        .verify_strict(&message(domain, &payload), &signature)
        .context("bundle signature verification failed")?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_bound_signatures_verify_and_reject_tampering() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let trust =
            TrustKey::from_base64(&STANDARD.encode(key.verifying_key().to_bytes())).unwrap();
        let env = sign("sumunjang.asn-bundle.v1", b"{\"a\":1}", &key, 1 << 20).unwrap();
        assert_eq!(
            verify("sumunjang.asn-bundle.v1", &env, &trust, 1 << 20).unwrap(),
            b"{\"a\":1}"
        );
        assert!(verify("other", &env, &trust, 1 << 20).is_err());
        assert!(verify("sumunjang.asn-bundle.v1", &env, &trust, 10).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&env).unwrap();
        v["payload"] = serde_json::json!(STANDARD.encode(b"{\"a\":2}"));
        assert!(
            verify(
                "sumunjang.asn-bundle.v1",
                &serde_json::to_vec(&v).unwrap(),
                &trust,
                1 << 20
            )
            .is_err()
        );
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let other_trust =
            TrustKey::from_base64(&STANDARD.encode(other.verifying_key().to_bytes())).unwrap();
        assert!(verify("sumunjang.asn-bundle.v1", &env, &other_trust, 1 << 20).is_err());
    }
}
