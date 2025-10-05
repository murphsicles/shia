//! Paymail BEEF integration (BRC-70): Wraps BEEF in JSON envelopes for
//! human-readable addressing and SPV payments.
//! Relies on BRC-77 for base Paymail format; focuses on 'beef' payload field.
//!
//! # Features
//! - `paymail`: Enables this module (adds serde/base64 deps).

#[cfg(not(feature = "paymail"))]
compile_error!("Paymail support requires the 'paymail' feature.");

use crate::beef::Beef;
use crate::errors::{Result, ShiaError};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Paymail resolution envelope with embedded BEEF payload (BRC-70).
/// Sent by Paymail services in response to payment resolution requests.
/// # Fields
/// - `beef`: Base64-encoded BEEF bytes for the payment TX bundle.
/// - `proofs`: Optional hex-encoded BUMP proofs (for manual verification).
/// - `metadata`: Optional Paymail-specific fields (e.g., alias, avatar).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymailEnvelope {
    /// Base64-encoded BEEF binary stream.
    pub beef: String,
    /// Optional array of hex-encoded BUMP Merkle proofs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proofs: Option<Vec<String>>,
    /// Optional metadata from Paymail resolution (e.g., {"alias": "roy", "dt": "2025-10-05"}).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl PaymailEnvelope {
    /// Creates a new envelope from a BEEF bundle.
    /// # Args
    /// - `beef`: The BEEF to embed.
    /// - `proofs`: Optional BUMP hex strings (e.g., from service).
    /// - `metadata`: Optional Paymail extras.
    /// # Errors
    /// - Base64 encoding failure (rare).
    pub fn from_beef(
        beef: &Beef,
        proofs: Option<Vec<String>>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<Self> {
        let beef_bytes = beef.serialize()?;
        let beef_b64 = STANDARD.encode(&beef_bytes);
        Ok(Self {
            beef: beef_b64,
            proofs,
            metadata,
        })
    }

    /// Deserializes from JSON string (e.g., from Paymail HTTP response).
    /// # Errors
    /// - JSON parse or base64 decode fails.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| ShiaError::Verification(e.to_string()).into())
    }

    /// Serializes to JSON string for transmission.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| ShiaError::Verification(e.to_string()).into())
    }

    /// Extracts and deserializes the inner BEEF for validation.
    /// # Errors
    /// - Base64 decode or BEEF parse fails.
    pub fn to_beef(&self) -> Result<Beef> {
        let beef_bytes = STANDARD.decode(&self.beef)
            .map_err(|e| ShiaError::Verification(format!("Base64 decode: {}", e)))?;
        Beef::deserialize(&beef_bytes)
    }

    /// Validates the envelope: Decodes BEEF and runs full verification.
    /// # Args
    /// - `headers_client`: For Merkle root checks.
    pub fn verify(&self, headers_client: &impl crate::client::BlockHeadersClient) -> Result<()> {
        let beef = self.to_beef()?;
        beef.verify(headers_client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockHeadersClient;
    use crate::beef::Beef;
    use std::collections::HashMap;

    #[test]
    fn test_from_beef_roundtrip() {
        let subject_raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000").unwrap();
        let subject_tx = crate::tx::Transaction::from_raw(&subject_raw).unwrap();
        let ancestors = HashMap::new();
        let bump_map = HashMap::new();
        let beef = Beef::build(subject_tx, ancestors, bump_map, false).unwrap();

        let proofs = Some(vec!["deadbeef".to_string()]);
        let mut metadata = HashMap::new();
        metadata.insert("alias".to_string(), serde_json::Value::String("roy".to_string()));
        let envelope = PaymailEnvelope::from_beef(&beef, proofs.clone(), Some(metadata)).unwrap();

        let json = envelope.to_json().unwrap();
        let roundtrip = PaymailEnvelope::from_json(&json).unwrap();
        assert_eq!(roundtrip.beef, envelope.beef);
        assert_eq!(roundtrip.proofs, proofs);
        assert_eq!(roundtrip.metadata.as_ref().unwrap().get("alias").unwrap().as_str().unwrap(), "roy");

        let extracted_beef = roundtrip.to_beef().unwrap();
        assert_eq!(extracted_beef.txs.len(), beef.txs.len());
    }

    #[test]
    fn test_verify_envelope() {
        let minimal_beef_hex = "f1c6c3ef00010100000000000000000000000000000000000000000000000000000000000000000000000000000000000504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac0000000000";
        let beef = Beef::from_hex(minimal_beef_hex).unwrap();
        let envelope = PaymailEnvelope::from_beef(&beef, None, None).unwrap();
        let mock_client = MockHeadersClient;
        assert!(envelope.verify(&mock_client).is_ok());
    }

    #[test]
    fn test_invalid_json() {
        let bad_json = r#"{"beef": "invalid_base64"}"#;
        assert!(PaymailEnvelope::from_json(bad_json).is_err());
    }
}
