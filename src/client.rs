//! Pluggable client for block headers and Merkle root validation.

/// Trait for verifying Merkle roots against block headers.
/// Implement for HTTP clients, local nodes, etc.
pub trait BlockHeadersClient {
    /// Checks if the root is valid for the given block height.
    /// # Returns
    /// `true` if in the longest chain.
    fn is_valid_root_for_height(&self, root: [u8; 32], height: u64) -> bool;
}

/// Mock client for testing (always valid).
#[derive(Debug, Clone)]
pub struct MockHeadersClient;

impl BlockHeadersClient for MockHeadersClient {
    fn is_valid_root_for_height(&self, _root: [u8; 32], _height: u64) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client() {
        let client = MockHeadersClient;
        assert!(client.is_valid_root_for_height([0u8; 32], 1));
    }
}
