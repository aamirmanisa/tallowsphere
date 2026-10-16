//! Secure buffer that automatically zeroizes on drop

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure buffer that automatically zeroizes its contents when dropped
///
/// This wrapper ensures that sensitive cryptographic material is always
/// wiped from memory when it goes out of scope.
/// Not Clone — key material must never be duplicated.
#[derive(ZeroizeOnDrop)]
pub struct SecureBuf<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> SecureBuf<T> {
    /// Create a new secure buffer
    ///
    /// # Arguments
    ///
    /// * `value` - The sensitive value to protect
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Expose the secret value as a reference
    ///
    /// # Security
    ///
    /// The caller must ensure they don't leak or copy the secret value.
    /// Prefer using this in limited scopes.
    pub fn expose_secret(&self) -> &T {
        &self.inner
    }

    /// Expose the secret value as a mutable reference
    ///
    /// # Security
    ///
    /// The caller must ensure they don't leak or copy the secret value.
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Zeroize> From<T> for SecureBuf<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl SecureBuf<Vec<u8>> {
    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<const N: usize> SecureBuf<[u8; N]> {
    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        N
    }

    /// Check if the buffer is empty (always false for fixed-size arrays)
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl<T: Zeroize + std::fmt::Debug> std::fmt::Debug for SecureBuf<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureBuf<REDACTED>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buf_vec() {
        let buf = SecureBuf::new(vec![1u8, 2, 3, 4]);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.expose_secret(), &vec![1u8, 2, 3, 4]);
    }

    #[test]
    fn test_secure_buf_array() {
        let buf = SecureBuf::new([1u8, 2, 3, 4]);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.expose_secret(), &[1u8, 2, 3, 4]);
    }
}
