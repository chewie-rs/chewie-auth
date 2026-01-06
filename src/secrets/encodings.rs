use base64::Engine as _;
use secrecy::{SecretBox, SecretString};
use snafu::prelude::*;

use crate::platform::MaybeSendSync;

/// Errors that can occur when decoding a secret.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DecodingError {
    /// The bytes are not valid UTF-8.
    #[snafu(display("Invalid UTF-8"))]
    InvalidUtf8 {
        /// The underlying UTF-8 error.
        source: std::str::Utf8Error,
    },
    /// The string is not valid hexadecimal.
    #[snafu(display("Invalid hex"))]
    InvalidHex {
        /// The hex decoding error.
        source: hex::FromHexError,
    },
    /// The string is not valid base64.
    #[snafu(display("Invalid base64"))]
    InvalidBase64 {
        /// The base64 decoding error.
        source: base64::DecodeError,
    },
}

/// Trait for decoding raw bytes into a typed secret.
pub trait SecretDecoder: Clone + MaybeSendSync {
    /// The type of secret this encoding produces.
    type Output: MaybeSendSync;

    /// Decodes raw bytes into the secret type.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes cannot be decoded (e.g., invalid UTF-8,
    /// invalid hex characters).
    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError>;
}

/// Interprets bytes as UTF-8 text, returning a `SecretString`.
///
/// Trims leading/trailing whitespace from the decoded string.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringEncoding;

impl SecretDecoder for StringEncoding {
    type Output = SecretString;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        Ok(SecretString::from(s.trim().to_string()))
    }
}

/// Uses raw bytes directly, returning `SecretBytes`.
///
/// No transformation is applied - bytes pass through as-is.
#[derive(Debug, Clone, Copy, Default)]
pub struct BinaryEncoding;

impl SecretDecoder for BinaryEncoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        Ok(SecretBox::new(bytes.to_vec().into_boxed_slice()))
    }
}

/// Decodes hex-encoded text into `SecretBytes`.
///
/// Trims whitespace before decoding. Expects the bytes to be valid UTF-8
/// containing hexadecimal characters (0-9, a-f, A-F).
#[derive(Debug, Clone, Copy, Default)]
pub struct HexEncoding;

impl SecretDecoder for HexEncoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        let decoded = hex::decode(s.trim()).context(InvalidHexSnafu)?;
        Ok(SecretBox::new(decoded.into_boxed_slice()))
    }
}

/// Decodes base64-encoded text into `SecretBytes`.
///
/// Trims whitespace before decoding. Expects the bytes to be valid base64
/// with padding.
#[derive(Debug, Clone, Copy, Default)]
pub struct Base64Encoding;

impl SecretDecoder for Base64Encoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .context(InvalidBase64Snafu)?;
        Ok(SecretBox::new(decoded.into_boxed_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn string_encoding_valid_utf8() {
        let result = StringEncoding.decode(b"hello world").unwrap();
        assert_eq!(result.expose_secret(), "hello world");
    }

    #[test]
    fn string_encoding_trims_whitespace() {
        let result = StringEncoding.decode(b"  hello  \n").unwrap();
        assert_eq!(result.expose_secret(), "hello");
    }

    #[test]
    fn string_encoding_invalid_utf8() {
        let result = StringEncoding.decode(&[0xff, 0xfe]);
        assert!(matches!(result, Err(DecodingError::InvalidUtf8 { .. })));
    }

    #[test]
    fn binary_encoding_passthrough() {
        let bytes = &[0x00, 0x01, 0x02, 0xff];
        let result = BinaryEncoding.decode(bytes).unwrap();
        assert_eq!(result.expose_secret(), bytes);
    }

    #[test]
    fn hex_encoding_valid() {
        let result = HexEncoding.decode(b"deadbeef").unwrap();
        assert_eq!(result.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_encoding_trims_whitespace() {
        let result = HexEncoding.decode(b"  deadbeef  \n").unwrap();
        assert_eq!(result.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_encoding_invalid() {
        let result = HexEncoding.decode(b"not hex!");
        assert!(matches!(result, Err(DecodingError::InvalidHex { .. })));
    }

    #[test]
    fn base64_encoding_valid() {
        let result = Base64Encoding.decode(b"SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(result.expose_secret(), b"Hello World");
    }

    #[test]
    fn base64_encoding_trims_whitespace() {
        let result = Base64Encoding.decode(b"  SGVsbG8gV29ybGQ=  \n").unwrap();
        assert_eq!(result.expose_secret(), b"Hello World");
    }

    #[test]
    fn base64_encoding_invalid() {
        let result = Base64Encoding.decode(b"not valid base64!");
        assert!(matches!(result, Err(DecodingError::InvalidBase64 { .. })));
    }
}
