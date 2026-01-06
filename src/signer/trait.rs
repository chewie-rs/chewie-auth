//! Cryptographic signing traits.

use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;

use bon::Builder;
use bytes::Bytes;
use snafu::prelude::*;

use crate::error::BoxedError;
use crate::jwk::PublicJwk;
use crate::platform::{MaybeSend, MaybeSendSync};
use crate::signer::error::{MismatchedKeyMetadataSnafu, UnderlyingSnafu};
use crate::{Error, platform::MaybeSendFuture};

/// Boxed JWS Signer.
#[derive(Clone)]
pub struct BoxedJwsSigner {
    inner: Arc<dyn DynJwsSigner>,
}

impl BoxedJwsSigner {
    /// Create a boxed signer from a non-boxed.
    pub fn new<Sgn: JwsSigner + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

/// Boxed trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
trait DynJwsSigner: MaybeSendSync {
    /// Returns metadata about the key used by this signer.
    fn key_metadata(&self) -> Cow<'_, KeyMetadata>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the algorithm
    /// and key ID match the values signed (which could happen due to key updates).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Bytes, BoxedError>> + 'a>>;
}

impl<Sgn: JwsSigner> DynJwsSigner for Sgn {
    fn key_metadata(&self) -> Cow<'_, KeyMetadata> {
        self.key_metadata()
    }

    fn sign_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Bytes, BoxedError>> + 'a>> {
        Box::pin(async {
            self.sign_unchecked(input)
                .await
                .map_err(BoxedError::from_err)
        })
    }
}

impl JwsSigner for BoxedJwsSigner {
    type Error = BoxedError;

    fn key_metadata(&self) -> Cow<'_, KeyMetadata> {
        self.inner.key_metadata()
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        self.inner.sign_unchecked(input).await
    }
}

/// Key metadata.
#[derive(Debug, Clone, Builder, PartialEq)]
pub struct KeyMetadata {
    /// Returns the JWS algorithm identifier.
    ///
    /// This is specifically for use in the JWT `alg` header parameter.
    ///
    /// Note: Implementations should return fully specified algorithms, as
    /// in RFC 9864. It is the responsibility of the caller to map this to a
    /// polymorphic algorithm when needed.
    #[builder(into)]
    pub(crate) jws_algorithm: String,
    /// Returns the key ID of the signer.
    ///
    /// This is specifically for use in the JWT `kid` header parameter.
    ///
    /// Note: The "natural" key ID is not always directly suitable as a
    /// `kid` value, and may require transformation before use.
    #[builder(into)]
    pub(crate) key_id: Option<String>,
}

/// Trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait JwsSigner: Clone + MaybeSendSync {
    /// The error type returned by this signer's operations.
    type Error: Error + 'static;

    /// Returns the key metadata for this signer.
    fn key_metadata(&self) -> Cow<'_, KeyMetadata>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the metadata
    /// match the values signed (which could happen due to key updates).
    ///
    /// Generally implementations should implement this function, and users will
    /// call `sign`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked(
        &self,
        input: &[u8],
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + MaybeSend;

    /// Asynchronously signs the given input data and returns the signature with metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the key metadata is mismatched, or the signing operation fails.
    fn sign(
        &self,
        input: &[u8],
        key_metadata: &KeyMetadata,
    ) -> impl Future<Output = Result<Bytes, super::JwsSignerError<Self::Error>>> + MaybeSend {
        async move {
            if &*self.key_metadata() == key_metadata {
                self.sign_unchecked(input).await.context(UnderlyingSnafu)
            } else {
                MismatchedKeyMetadataSnafu.fail()
            }
        }
    }
}

/// Trait for asymmetric keys that provides its public key in JWK (RFC 7517) format.
pub trait HasPublicKey: MaybeSendSync {
    /// Returns the public key for this asymmetric key as a JSON Web Key.
    fn public_key_jwk(&self) -> &PublicJwk;
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, convert::Infallible};

    use crate::signer::{JwsSigner, r#trait::KeyMetadata};

    #[derive(Debug, Clone)]
    struct MockSigner {
        key_metadata: KeyMetadata,
    }

    impl MockSigner {
        pub fn new() -> Self {
            Self {
                key_metadata: KeyMetadata::builder().jws_algorithm("ALG").build(),
            }
        }
    }

    impl JwsSigner for MockSigner {
        type Error = Infallible;

        fn key_metadata(&self) -> std::borrow::Cow<'_, super::KeyMetadata> {
            Cow::Borrowed(&self.key_metadata)
        }

        async fn sign_unchecked(&self, _input: &[u8]) -> Result<bytes::Bytes, Self::Error> {
            Ok(bytes::Bytes::new())
        }
    }

    #[tokio::test]
    async fn test_metadata_no_mismatch_succeeds() {
        MockSigner::new()
            .sign(
                &[],
                &KeyMetadata {
                    jws_algorithm: "ALG".into(),
                    key_id: None,
                },
            )
            .await
            .expect("no mismatch");
    }

    #[tokio::test]
    async fn test_metadata_different_alg_fails() {
        let result = MockSigner::new()
            .sign(&[], &KeyMetadata::builder().jws_algorithm("ALG2").build())
            .await;

        assert!(matches!(
            result,
            Err(crate::signer::JwsSignerError::MismatchedKeyMetadata)
        ))
    }

    #[tokio::test]
    async fn test_metadata_different_kid_fails() {
        let result = MockSigner::new()
            .sign(
                &[],
                &KeyMetadata::builder()
                    .jws_algorithm("ALG")
                    .key_id("key-id")
                    .build(),
            )
            .await;

        assert!(matches!(
            result,
            Err(crate::signer::JwsSignerError::MismatchedKeyMetadata)
        ))
    }
}
