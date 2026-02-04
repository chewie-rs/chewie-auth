use std::{borrow::Cow, convert::Infallible, sync::Arc};

use bytes::Bytes;
use hmac::Mac as _;
use secrecy::{ExposeSecret, SecretBox};

use crate::{crypto::signer::SigningKeyMetadata, prelude::JwsSigningKey, secrets::Secret};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacAlgorithm {
    Hs256,
    Hs384,
    Hs512,
}

impl AsRef<str> for HmacAlgorithm {
    fn as_ref(&self) -> &str {
        match self {
            HmacAlgorithm::Hs256 => "HS256",
            HmacAlgorithm::Hs384 => "HS384",
            HmacAlgorithm::Hs512 => "HS512",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HmacKey {
    key: Arc<SecretBox<[u8]>>,
    algorithm: HmacAlgorithm,
    metadata: SigningKeyMetadata,
}

impl HmacKey {
    pub async fn load_bytes<S: Secret<Output = SecretBox<[u8]>>>(
        secret: S,
        algorithm: HmacAlgorithm,
    ) -> Result<Self, S::Error> {
        let slice = secret.get_secret_value().await?;

        let metadata = SigningKeyMetadata::builder()
            .jws_algorithm(algorithm.as_ref())
            .build();

        Ok(Self {
            key: Arc::new(slice),
            algorithm,
            metadata,
        })
    }
}

impl JwsSigningKey for HmacKey {
    type Error = Infallible;

    fn key_metadata(&self) -> std::borrow::Cow<'_, crate::crypto::signer::SigningKeyMetadata> {
        Cow::Borrowed(&self.metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<bytes::Bytes, Self::Error> {
        let key_bytes = self.key.expose_secret();

        let signed_bytes = match self.algorithm {
            HmacAlgorithm::Hs256 => {
                let mut key: hmac::Hmac<sha2::Sha256> =
                    hmac::Hmac::new_from_slice(key_bytes).expect("Should not fail with HMAC-SHA");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
            HmacAlgorithm::Hs384 => {
                let mut key: hmac::Hmac<sha2::Sha384> =
                    hmac::Hmac::new_from_slice(key_bytes).expect("Should not fail with HMAC-SHA");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
            HmacAlgorithm::Hs512 => {
                let mut key: hmac::Hmac<sha2::Sha512> =
                    hmac::Hmac::new_from_slice(key_bytes).expect("Should not fail with HMAC-SHA");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
        };

        Ok(Bytes::from(signed_bytes))
    }
}
