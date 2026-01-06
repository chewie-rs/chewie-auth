use bytes::Bytes;
use p384::ecdsa::{Signature, SigningKey, signature::Signer};
use p384::elliptic_curve::Generate as _;
use p384::pkcs8::DecodePrivateKey as _;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use snafu::prelude::*;
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;

use crate::jwk;
use crate::secrets::Secret;
use crate::signer::{HasPublicKey, JwsSigner, KeyMetadata};

const ALGORITHM: &str = "ES384";

#[derive(Debug, Snafu)]
pub enum Es384PrivateKeyLoadError<E: crate::Error> {
    Secret {
        source: E,
    },
    #[snafu(display("Failed to decode PKCS#8 key"))]
    KeyDecode {
        source: p384::pkcs8::Error,
    },
}

#[derive(Clone)]
pub struct Es384PrivateKey {
    pub(super) inner: Arc<SigningKey>,
    key_metadata: KeyMetadata,
    jwk: jwk::PublicJwk,
}

impl From<SigningKey> for Es384PrivateKey {
    fn from(value: SigningKey) -> Self {
        let encoded_point = value.verifying_key().to_encoded_point(false);
        let key = jwk::EcPublicKey::builder()
            .crv("P-384")
            .x(encoded_point
                .x()
                .expect("uncompressed point always has x coordinate")
                .to_vec())
            .y(encoded_point
                .y()
                .expect("uncompressed point always has y coordinate")
                .to_vec())
            .build();

        Self {
            inner: Arc::new(value),
            key_metadata: KeyMetadata::builder().jws_algorithm(ALGORITHM).build(),
            jwk: jwk::PublicJwk::builder()
                .algorithm(ALGORITHM)
                .key_use(jwk::KeyUse::Sign)
                .key(key)
                .build(),
        }
    }
}

impl Es384PrivateKey {
    #[must_use]
    pub fn generate() -> Self {
        p384::ecdsa::SigningKey::generate().into()
    }

    pub async fn load_pkcs8_der<S: Secret<Output = SecretBox<[u8]>>>(
        secret: S,
    ) -> Result<Self, Es384PrivateKeyLoadError<S::Error>> {
        let der = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = SigningKey::from_pkcs8_der(der.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(key.into())
    }

    pub async fn load_pkcs8_pem<S: Secret<Output = SecretString>>(
        secret: S,
    ) -> Result<Self, Es384PrivateKeyLoadError<S::Error>> {
        let pem = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = SigningKey::from_pkcs8_pem(pem.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(key.into())
    }
}

impl JwsSigner for Es384PrivateKey {
    type Error = Infallible;

    fn key_metadata(&self) -> Cow<'_, KeyMetadata> {
        Cow::Borrowed(&self.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        let signature: Signature = self.inner.sign(input);
        Ok(signature.to_vec().into())
    }
}

impl HasPublicKey for Es384PrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.jwk
    }
}
