use bytes::Bytes;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::DecodePrivateKey;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use snafu::prelude::*;
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;

use crate::jwk::{self, PublicJwk};
use crate::secrets::Secret;
use crate::signer::{HasPublicKey, JwsSigner, KeyMetadata};

const ALGORITHM: &str = "ES256";

#[derive(Debug, Snafu)]
pub enum Es256PrivateKeyLoadError<E: crate::Error> {
    Secret {
        source: E,
    },
    #[snafu(display("Failed to decode PKCS#8 key"))]
    KeyDecode {
        source: p256::pkcs8::Error,
    },
}

#[derive(Clone)]
pub struct Es256PrivateKey {
    pub(super) inner: Arc<SigningKey>,
    key_metadata: KeyMetadata,
    jwk: PublicJwk,
}

impl From<SigningKey> for Es256PrivateKey {
    fn from(value: SigningKey) -> Self {
        let encoded_point = value.verifying_key().to_encoded_point(false);
        let key = jwk::EcPublicKey::builder()
            .crv("P-256")
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
            jwk: PublicJwk::builder()
                .algorithm(ALGORITHM)
                .key_use(jwk::KeyUse::Sign)
                .key(key)
                .build(),
        }
    }
}

impl Es256PrivateKey {
    #[must_use]
    pub fn generate() -> Self {
        p256::ecdsa::SigningKey::generate().into()
    }

    pub async fn load_pkcs8_der<S: Secret<Output = SecretBox<[u8]>>>(
        secret: S,
    ) -> Result<Self, Es256PrivateKeyLoadError<S::Error>> {
        let der = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = SigningKey::from_pkcs8_der(der.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(key.into())
    }

    pub async fn load_pkcs8_pem<S: Secret<Output = SecretString>>(
        secret: S,
    ) -> Result<Self, Es256PrivateKeyLoadError<S::Error>> {
        let pem = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = SigningKey::from_pkcs8_pem(pem.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(key.into())
    }
}

impl JwsSigner for Es256PrivateKey {
    type Error = Infallible;

    fn key_metadata(&self) -> Cow<'_, KeyMetadata> {
        Cow::Borrowed(&self.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        let signature: Signature = self.inner.sign(input);
        Ok(signature.to_vec().into())
    }
}

impl HasPublicKey for Es256PrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.jwk
    }
}
