use bytes::Bytes;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::traits::PublicKeyParts;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use snafu::prelude::*;
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;

use crate::crypto::signer::{HasPublicKey, JwsSigningKey, SigningKeyMetadata};
use crate::jwk::{self, PublicJwk};
use crate::secrets::Secret;

pub enum RsaAlgorithm {
    Rs256,
    Ps256,
    Ps384,
    Ps512,
}

impl AsRef<str> for RsaAlgorithm {
    fn as_ref(&self) -> &str {
        match self {
            RsaAlgorithm::Rs256 => "RS256",
            RsaAlgorithm::Ps256 => "PS256",
            RsaAlgorithm::Ps384 => "PS384",
            RsaAlgorithm::Ps512 => "PS512",
        }
    }
}

enum SigningKey {
    Rs256(rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>),
    Ps256(rsa::pss::SigningKey<rsa::sha2::Sha256>),
    Ps384(rsa::pss::SigningKey<rsa::sha2::Sha384>),
    Ps512(rsa::pss::SigningKey<rsa::sha2::Sha512>),
}

impl SigningKey {
    pub fn sign(&self, msg: &[u8]) -> bytes::Bytes {
        use rsa::signature::RandomizedSigner;

        match self {
            SigningKey::Rs256(signing_key) => signing_key.sign(msg).to_vec().into(),
            SigningKey::Ps256(signing_key) => signing_key
                .sign_with_rng(&mut rand::rng(), msg)
                .to_vec()
                .into(),
            SigningKey::Ps384(signing_key) => signing_key
                .sign_with_rng(&mut rand::rng(), msg)
                .to_vec()
                .into(),
            SigningKey::Ps512(signing_key) => signing_key
                .sign_with_rng(&mut rand::rng(), msg)
                .to_vec()
                .into(),
        }
    }
}

#[derive(Debug, Snafu)]
pub enum RsaPrivateKeyLoadError<E: crate::Error> {
    Secret {
        source: E,
    },
    #[snafu(display("Failed to decode PKCS#8 key"))]
    KeyDecode {
        source: rsa::pkcs8::Error,
    },
}

#[derive(Clone)]
pub struct RsaPrivateKey {
    inner: Arc<SigningKey>,
    key_metadata: SigningKeyMetadata,
    jwk: PublicJwk,
}

fn convert(private_key: rsa::RsaPrivateKey, algorithm: RsaAlgorithm) -> RsaPrivateKey {
    let public_key = jwk::RsaPublicKey::builder()
        .e(private_key.e_bytes())
        .n(private_key.n_bytes())
        .build();

    let signing_key = match algorithm {
        RsaAlgorithm::Rs256 => SigningKey::Rs256(
            rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private_key),
        ),
        RsaAlgorithm::Ps256 => {
            SigningKey::Ps256(rsa::pss::SigningKey::<rsa::sha2::Sha256>::new(private_key))
        }
        RsaAlgorithm::Ps384 => {
            SigningKey::Ps384(rsa::pss::SigningKey::<rsa::sha2::Sha384>::new(private_key))
        }
        RsaAlgorithm::Ps512 => {
            SigningKey::Ps512(rsa::pss::SigningKey::<rsa::sha2::Sha512>::new(private_key))
        }
    };

    RsaPrivateKey {
        inner: Arc::new(signing_key),
        key_metadata: SigningKeyMetadata::builder()
            .jws_algorithm(algorithm.as_ref())
            .build(),
        jwk: PublicJwk::builder()
            .algorithm(algorithm.as_ref())
            .key_use(jwk::KeyUse::Sign)
            .key(public_key)
            .build(),
    }
}

impl RsaPrivateKey {
    #[must_use]
    pub fn generate(algorithm: RsaAlgorithm) -> Result<Self, rsa::Error> {
        Ok(convert(
            rsa::RsaPrivateKey::new(&mut rand::rng(), 2048)?,
            algorithm,
        ))
    }

    pub async fn load_pkcs8_der<S: Secret<Output = SecretBox<[u8]>>>(
        secret: S,
        algorithm: RsaAlgorithm,
    ) -> Result<Self, RsaPrivateKeyLoadError<S::Error>> {
        let der = secret.get_secret_value().await.context(SecretSnafu)?;
        let key =
            rsa::RsaPrivateKey::from_pkcs8_der(der.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(convert(key, algorithm))
    }

    pub async fn load_pkcs8_pem<S: Secret<Output = SecretString>>(
        secret: S,
        algorithm: RsaAlgorithm,
    ) -> Result<Self, RsaPrivateKeyLoadError<S::Error>> {
        let pem = secret.get_secret_value().await.context(SecretSnafu)?;
        let key =
            rsa::RsaPrivateKey::from_pkcs8_pem(pem.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(convert(key, algorithm))
    }
}

impl JwsSigningKey for RsaPrivateKey {
    type Error = Infallible;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        Ok(self.inner.sign(input))
    }
}

impl HasPublicKey for RsaPrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.jwk
    }
}
