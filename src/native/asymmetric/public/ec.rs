use snafu::prelude::*;
use std::sync::Arc;

#[derive(Debug, Snafu)]
pub enum EcKeyDecodeError {
    UnsupportedCurve {
        /// The unsupported curve type.
        curve: String,
    },
    /// Signature error.
    Signature {
        /// The underlying error.
        source: p256::ecdsa::Error,
    },
}

#[derive(Clone)]
pub enum EcPublicKey {
    P256(Arc<p256::ecdsa::VerifyingKey>),
    P384(Arc<p384::ecdsa::VerifyingKey>),
    P521(Arc<p521::ecdsa::VerifyingKey>),
}

impl std::fmt::Debug for EcPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P256(_) => f.debug_tuple("P256").finish_non_exhaustive(),
            Self::P384(_) => f.debug_tuple("P384").finish_non_exhaustive(),
            Self::P521(_) => f.debug_tuple("P521").finish_non_exhaustive(),
        }
    }
}

impl From<p256::ecdsa::VerifyingKey> for EcPublicKey {
    fn from(value: p256::ecdsa::VerifyingKey) -> Self {
        Self::P256(Arc::new(value))
    }
}

impl From<p384::ecdsa::VerifyingKey> for EcPublicKey {
    fn from(value: p384::ecdsa::VerifyingKey) -> Self {
        Self::P384(Arc::new(value))
    }
}

impl From<p521::ecdsa::VerifyingKey> for EcPublicKey {
    fn from(value: p521::ecdsa::VerifyingKey) -> Self {
        Self::P521(Arc::new(value))
    }
}

impl TryFrom<chewie_auth::jwk::EcPublicKey> for EcPublicKey {
    type Error = EcKeyDecodeError;

    fn try_from(value: chewie_auth::jwk::EcPublicKey) -> Result<Self, Self::Error> {
        match value.crv.as_ref() {
            "P-256" => {
                let key = p256::ecdsa::VerifyingKey::from_encoded_point(
                    &p256::EncodedPoint::from_affine_coordinates(
                        value.x.as_slice().into(),
                        value.y.as_slice().into(),
                        false,
                    ),
                )
                .context(SignatureSnafu)?;
                Ok(key.into())
            }
            "P-384" => {
                let key = p384::ecdsa::VerifyingKey::from_encoded_point(
                    &p384::EncodedPoint::from_affine_coordinates(
                        value.x.as_slice().into(),
                        value.y.as_slice().into(),
                        false,
                    ),
                )
                .context(SignatureSnafu)?;
                Ok(key.into())
            }
            "P-521" => {
                let key = p521::ecdsa::VerifyingKey::from_encoded_point(
                    &p521::EncodedPoint::from_affine_coordinates(
                        value.x.as_slice().into(),
                        value.y.as_slice().into(),
                        false,
                    ),
                )
                .context(SignatureSnafu)?;
                Ok(key.into())
            }
            curve => UnsupportedCurveSnafu { curve }.fail(),
        }
    }
}
