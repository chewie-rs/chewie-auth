use crate::{crypto::signer::BoxedJwsSigningKey, platform::MaybeSendSync};

pub trait KeyResolver: MaybeSendSync {
    type Error: crate::Error;

    fn verification_key(
        &self,
        kid: Option<&str>,
        alg: &str,
    ) -> Result<BoxedJwsSigningKey, Self::Error>;
}
