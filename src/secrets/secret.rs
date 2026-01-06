use crate::platform::{MaybeSend, MaybeSendSync};

/// Trait for async secret retrieval.
pub trait Secret: MaybeSendSync + Clone {
    /// The error type returned by this secret source's operations.
    type Error: crate::Error + 'static;

    /// The type of secret this source provides.
    type Output: MaybeSendSync;

    /// Retrieves the secret value.
    fn get_secret_value(
        &self,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + MaybeSend;
}
