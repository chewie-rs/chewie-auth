use std::{hash::Hash, str::FromStr};

use serde::{Deserialize, Serialize};
use url::Url;

/// A URL used as a redirect parameter.
#[derive(Debug, Clone)]
pub struct RedirectUrl {
    original: String,
    parsed: Url,
}

impl RedirectUrl {
    /// Creates a new `RedirectUrl` value from a string.
    pub fn new(url: impl Into<String>) -> Result<Self, url::ParseError> {
        let original = url.into();
        let parsed = Url::parse(&original)?;

        Ok(Self { original, parsed })
    }

    /// Returns the original string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Returns the parsed URL.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.parsed
    }
}

impl FromStr for RedirectUrl {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl PartialEq for RedirectUrl {
    fn eq(&self, other: &Self) -> bool {
        self.original == other.original
    }
}

impl Eq for RedirectUrl {}

impl Hash for RedirectUrl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.original.hash(state);
    }
}

impl Serialize for RedirectUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.original)
    }
}

impl<'de> Deserialize<'de> for RedirectUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let original = String::deserialize(deserializer)?;
        let parsed = Url::parse(&original).map_err(serde::de::Error::custom)?;

        Ok(Self { original, parsed })
    }
}
