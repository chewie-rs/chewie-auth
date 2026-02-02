use serde::Serializer;

pub(super) fn serialize_ed25519<S>(serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeStruct;

    let mut s = serializer.serialize_struct("Ed25519", 1).unwrap();
    s.serialize_field("name", "Ed25519").unwrap();
    s.end()
}

pub(super) fn serialize_x25519<S>(serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeStruct;

    let mut s = serializer.serialize_struct("X25519", 1).unwrap();
    s.serialize_field("name", "X25519").unwrap();
    s.end()
}

pub(super) fn serialize_hmac<S>(serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeStruct;

    let mut s = serializer.serialize_struct("HMAC", 1).unwrap();
    s.serialize_field("name", "HMAC").unwrap();
    s.end()
}

pub(super) fn serialize_rsa_pkcs1<S>(serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeStruct;

    let mut s = serializer.serialize_struct("RsaPkcs1", 1).unwrap();
    s.serialize_field("name", "RSASSA-PKCS1-v1_5").unwrap();
    s.end()
}
