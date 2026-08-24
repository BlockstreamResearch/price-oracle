use secp256k1_zkp::PublicKey;

use crate::error::Error;

pub(super) fn parse_public_key(encoded: &str) -> Result<String, Error> {
    let bytes = hex::decode(encoded).map_err(|_| Error::InvalidPublicKey(encoded.to_string()))?;
    let public_key =
        PublicKey::from_slice(&bytes).map_err(|_| Error::InvalidPublicKey(encoded.to_string()))?;
    Ok(hex::encode(public_key.serialize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PUBLIC_KEY: &str =
        "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";

    #[test]
    fn parses_a_valid_public_key() {
        assert_eq!(
            parse_public_key(VALID_PUBLIC_KEY).unwrap(),
            VALID_PUBLIC_KEY
        );
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(matches!(
            parse_public_key("not-a-public-key"),
            Err(Error::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn rejects_bytes_that_are_not_a_public_key() {
        let invalid_key = "00".repeat(33);

        assert!(matches!(
            parse_public_key(&invalid_key),
            Err(Error::InvalidPublicKey(_))
        ));
    }
}
