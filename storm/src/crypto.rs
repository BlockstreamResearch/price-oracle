use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey, ecdh::SharedSecret};
use snow::{
    Builder,
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver, FallbackResolver},
    types::{Cipher, Dh, Hash, Random},
};

use crate::constants;

pub(super) fn noise_builder() -> Builder<'static> {
    Builder::with_resolver(
        constants::NOISE_PARAMS.clone(),
        Box::new(FallbackResolver::new(
            Box::new(Secp256k1Resolver),
            Box::new(DefaultResolver),
        )),
    )
}

struct Secp256k1Resolver;

impl CryptoResolver for Secp256k1Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        None
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::P256 => Some(Box::new(Secp256k1Dh::default())),
            _ => None,
        }
    }

    fn resolve_hash(&self, _choice: &HashChoice) -> Option<Box<dyn Hash>> {
        None
    }

    fn resolve_cipher(&self, _choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        None
    }
}

struct Secp256k1Dh {
    private_key: [u8; 32],
    public_key: [u8; 33],
}

impl Default for Secp256k1Dh {
    fn default() -> Self {
        Self {
            private_key: [0; 32],
            public_key: [0; 33],
        }
    }
}

impl Secp256k1Dh {
    fn set_secret_key(&mut self, secret_key: SecretKey) {
        self.private_key = secret_key.secret_bytes();
        self.public_key = secret_key.public_key(&Secp256k1::new()).serialize();
    }
}

impl Dh for Secp256k1Dh {
    fn name(&self) -> &'static str {
        "secp256k1"
    }

    fn pub_len(&self) -> usize {
        33
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, private_key: &[u8]) {
        let secret_key = SecretKey::from_slice(private_key)
            .expect("Noise provided an invalid secp256k1 private key");
        self.set_secret_key(secret_key);
    }

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        loop {
            let mut private_key = [0_u8; 32];
            rng.try_fill_bytes(&mut private_key)?;

            if let Ok(secret_key) = SecretKey::from_slice(&private_key) {
                self.set_secret_key(secret_key);
                return Ok(());
            }
        }
    }

    fn pubkey(&self) -> &[u8] {
        &self.public_key
    }

    fn privkey(&self) -> &[u8] {
        &self.private_key
    }

    fn dh(&self, public_key: &[u8], output: &mut [u8]) -> Result<(), snow::Error> {
        let secret_key = SecretKey::from_slice(&self.private_key).map_err(|_| snow::Error::Dh)?;
        let public_key =
            PublicKey::from_slice(public_key.get(..self.pub_len()).ok_or(snow::Error::Dh)?)
                .map_err(|_| snow::Error::Dh)?;
        let shared_secret = SharedSecret::new(&public_key, &secret_key).secret_bytes();
        output
            .get_mut(..shared_secret.len())
            .ok_or(snow::Error::Dh)?
            .copy_from_slice(&shared_secret);
        Ok(())
    }

    fn dh_len(&self) -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_completes_mutually_authenticated_handshake() {
        let initiator_key = noise_builder().generate_keypair().unwrap();
        let responder_key = noise_builder().generate_keypair().unwrap();
        let mut initiator = noise_builder()
            .local_private_key(&initiator_key.private)
            .unwrap()
            .remote_public_key(&responder_key.public)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut responder = noise_builder()
            .local_private_key(&responder_key.private)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut message = [0_u8; 256];
        let mut payload = [0_u8; 256];

        let length = initiator.write_message(&[], &mut message).unwrap();
        responder
            .read_message(&message[..length], &mut payload)
            .unwrap();
        let length = responder.write_message(&[], &mut message).unwrap();
        initiator
            .read_message(&message[..length], &mut payload)
            .unwrap();

        assert_eq!(
            initiator.get_remote_static(),
            Some(responder_key.public.as_slice())
        );
        assert_eq!(
            responder.get_remote_static(),
            Some(initiator_key.public.as_slice())
        );
        assert!(initiator.into_transport_mode().is_ok());
        assert!(responder.into_transport_mode().is_ok());
    }
}
