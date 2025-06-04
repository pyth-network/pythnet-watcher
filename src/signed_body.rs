use {
    secp256k1::{
        Message,
        Secp256k1,
        SecretKey,
    },
    serde::Serialize,
    wormhole_sdk::vaa::Body,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedBody<P> {
    pub version:   u8,
    pub signature: [u8; 65],
    pub body:      Body<P>,
}

impl<P: Serialize> SignedBody<P> {
    pub fn try_new(body: Body<P>, secret_key: SecretKey) -> Result<Self, anyhow::Error> {
        let digest = body.digest()?;
        let signature = Secp256k1::new()
            .sign_ecdsa_recoverable(Message::from_digest(digest.secp256k_hash), &secret_key);
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let recovery_id: i32 = recovery_id.into();
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&signature_bytes);
        signature[64] = recovery_id as u8;

        Ok(Self {
            version: 1,
            signature,
            body,
        })
    }
}
