use {
    secp256k1::{
        Message,
        Secp256k1,
        SecretKey,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    sha3::Digest as Sha3Digest,
    std::io::Write,
};

/// The body for a VAA.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Body<P> {
    /// The timestamp of the block this message was published in.
    /// Seconds since UNIX epoch
    pub timestamp:         u32,
    pub nonce:             u32,
    pub emitter_chain:     u16,
    pub emitter_address:   [u8; 32],
    pub sequence:          u64,
    pub consistency_level: u8,
    pub payload:           P,
}

#[derive(Debug)]
pub enum Error {
    #[allow(dead_code)]
    DigestFailed(serde_wormhole::Error),
    #[allow(dead_code)]
    InvalidSecretKey(secp256k1::Error),
}

impl<P: Serialize> Body<P> {
    /// Body Digest Components.
    ///
    /// A VAA is distinguished by the unique 256bit Keccak256 hash of its body. This hash is
    /// utilised in all Wormhole components for identifying unique VAA's, including the bridge,
    /// modules, and core guardian software. The `Digest` is documented with reasoning for
    /// each field.
    ///
    /// NOTE: This function uses a library to do Keccak256 hashing, but on-chain this may not be
    /// efficient. If efficiency is needed, consider calling `serde_wormhole::to_writer` instead
    /// and hashing the result using on-chain primitives.
    #[inline]
    fn digest(&self) -> Result<[u8; 32], Error> {
        // The `body` of the VAA is hashed to produce a `digest` of the VAA.
        let hash: [u8; 32] = {
            let mut h = sha3::Keccak256::default();
            serde_wormhole::to_writer(&mut h, self).map_err(Error::DigestFailed)?;
            h.finalize().into()
        };

        // Hash `hash` again to get the secp256k internal hash, see `Digest` for detail.
        let secp256k_hash: [u8; 32] = {
            let mut h = sha3::Keccak256::default();
            h.write_all(&hash)
                .map_err(|e| Error::DigestFailed(e.into()))?;
            h.finalize().into()
        };

        Ok(secp256k_hash)
    }

    pub fn sign(&self, secret_key: [u8; 32]) -> Result<[u8; 65], Error> {
        let secp = Secp256k1::new();
        let digest = self.digest()?;
        let secret_key = SecretKey::from_slice(&secret_key).map_err(Error::InvalidSecretKey)?;
        let signature = secp.sign_ecdsa_recoverable(Message::from_digest(digest), &secret_key);
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let recovery_id: i32 = recovery_id.into();
        let mut result = [0u8; 65];
        result[..64].copy_from_slice(&signature_bytes);
        result[64] = recovery_id as u8;
        Ok(result)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedBody<P> {
    pub version:   u8,
    #[serde(with = "crate::serde_array")]
    pub signature: [u8; 65],

    #[serde(flatten)]
    pub body: Body<P>,
}
