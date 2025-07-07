use std::{
    fs,
    io::{Cursor, Read},
    path::PathBuf,
    str::FromStr,
};

use async_trait::async_trait;
use prost::Message as ProstMessage;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sequoia_openpgp::armor::{Kind, Reader, ReaderMode};
use sha3::{Digest, Keccak256};

#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, data: [u8; 32]) -> anyhow::Result<[u8; 65]>;
    async fn get_public_key(&self) -> anyhow::Result<(PublicKey, [u8; 20])>;
}

#[derive(Clone, Debug)]
pub struct FileSigner {
    pub secret_key: SecretKey,
}

#[derive(Clone, PartialEq, ProstMessage)]
pub struct GuardianKey {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub unsafe_deterministic_key: bool,
}

pub const GUARDIAN_KEY_ARMORED_BLOCK: &str = "WORMHOLE GUARDIAN PRIVATE KEY";
pub const STANDARD_ARMOR_LINE_HEADER: &str = "PGP PRIVATE KEY BLOCK";

impl FileSigner {
    pub fn try_new(secret_key_path: PathBuf, mode: crate::config::Mode) -> anyhow::Result<Self> {
        let content = fs::read_to_string(secret_key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read secret key file: {}", e))?;
        let guardian_key = Self::parse_and_verify_proto_guardian_key(content, mode)?;
        Ok(FileSigner {
            secret_key: SecretKey::from_slice(&guardian_key.data)
                .map_err(|e| anyhow::anyhow!("Failed to create SecretKey: {}", e))?,
        })
    }

    pub fn parse_and_verify_proto_guardian_key(
        content: String,
        mode: crate::config::Mode,
    ) -> anyhow::Result<GuardianKey> {
        let content = content.replace(GUARDIAN_KEY_ARMORED_BLOCK, STANDARD_ARMOR_LINE_HEADER);
        let cursor = Cursor::new(content);
        let mut armor_reader =
            Reader::from_reader(cursor, ReaderMode::Tolerant(Some(Kind::SecretKey)));

        let mut buf = Vec::new();
        armor_reader
            .read_to_end(&mut buf)
            .map_err(|e| anyhow::anyhow!("Failed to read armored key: {}", e))?;

        let guardian_key = GuardianKey::decode(&mut buf.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to decode GuardianKey: {}", e))?;

        if let crate::config::Mode::Production = mode {
            if guardian_key.unsafe_deterministic_key {
                return Err(anyhow::anyhow!(
                    "Unsafe deterministic key is not allowed in production mode"
                ));
            }
        }

        Ok(guardian_key)
    }
}

fn get_evm_public_key(public_key: &PublicKey) -> anyhow::Result<[u8; 20]> {
    let pubkey_uncompressed = public_key.serialize_uncompressed();
    let pubkey_hash: [u8; 32] = Keccak256::new_with_prefix(&pubkey_uncompressed[1..])
        .finalize()
        .into();
    let pubkey_evm: [u8; 20] = pubkey_hash[pubkey_hash.len() - 20..]
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to convert public key hash to EVM format: {}", e))?;
    Ok(pubkey_evm)
}

#[async_trait]
impl Signer for FileSigner {
    async fn sign(&self, data: [u8; 32]) -> anyhow::Result<[u8; 65]> {
        let signature =
            Secp256k1::new().sign_ecdsa_recoverable(&Message::from_digest(data), &self.secret_key);
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let recovery_id: i32 = recovery_id.into();
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&signature_bytes);
        signature[64] = recovery_id as u8;
        Ok(signature)
    }

    async fn get_public_key(&self) -> anyhow::Result<(PublicKey, [u8; 20])> {
        let secp = Secp256k1::new();
        let public_key = self.secret_key.public_key(&secp);
        let pubkey_evm = get_evm_public_key(&public_key)?;
        Ok((public_key, pubkey_evm))
    }
}

#[derive(Clone, Debug)]
pub struct KMSSigner {
    client: aws_sdk_kms::Client,
    arn: aws_arn::ResourceName,
}

impl KMSSigner {
    pub async fn try_new(arn_string: String) -> anyhow::Result<Self> {
        let config = aws_config::load_from_env().await;
        let client = aws_sdk_kms::Client::new(&config);
        let arn = aws_arn::ResourceName::from_str(&arn_string)?;
        Ok(KMSSigner { client, arn })
    }
}

#[async_trait]
impl Signer for KMSSigner {
    async fn sign(&self, data: [u8; 32]) -> anyhow::Result<[u8; 65]> {
        let result = self
            .client
            .sign()
            .key_id(self.arn.to_string())
            .message(data.to_vec().into())
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to sign data with KMS: {}", e))?;
        result
            .signature
            .ok_or_else(|| anyhow::anyhow!("KMS did not return a signature"))
            .and_then(|sig| {
                let sig = sig.into_inner();
                let signature: [u8; 65] = sig
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Failed to convert KMS signature: {:?}", e))?;
                Ok(signature)
            })
    }

    async fn get_public_key(&self) -> anyhow::Result<(PublicKey, [u8; 20])> {
        let result = self
            .client
            .get_public_key()
            .key_id(self.arn.to_string())
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get public key from KMS: {}", e))?;
        let public_key = result
            .public_key
            .ok_or(anyhow::anyhow!("KMS did not return a public key"))?;
        let public_key = PublicKey::from_slice(public_key.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to create PublicKey from KMS: {}", e))?;
        let pubkey_evm = get_evm_public_key(&public_key)?;
        Ok((public_key, pubkey_evm))
    }
}
