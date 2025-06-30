use {
    crate::signer::Signer,
    reqwest::{Client, Url},
    serde::Serialize,
    std::{sync::Arc, time::Duration},
    wormhole_sdk::vaa::Body,
};

pub struct ApiClientConfig {
    pub timeout: Option<Duration>,
}

struct ApiClientInner {
    client: Client,
    base_url: Url,
}

#[derive(Clone)]
pub struct ApiClient {
    inner: Arc<ApiClientInner>,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Observation<P: Serialize> {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub signature: [u8; 65],
    #[serde(serialize_with = "serialize_body")]
    pub body: Body<P>,
}

fn serialize_body<S, P>(body: &Body<P>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    P: Serialize,
{
    let serialized = serde_wormhole::to_vec(body).map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&serialized)
}

impl<P: Serialize> Observation<P> {
    pub fn try_new(body: Body<P>, signer: impl Signer) -> Result<Self, anyhow::Error> {
        let digest = body.digest()?;
        let signature = signer
            .sign(digest.secp256k_hash)
            .map_err(|e| anyhow::anyhow!("Failed to sign observation: {}", e))?;
        Ok(Self {
            version: 1,
            signature,
            body,
        })
    }
}

impl ApiClient {
    pub fn get_base_url(&self) -> &Url {
        &self.inner.base_url
    }

    pub fn try_new(
        base_url: String,
        config: Option<ApiClientConfig>,
    ) -> Result<Self, anyhow::Error> {
        let base_url =
            Url::parse(&base_url).map_err(|e| anyhow::anyhow!("Invalid base URL: {}", e))?;

        let timeout = config.and_then(|c| c.timeout).unwrap_or(DEFAULT_TIMEOUT);
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create api client: {}", e))?;

        let inner = ApiClientInner { client, base_url };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub async fn post_observation<P: Serialize>(
        &self,
        observation: Observation<P>,
    ) -> Result<(), anyhow::Error> {
        let url = self
            .inner
            .base_url
            .join("observation")
            .map_err(|e| anyhow::anyhow!("Failed to construct URL: {}", e))?;
        let response = self
            .inner
            .client
            .post(url)
            .json(&observation)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to post observation: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to post observation with status: {} - {}",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_else(|_| String::from("No response text"))
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message, PublicKey, Secp256k1, SecretKey,
    };
    use serde_json::Value;
    use serde_wormhole::RawMessage;
    use wormhole_sdk::{Address, Chain};

    use super::*;

    #[test]
    fn test_new_signed_observation() {
        let secret_key = SecretKey::from_byte_array(&[1u8; 32]).expect("Invalid secret key length");
        let signer = crate::signer::FileSigner { secret_key };
        let body = Body {
            timestamp: 1234567890,
            nonce: 42,
            emitter_chain: Chain::Solana,
            emitter_address: Address([1u8; 32]),
            sequence: 1000,
            consistency_level: 1,
            payload: vec![1, 2, 3, 4, 5],
        };
        let observation =
            Observation::try_new(body.clone(), signer).expect("Failed to create observation");
        assert_eq!(observation.version, 1);
        assert_eq!(observation.body, body);

        // Signature verification
        let secp = Secp256k1::new();
        let digest = body.digest().expect("Failed to compute digest");
        let message = Message::from_digest(digest.secp256k_hash);

        let recovery_id: RecoveryId = (observation.signature[64] as i32)
            .try_into()
            .expect("Invalid recovery ID");
        let recoverable_sig =
            RecoverableSignature::from_compact(&observation.signature[..64], recovery_id)
                .expect("Invalid recoverable signature");

        let pubkey = secp
            .recover_ecdsa(&message, &recoverable_sig)
            .expect("Failed to recover pubkey");

        let expected_pubkey = PublicKey::from_secret_key(&secp, &secret_key);
        assert_eq!(pubkey, expected_pubkey);
    }

    #[test]
    fn test_observation_serialization() {
        let payload = vec![5, 1, 2, 3, 4, 5];
        let observation = Observation {
            version: 1,
            signature: [1u8; 65],
            body: Body {
                timestamp: 1234567890,
                nonce: 42,
                emitter_chain: Chain::Solana,
                emitter_address: Address([1u8; 32]),
                sequence: 1000,
                consistency_level: 1,
                payload: RawMessage::new(payload.as_slice()),
            },
        };

        let serialized =
            serde_json::to_string(&observation).expect("Failed to serialize observation");
        let parsed: Value = serde_json::from_str(&serialized).expect("Failed to parse JSON");

        assert_eq!(parsed["version"], 1);
        let sig = parsed["signature"]
            .as_str()
            .expect("Signature should be a string");
        let decoded = hex::decode(sig).expect("Should be valid hex");
        assert_eq!(decoded, observation.signature);

        let message = parsed["body"].as_array().expect("Body should be an array");
        let bytes = message
            .iter()
            .map(|v| v.as_u64().expect("Body elements should be u64") as u8)
            .collect::<Vec<u8>>();
        let deserialized: Body<&RawMessage> =
            serde_wormhole::from_slice(&bytes).expect("Failed to deserialize body");
        assert_eq!(deserialized, observation.body);
    }
}
