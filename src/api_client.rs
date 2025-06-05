use {
    reqwest::{Client, Url},
    secp256k1::{Message, Secp256k1, SecretKey},
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
pub struct Observation<P> {
    pub version: u8,
    #[serde(with = "hex::serde")]
    pub signature: [u8; 65],
    pub body: Body<P>,
}

impl<P: Serialize> Observation<P> {
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

impl ApiClient {
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
