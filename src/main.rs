use {
    crate::api_client::ApiClient,
    api_client::Observation,
    borsh::BorshDeserialize,
    clap::Parser,
    posted_message::PostedMessageUnreliableData,
    secp256k1::SecretKey,
    solana_account_decoder::UiAccountEncoding,
    solana_client::{
        nonblocking::pubsub_client::PubsubClient,
        pubsub_client::PubsubClientError,
        rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
        rpc_filter::{Memcmp, RpcFilterType},
    },
    solana_sdk::pubkey::Pubkey,
    std::{fs, str::FromStr, time::Duration},
    tokio::time::sleep,
    tokio_stream::StreamExt,
    wormhole_sdk::{vaa::Body, Address, Chain},
};

mod api_client;
mod config;
mod posted_message;

struct RunListenerInput {
    ws_url:              String,
    secret_key:          SecretKey,
    wormhole_pid:        Pubkey,
    accumulator_address: Pubkey,
    api_client:          ApiClient,
}

fn find_message_pda(wormhole_pid: &Pubkey, slot: u64) -> Pubkey {
    let ring_index = (slot % 10_000) as u32;
    Pubkey::find_program_address(
        &[b"AccumulatorMessage", &ring_index.to_be_bytes()],
        wormhole_pid,
    )
    .0
}

async fn run_listener(input: RunListenerInput) -> Result<(), PubsubClientError> {
    let client = PubsubClient::new(input.ws_url.as_str()).await?;
    let (mut stream, unsubscribe) = client
        .program_subscribe(
            &input.wormhole_pid,
            Some(RpcProgramAccountsConfig {
                filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new(
                    0,
                    solana_client::rpc_filter::MemcmpEncodedBytes::Bytes(b"msu".to_vec()),
                ))]),
                account_config: RpcAccountInfoConfig {
                    encoding: Some(UiAccountEncoding::Base64),
                    data_slice: None,
                    commitment: Some(solana_sdk::commitment_config::CommitmentConfig::confirmed()),
                    min_context_slot: None,
                },
                with_context: None,
                sort_results: None,
            }),
        )
        .await?;

    while let Some(update) = stream.next().await {
        if find_message_pda(&input.wormhole_pid, update.context.slot).to_string()
            != update.value.pubkey
        {
            continue; // Skip updates that are not for the expected PDA
        }

        let unreliable_data: PostedMessageUnreliableData = {
            let data = match update.value.account.data.decode() {
                Some(data) => data,
                None => {
                    tracing::error!("Failed to decode account data");
                    continue;
                }
            };

            match BorshDeserialize::deserialize(&mut data.as_slice()) {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = ?e, "Invalid unreliable data format");
                    continue;
                }
            }
        };

        if Chain::Pythnet != unreliable_data.emitter_chain.into() {
            continue;
        }
        if input.accumulator_address != Pubkey::from(unreliable_data.emitter_address) {
            continue;
        }

        let body = Body {
            timestamp: unreliable_data.submission_time,
            nonce: unreliable_data.nonce,
            emitter_chain: unreliable_data.emitter_chain.into(),
            emitter_address: Address(unreliable_data.emitter_address),
            sequence: unreliable_data.sequence,
            consistency_level: unreliable_data.consistency_level,
            payload: unreliable_data.payload.clone(),
        };

        match Observation::try_new(body, input.secret_key) {
            Ok(observation) => {
                if let Err(e) = input.api_client.post_observation(observation).await {
                    tracing::error!(error = ?e, "Failed to post observation");
                } else {
                    tracing::info!("Observation posted successfully");
                }
            }
            Err(e) => tracing::error!(error = ?e, "Failed to create observation"),
        };
    }

    tokio::spawn(async move { unsubscribe().await });

    Err(PubsubClientError::ConnectionClosed(
        "Stream ended".to_string(),
    ))
}

fn load_secret_key(path: String) -> SecretKey {
    let bytes = fs::read(path.clone()).expect("Invalid secret key file");
    if bytes.len() == 32 {
        let byte_array: [u8; 32] = bytes.try_into().expect("Invalid secret key length");
        return SecretKey::from_byte_array(byte_array).expect("Invalid secret key length");
    }

    let content = fs::read_to_string(path)
        .expect("Invalid secret key file")
        .trim()
        .to_string();
    SecretKey::from_str(&content).expect("Invalid secret key")
}

#[tokio::main]
async fn main() {
    let run_options = config::RunOptions::parse();
    let secret_key = load_secret_key(run_options.secret_key_path);
    let client = PubsubClient::new(&run_options.pythnet_url)
        .await
        .expect("Invalid WebSocket URL");
    drop(client); // Drop the client to avoid holding the connection open
    let accumulator_address = Pubkey::from_str("G9LV2mp9ua1znRAfYwZz5cPiJMAbo1T6mbjdQsDZuMJg")
        .expect("Invalid accumulator address");
    let wormhole_pid =
        Pubkey::from_str(&run_options.wormhole_pid).expect("Invalid Wormhole program ID");
    let api_client =
        ApiClient::try_new(run_options.server_url, None).expect("Failed to create API client");

    loop {
        if let Err(e) = run_listener(RunListenerInput {
            ws_url: run_options.pythnet_url.clone(),
            secret_key,
            wormhole_pid,
            accumulator_address,
            api_client: api_client.clone(),
        })
        .await
        {
            tracing::error!(error = ?e, "Error listening to messages");
            sleep(Duration::from_millis(200)).await; // Wait before retrying
        }
    }
}
