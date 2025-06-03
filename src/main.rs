use borsh::BorshDeserialize;
use observation::{Body, SignedBody};
use posted_message::PostedMessageUnreliableData;
use secp256k1::SecretKey;
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    nonblocking::pubsub_client::PubsubClient, pubsub_client::PubsubClientError, rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig}
};
use solana_sdk::pubkey::Pubkey;
use tokio::time::sleep;
use core::panic;
use std::{fs, path::PathBuf, str::FromStr, time::Duration};
use tokio_stream::StreamExt;
use clap::Parser;

mod posted_message;
mod observation;
mod serde_array;
mod config;

const PYTHNET_CHAIN_ID: u16 = 26;

struct ListenerConfig {
    ws_url: String,
    secret_key: SecretKey,
    wormhole_pid: Pubkey,
    accumulator_address: Pubkey,
}

fn find_message_pda(
    wormhole_pid: &Pubkey,
    ring_index: u32,
) -> Pubkey {
    Pubkey::find_program_address(
        &[b"AccumulatorMessage", &ring_index.to_be_bytes()],
        wormhole_pid,
    ).0
}

async fn run_listener(config: ListenerConfig) -> Result<(), PubsubClientError> {
    let client = PubsubClient::new(config.ws_url.as_str()).await?;
    let (mut stream, unsubscribe) = client.program_subscribe(
        &config.wormhole_pid,
        Some(RpcProgramAccountsConfig { 
            filters: None,
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                data_slice: None,
                commitment: Some(solana_sdk::commitment_config::CommitmentConfig::confirmed()),
                min_context_slot: None,
            }, 
            with_context: None, 
            sort_results: None
        }),
    )
    .await?;

    while let Some(update) = stream.next().await {
        let message_pda = find_message_pda(
            &config.wormhole_pid, 
            (update.context.slot % 10_000) as u32
        );
        if message_pda.to_string() != update.value.pubkey {
            continue; // Skip updates that are not for the expected PDA
        }

        let unreliable_data: Option<PostedMessageUnreliableData> = update.value.account.data.decode().map(|data| {
            BorshDeserialize::deserialize(&mut data.as_slice()).ok()
        }).flatten();

        if let Some(unreliable_data) = unreliable_data {
            if PYTHNET_CHAIN_ID != unreliable_data.emitter_chain {
                continue;
            }
            if config.accumulator_address != Pubkey::from(unreliable_data.emitter_address) {
                continue;
            }

            let body = Body {
                timestamp: unreliable_data.submission_time,
                nonce: unreliable_data.nonce,
                emitter_chain: unreliable_data.emitter_chain,
                emitter_address: unreliable_data.emitter_address,
                sequence: unreliable_data.sequence,
                consistency_level: unreliable_data.consistency_level,
                payload: unreliable_data.payload.clone(),
            };

            match body.sign(config.secret_key.secret_bytes()) {
                Ok(signature) => {
                    let signed_body = SignedBody {
                        version: unreliable_data.vaa_version,
                        signature,
                        body,
                    };
                    println!("Signed Body: {:?}", signed_body);
                }
                Err(e) => tracing::error!(error = ?e, "Failed to sign body"),
            }
        }
    }

    tokio::spawn(async move {
        // Wait for the stream to finish
        unsubscribe().await
    });

    Err(PubsubClientError::ConnectionClosed("Stream ended".to_string()))
}

fn load_secret_key(path: String) -> SecretKey {
    let bytes = fs::read(path.clone()).expect("Invalid secret key file");
    if bytes.len() == 32 {
        let byte_array: [u8; 32] = bytes.try_into().expect("Invalid secret key length");
        return SecretKey::from_byte_array(byte_array).expect("Invalid secret key length");
    }

    let content = fs::read_to_string(path).expect("Invalid secret key file").trim().to_string();
    if let Ok(secret_key) = SecretKey::from_str(&content) {
        return secret_key;
    }

    panic!("Invalid secret key");
}

#[tokio::main]
async fn main() {
    let run_options = config::RunOptions::parse();
    let secret_key = load_secret_key(run_options.secret_key_path);
    let client = PubsubClient::new(&run_options.pythnet_url).await.expect("Invalid WebSocket URL");
    drop(client); // Drop the client to avoid holding the connection open
    let accumulator_address = Pubkey::from_str(&run_options.accumulator_address).expect("Invalid accumulator address");
    let wormhole_pid = Pubkey::from_str(&run_options.wormhole_pid).expect("Invalid Wormhole program ID");

    loop {
        if let Err(e) = run_listener(ListenerConfig { 
            ws_url: run_options.pythnet_url.clone(),
            secret_key, 
            wormhole_pid, 
            accumulator_address,
        }).await {
            tracing::error!(error = ?e, "Error listening to messages");
            sleep(Duration::from_millis(200)).await; // Wait before retrying
        }
    }
}
