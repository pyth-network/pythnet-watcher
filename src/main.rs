use borsh::BorshDeserialize;
use observation::{Body, SignedBody};
use posted_message::PostedMessageUnreliableData;
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    nonblocking::pubsub_client::PubsubClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
};
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use std::str::FromStr;
use tokio_stream::StreamExt;

mod posted_message;
mod observation;
mod serde_array;

const PYTHNET_CHAIN_ID: u16 = 26;

#[tokio::main]
async fn main() {
    let ws_url = "wss://api2.pythnet.pyth.network/"; 
    let accumulator_address = Pubkey::from_str("G9LV2mp9ua1znRAfYwZz5cPiJMAbo1T6mbjdQsDZuMJg").unwrap(); // Replace with actual Wormhole address
    let wormhole_pid = Pubkey::from_str("H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU").unwrap(); // Replace with actual Wormhole program ID
    let secret_key = Keypair::new().secret().to_bytes();
    let index = 0;

    let client = PubsubClient::new(ws_url).await.unwrap();
    let (mut stream, unsubscribe) = client.program_subscribe(
        &wormhole_pid,
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
    .await
    .unwrap();

    while let Some(update) = stream.next().await {
        let ring_index = (update.context.slot % 10_000) as u32;
        let (message_pda, _) = Pubkey::find_program_address(
            &[b"AccumulatorMessage", &ring_index.to_be_bytes()],
            &wormhole_pid,
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
            if accumulator_address != Pubkey::from(unreliable_data.emitter_address) {
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
            match body.sign(secret_key) {
                Ok(signature) => {
                    let signed_body = SignedBody {
                        version: unreliable_data.vaa_version,
                        guardian_set_index: index,
                        signature,
                        body,
                    };
                    // Post it to server
                    println!("message: {:?}", signed_body);
                }
                Err(e) => tracing::error!(error = ?e, "Failed to sign body"),
            }
        }
    }

    unsubscribe().await;
}
