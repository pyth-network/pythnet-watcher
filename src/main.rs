use borsh::BorshDeserialize;
use observation::{Body, SignedBody};
use posted_message::PostedMessageUnreliableData;
use secp256k1::{ecdsa::{RecoverableSignature, RecoveryId}, Message, PublicKey, Secp256k1, SecretKey};
use serde_wormhole::RawMessage;
use sha3::digest::crypto_common::rand_core::OsRng;
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    nonblocking::pubsub_client::PubsubClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
};
use solana_sdk::pubkey::Pubkey;
use wormhole_sdk::{vaa::{Body as BodyWormhole, Header, Signature}, Address, Chain, Vaa};
use std::str::FromStr;
use tokio_stream::StreamExt;
use sha3::{Digest, Keccak256};
use sha3::digest::crypto_common::rand_core::RngCore;

mod posted_message;
mod observation;
mod serde_array;

const PYTHNET_CHAIN_ID: u16 = 26;

fn generate_guardian_key() -> (SecretKey, [u8; 20]) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let secret_key = SecretKey::from_slice(&sk_bytes).expect("Failed to create secret key");

    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let uncompressed = public_key.serialize_uncompressed();

    let hash = Keccak256::digest(&uncompressed[1..]);
    let address: [u8; 20] = hash[12..].try_into().unwrap();

    (secret_key, address)
}

pub fn verify_vaa(public_key_original: [u8; 20], signed_body: SignedBody<Vec<u8>>) -> bool {
    let mut signature = Signature::default();
    signature.signature = signed_body.signature;
    let vaa: Vaa<Vec<u8>> = Vaa {
        version: signed_body.version,
        guardian_set_index: signed_body.guardian_set_index,
        signatures: vec![signature],
        timestamp: signed_body.body.timestamp,
        nonce: signed_body.body.nonce,
        emitter_chain: Chain::Pythnet,
        emitter_address: Address(signed_body.body.emitter_address),
        sequence: signed_body.body.sequence,
        consistency_level: 1,
        payload: signed_body.body.payload,
    };
    let (_, body): (Header, BodyWormhole<Vec<u8>>) = vaa.into();
    let digest = body.digest().expect("Failed to get digest");

    let secp = Secp256k1::new();
    let signature: [u8; 65] = signed_body.signature;

    // Recover the public key from an [u8; 65] serialized ECDSA signature in (v, r, s) format
    let recid = RecoveryId::try_from(signature[64] as i32).expect("Failed to create recovery ID");

    // An address is the last 20 bytes of the Keccak256 hash of the uncompressed public key.
    let pubkey: &[u8; 65] = &secp
        .recover_ecdsa(
            Message::from_digest(digest.secp256k_hash),
            &RecoverableSignature::from_compact(&signature[..64], recid).expect("Failed to create recoverable signature"),
        )
        .expect("Failed to recover public key")
        .serialize_uncompressed();

    // The address is the last 20 bytes of the Keccak256 hash of the public key
    let address: [u8; 32] = Keccak256::new_with_prefix(&pubkey[1..]).finalize().into();
    let address: [u8; 20] = address[address.len() - 20..].try_into()
        .expect("Failed to convert address to 20 bytes");

    println!("Recovered address: {:?}", address);
    println!("Public key: {:?}", public_key_original);
    // Confirm the recovered address matches an address in the guardian set.
    public_key_original == address
}

#[tokio::main]
async fn main() {
    let ws_url = "wss://api2.pythnet.pyth.network/"; 
    let accumulator_address = Pubkey::from_str("G9LV2mp9ua1znRAfYwZz5cPiJMAbo1T6mbjdQsDZuMJg").unwrap(); // Replace with actual Wormhole address
    let wormhole_pid = Pubkey::from_str("H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU").unwrap(); // Replace with actual Wormhole program ID
    let (secret_key, pulick_key) = generate_guardian_key();
    println!("Generated secret key: {:?}", secret_key);
    println!("Generated public key: {:?}", pulick_key);
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
            match body.sign(secret_key.secret_bytes()) {
                Ok(signature) => {
                    let signed_body = SignedBody {
                        version: unreliable_data.vaa_version,
                        guardian_set_index: index,
                        signature,
                        body,
                    };
                    // Post it to server
                    println!("message: {:?}", signed_body);
                    println!("The message is verified {}", verify_vaa(pulick_key, signed_body));
                }
                Err(e) => tracing::error!(error = ?e, "Failed to sign body"),
            }
        }
    }

    unsubscribe().await;
}
