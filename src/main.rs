use {
    crate::config::Command,
    api_client::{ApiClient, Observation},
    borsh::BorshDeserialize,
    clap::Parser,
    posted_message::PostedMessageUnreliableData,
    secp256k1::{rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey},
    serde_wormhole::RawMessage,
    sha3::{Digest, Keccak256},
    solana_account_decoder::UiAccountEncoding,
    solana_client::{
        nonblocking::pubsub_client::PubsubClient,
        pubsub_client::PubsubClientError,
        rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
        rpc_filter::{Memcmp, RpcFilterType},
        rpc_response::{Response, RpcKeyedAccount},
    },
    solana_sdk::pubkey::Pubkey,
    std::{fs, io::IsTerminal, str::FromStr, time::Duration},
    tokio::time::sleep,
    tokio_stream::StreamExt,
    wormhole_sdk::{vaa::Body, Address, Chain},
};

mod api_client;
mod config;
mod posted_message;

struct RunListenerInput {
    ws_url: String,
    secret_key: SecretKey,
    wormhole_pid: Pubkey,
    accumulator_address: Pubkey,
    api_client: ApiClient,
}

fn find_message_pda(wormhole_pid: &Pubkey, slot: u64) -> Pubkey {
    let ring_index = (slot % 10_000) as u32;
    Pubkey::find_program_address(
        &[b"AccumulatorMessage", &ring_index.to_be_bytes()],
        wormhole_pid,
    )
    .0
}

const FAILED_TO_DECODE: &str = "Failed to decode account data";
const INVALID_UNRELIABLE_DATA_FORMAT: &str = "Invalid unreliable data format";
const INVALID_PDA_MESSAGE: &str = "Invalid PDA message";
const INVALID_EMITTER_CHAIN: &str = "Invalid emitter chain";
const INVALID_ACCUMULATOR_ADDRESS: &str = "Invalid accumulator address";

fn decode_and_verify_update(
    wormhole_pid: &Pubkey,
    accumulator_address: &Pubkey,
    update: Response<RpcKeyedAccount>,
) -> anyhow::Result<PostedMessageUnreliableData> {
    if find_message_pda(wormhole_pid, update.context.slot).to_string() != update.value.pubkey {
        return Err(anyhow::anyhow!(INVALID_PDA_MESSAGE));
    }
    let data = update.value.account.data.decode().ok_or_else(|| {
        tracing::error!(
            data = ?update.value.account.data,
            "Failed to decode account data",
        );
        anyhow::anyhow!(FAILED_TO_DECODE)
    })?;
    let unreliable_data: PostedMessageUnreliableData =
        BorshDeserialize::deserialize(&mut data.as_slice()).map_err(|e| {
            tracing::error!(
                data = ?data,
                error = ?e,
                "Failed to decode unreliable data",
            );
            anyhow::anyhow!(format!("{}: {}", INVALID_UNRELIABLE_DATA_FORMAT, e))
        })?;

    if Chain::Pythnet != unreliable_data.emitter_chain.into() {
        tracing::error!(
            emitter_chain = unreliable_data.emitter_chain,
            "Invalid emitter chain"
        );
        return Err(anyhow::anyhow!(INVALID_EMITTER_CHAIN));
    }

    if accumulator_address != &Pubkey::from(unreliable_data.emitter_address) {
        tracing::error!(
            emitter_address = ?unreliable_data.emitter_address,
            "Invalid accumulator address"
        );
        return Err(anyhow::anyhow!(INVALID_ACCUMULATOR_ADDRESS));
    }

    Ok(unreliable_data)
}

fn message_data_to_body(unreliable_data: &PostedMessageUnreliableData) -> Body<&RawMessage> {
    Body {
        timestamp: unreliable_data.submission_time,
        nonce: unreliable_data.nonce,
        emitter_chain: unreliable_data.emitter_chain.into(),
        emitter_address: Address(unreliable_data.emitter_address),
        sequence: unreliable_data.sequence,
        consistency_level: unreliable_data.consistency_level,
        payload: RawMessage::new(unreliable_data.payload.as_slice()),
    }
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
        let unreliable_data =
            match decode_and_verify_update(&input.wormhole_pid, &input.accumulator_address, update)
            {
                Ok(data) => data,
                Err(_) => continue,
            };

        tokio::spawn({
            let api_client = input.api_client.clone();
            async move {
                let body = message_data_to_body(&unreliable_data);
                match Observation::try_new(body.clone(), input.secret_key) {
                    Ok(observation) => {
                        if let Err(e) = api_client.post_observation(observation).await {
                            tracing::error!(error = ?e, "Failed to post observation");
                        } else {
                            tracing::info!("Observation posted successfully");
                        };
                    }
                    Err(e) => tracing::error!(error = ?e, "Failed to create observation"),
                }
            }
        });
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
        return SecretKey::from_byte_array(&byte_array).expect("Invalid secret key length");
    }

    let content = fs::read_to_string(path)
        .expect("Invalid secret key file")
        .trim()
        .to_string();
    SecretKey::from_str(&content).expect("Invalid secret key")
}

fn get_public_key(secret_key: &SecretKey) -> (PublicKey, [u8; 20]) {
    let secp = Secp256k1::new();
    let public_key = secret_key.public_key(&secp);
    let pubkey_uncompressed = public_key.serialize_uncompressed();
    let pubkey_hash: [u8; 32] = Keccak256::new_with_prefix(&pubkey_uncompressed[1..])
        .finalize()
        .into();
    let pubkey_evm: [u8; 20] = pubkey_hash[pubkey_hash.len() - 20..]
        .try_into()
        .expect("Invalid address length");
    (public_key, pubkey_evm)
}

async fn run(run_options: config::RunOptions) {
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

    let (pubkey, pubkey_evm) = get_public_key(&secret_key);
    let evm_encded_public_key = format!("0x{}", hex::encode(pubkey_evm));
    tracing::info!(
        public_key = ?pubkey,
        evm_encoded_public_key = ?evm_encded_public_key,
        "Running listener...",
    );

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

#[tokio::main]
async fn main() {
    // Initialize a Tracing Subscriber
    let fmt_builder = tracing_subscriber::fmt()
        .with_file(false)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(std::io::stderr().is_terminal());

    // Use the compact formatter if we're in a terminal, otherwise use the JSON formatter.
    if std::io::stderr().is_terminal() {
        tracing::subscriber::set_global_default(fmt_builder.compact().finish())
            .expect("Failed to set global default subscriber");
    } else {
        tracing::subscriber::set_global_default(fmt_builder.json().finish())
            .expect("Failed to set global default subscriber");
    }

    // Parse the command line arguments with StructOpt, will exit automatically on `--help` or
    // with invalid arguments.
    match Command::parse() {
        Command::Run(run_options) => run(run_options).await,
        Command::GenerateKey(opts) => {
            let secp = Secp256k1::new();
            let mut rng = OsRng;

            // Generate keypair (secret + public key)
            let (secret_key, _) = secp.generate_keypair(&mut rng);
            fs::write(opts.output_path.clone(), secret_key.secret_bytes())
                .expect("Failed to write secret key to file");
            let (pubkey, pubkey_evm) = get_public_key(&secret_key);
            tracing::info!("Generated secret key at: {}", opts.output_path);
            tracing::info!("Public key: {}", pubkey);
            tracing::info!("EVM encoded public key: 0x{}", hex::encode(pubkey_evm));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine;
    use borsh::BorshSerialize;
    use solana_account_decoder::{UiAccount, UiAccountData};

    use crate::posted_message::MessageData;

    fn get_wormhole_pid() -> Pubkey {
        Pubkey::from_str("H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU").unwrap()
    }

    fn get_accumulator_address() -> Pubkey {
        Pubkey::from_str("G9LV2mp9ua1znRAfYwZz5cPiJMAbo1T6mbjdQsDZuMJg").unwrap()
    }

    fn get_payload() -> Vec<u8> {
        vec![
            65, 85, 87, 86, 0, 0, 0, 0, 0, 13, 74, 15, 90, 0, 0, 39, 16, 172, 145, 156, 108, 253,
            178, 4, 138, 51, 74, 110, 116, 101, 139, 121, 254, 152, 165, 24, 190,
        ]
    }

    fn get_unreliable_data() -> PostedMessageUnreliableData {
        PostedMessageUnreliableData {
            message: MessageData {
                submission_time: 1749732585,
                nonce: 0,
                emitter_chain: Chain::Pythnet.into(),
                emitter_address: [
                    225, 1, 250, 237, 172, 88, 81, 227, 43, 155, 35, 181, 249, 65, 26, 140, 43,
                    172, 74, 174, 62, 212, 221, 123, 129, 29, 209, 167, 46, 164, 170, 113,
                ],
                sequence: 138184361,
                consistency_level: 1,
                payload: get_payload(),
                vaa_version: 1,
                vaa_time: 0,
                vaa_signature_account: [0; 32],
            },
        }
    }

    fn get_update(unreliable_data: PostedMessageUnreliableData) -> Response<RpcKeyedAccount> {
        let message = unreliable_data.try_to_vec().unwrap();
        let message = base64::engine::general_purpose::STANDARD.encode(&message);
        Response {
            context: solana_client::rpc_response::RpcResponseContext {
                slot: 123456,
                api_version: None,
            },
            value: RpcKeyedAccount {
                pubkey: find_message_pda(&get_wormhole_pid(), 123456).to_string(),
                account: UiAccount {
                    lamports: 0,
                    data: UiAccountData::Binary(message, UiAccountEncoding::Base64),
                    owner: get_accumulator_address().to_string(),
                    executable: false,
                    rent_epoch: 0,
                    space: None,
                },
            },
        }
    }

    #[test]
    fn test_find_message_pda() {
        assert_eq!(
            find_message_pda(&get_wormhole_pid(), 123456).to_string(),
            "Ed9gRoBySmUjSVFxovuhTk6AcFkv9uE8EovvshtHWLNT"
        );
    }

    #[test]
    fn test_get_body() {
        let unreliable_data = get_unreliable_data();
        let body = message_data_to_body(&unreliable_data);
        assert_eq!(body.timestamp, unreliable_data.submission_time);
        assert_eq!(body.nonce, unreliable_data.nonce);
        assert_eq!(body.emitter_chain, Chain::Pythnet);
        assert_eq!(
            body.emitter_address,
            Address(unreliable_data.emitter_address)
        );
        assert_eq!(body.sequence, unreliable_data.sequence);
        assert_eq!(body.payload, RawMessage::new(get_payload().as_slice()));
    }

    #[test]
    fn test_decode_and_verify_update() {
        let expected_unreliable_data = get_unreliable_data();
        let update = get_update(expected_unreliable_data.clone());
        let result =
            decode_and_verify_update(&get_wormhole_pid(), &get_accumulator_address(), update);

        assert!(result.is_ok());
        let unreliable_data = result.unwrap();

        assert_eq!(
            expected_unreliable_data.consistency_level,
            unreliable_data.consistency_level
        );
        assert_eq!(
            expected_unreliable_data.emitter_chain,
            unreliable_data.emitter_chain
        );
        assert_eq!(
            expected_unreliable_data.emitter_address,
            unreliable_data.emitter_address
        );
        assert_eq!(expected_unreliable_data.sequence, unreliable_data.sequence);
        assert_eq!(
            expected_unreliable_data.submission_time,
            unreliable_data.submission_time
        );
        assert_eq!(expected_unreliable_data.nonce, unreliable_data.nonce);
        assert_eq!(expected_unreliable_data.payload, unreliable_data.payload);
        assert_eq!(
            expected_unreliable_data.vaa_version,
            unreliable_data.vaa_version
        );
        assert_eq!(expected_unreliable_data.vaa_time, unreliable_data.vaa_time);
        assert_eq!(
            expected_unreliable_data.vaa_signature_account,
            unreliable_data.vaa_signature_account
        );
    }

    #[test]
    fn test_decode_and_verify_update_invalid_pda() {
        let mut update = get_update(get_unreliable_data());
        update.context.slot += 1;
        let result =
            decode_and_verify_update(&get_wormhole_pid(), &get_accumulator_address(), update);
        assert_eq!(result.unwrap_err().to_string(), INVALID_PDA_MESSAGE);
    }

    #[test]
    fn test_decode_and_verify_update_failed_decode() {
        let mut update = get_update(get_unreliable_data());
        update.value.account.data =
            UiAccountData::Binary("invalid_base64".to_string(), UiAccountEncoding::Base64);
        let result =
            decode_and_verify_update(&get_wormhole_pid(), &get_accumulator_address(), update);
        assert_eq!(result.unwrap_err().to_string(), FAILED_TO_DECODE);
    }

    #[test]
    fn test_decode_and_verify_update_invalid_unreliable_data() {
        let mut update = get_update(get_unreliable_data());
        let message = base64::engine::general_purpose::STANDARD.encode(vec![4, 1, 2, 3, 4]);
        update.value.account.data = UiAccountData::Binary(message, UiAccountEncoding::Base64);
        let result =
            decode_and_verify_update(&get_wormhole_pid(), &get_accumulator_address(), update);
        let error_message = format!(
            "{}: {}",
            INVALID_UNRELIABLE_DATA_FORMAT,
            "Magic mismatch. Expected [109, 115, 117] but got [4, 1, 2]"
        );
        assert_eq!(result.unwrap_err().to_string(), error_message);
    }

    #[test]
    fn test_decode_and_verify_update_invalid_emitter_chain() {
        let mut unreliable_data = get_unreliable_data();
        unreliable_data.emitter_chain = Chain::Solana.into();
        let result = decode_and_verify_update(
            &get_wormhole_pid(),
            &get_accumulator_address(),
            get_update(unreliable_data),
        );
        assert_eq!(result.unwrap_err().to_string(), INVALID_EMITTER_CHAIN);
    }

    #[test]
    fn test_decode_and_verify_update_invalid_emitter_address() {
        let mut unreliable_data = get_unreliable_data();
        unreliable_data.emitter_address = Pubkey::new_unique().to_bytes();
        let result = decode_and_verify_update(
            &get_wormhole_pid(),
            &get_accumulator_address(),
            get_update(unreliable_data),
        );
        assert_eq!(result.unwrap_err().to_string(), INVALID_ACCUMULATOR_ADDRESS);
    }
}
