use {
    crate::{
        config::Command,
        signer::{GuardianKey, Signer, GUARDIAN_KEY_ARMORED_BLOCK, STANDARD_ARMOR_LINE_HEADER},
    },
    api_client::{ApiClient, Observation},
    borsh::BorshDeserialize,
    clap::Parser,
    posted_message::PostedMessageUnreliableData,
    prost::Message,
    secp256k1::{rand::rngs::OsRng, Secp256k1},
    sequoia_openpgp::armor::{Kind, Writer},
    serde_wormhole::RawMessage,
    solana_account_decoder::UiAccountEncoding,
    solana_client::{
        nonblocking::pubsub_client::PubsubClient,
        pubsub_client::PubsubClientError,
        rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
        rpc_filter::{Memcmp, RpcFilterType},
        rpc_response::{Response, RpcKeyedAccount},
    },
    solana_sdk::pubkey::Pubkey,
    std::{
        fs,
        io::{IsTerminal, Write},
        str::FromStr,
        time::Duration,
    },
    tokio::time::sleep,
    tokio_stream::StreamExt,
    wormhole_sdk::{vaa::Body, Address, Chain},
};

mod api_client;
mod config;
mod posted_message;
mod signer;

struct RunListenerInput<T: Signer> {
    ws_url: String,
    signer: T,
    wormhole_pid: Pubkey,
    accumulator_address: Pubkey,
    api_clients: Vec<ApiClient>,
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

async fn run_listener<T: Signer + 'static>(
    input: RunListenerInput<T>,
) -> Result<(), PubsubClientError> {
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

        input.api_clients.iter().for_each(|api_client| {
            tokio::spawn({
                let (unreliable_data, api_client, signer) = (
                    unreliable_data.clone(),
                    api_client.clone(),
                    input.signer.clone()
                );
                async move {
                    let body = message_data_to_body(&unreliable_data);
                    match Observation::try_new(body.clone(), signer.clone()) {
                        Ok(observation) => {
                            if let Err(e) = api_client.post_observation(observation).await {
                                tracing::error!(url = api_client.get_base_url().to_string(), error = ?e, "Failed to post observation");
                            } else {
                                tracing::info!(url = api_client.get_base_url().to_string(), "Observation posted successfully");
                            };
                        }
                        Err(e) => tracing::error!(error = ?e, "Failed to create observation"),
                    }
                }
            });
        });
    }

    tokio::spawn(async move { unsubscribe().await });

    Err(PubsubClientError::ConnectionClosed(
        "Stream ended".to_string(),
    ))
}

async fn run(run_options: config::RunOptions) {
    let signer = signer::FileSigner::try_new(run_options.clone()).expect("Failed to create signer");
    let client = PubsubClient::new(&run_options.pythnet_url)
        .await
        .expect("Invalid WebSocket URL");
    drop(client); // Drop the client to avoid holding the connection open
    let accumulator_address = Pubkey::from_str("G9LV2mp9ua1znRAfYwZz5cPiJMAbo1T6mbjdQsDZuMJg")
        .expect("Invalid accumulator address");
    let wormhole_pid =
        Pubkey::from_str(&run_options.wormhole_pid).expect("Invalid Wormhole program ID");
    let api_clients: Vec<ApiClient> = run_options
        .server_urls
        .into_iter()
        .map(|server_url| {
            ApiClient::try_new(server_url, None).expect("Failed to create API client")
        })
        .collect();

    let (pubkey, pubkey_evm) = signer.get_public_key().expect("Failed to get public key");
    let evm_encded_public_key = format!("0x{}", hex::encode(pubkey_evm));
    tracing::info!(
        public_key = ?pubkey,
        evm_encoded_public_key = ?evm_encded_public_key,
        "Running listener...",
    );

    loop {
        if let Err(e) = run_listener(RunListenerInput {
            ws_url: run_options.pythnet_url.clone(),
            signer: signer.clone(),
            wormhole_pid,
            accumulator_address,
            api_clients: api_clients.clone(),
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
            let signer = signer::FileSigner { secret_key };
            let (pubkey, pubkey_evm) = signer.get_public_key().expect("Failed to get public key");

            let guardian_key = GuardianKey {
                data: secret_key.secret_bytes().to_vec(),
                unsafe_deterministic_key: false,
            };
            let mut writer = Writer::with_headers(
                Vec::new(),
                Kind::SecretKey,
                vec![("PublicKey", format!("0x{}", hex::encode(pubkey_evm)))],
            )
            .expect("Failed to create writer");
            writer
                .write_all(guardian_key.encode_to_vec().as_slice())
                .expect("Failed to write GuardianKey to writer");
            let buffer = writer.finalize().expect("Failed to finalize writer");
            let armored_string =
                String::from_utf8(buffer).expect("Failed to convert buffer to string");
            let armored_string =
                armored_string.replace(STANDARD_ARMOR_LINE_HEADER, GUARDIAN_KEY_ARMORED_BLOCK);

            fs::write(&opts.output_path, armored_string)
                .expect("Failed to write GuardianKey to file");

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
    use secp256k1::SecretKey;
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

    #[test]
    fn test_parse_and_verify_proto_guardian_key() {
        // The content below is generated by keygen script at:
        // https://github.com/wormhole-foundation/wormhole/blob/main/node/cmd/guardiand/keygen.go
        let content = "-----BEGIN WORMHOLE GUARDIAN PRIVATE KEY-----
            PublicKey: 0x30e41be3f10d3ac813f91e49e189bbb948d030be

            CiDy8xJ7/1QMhEH5l2P1hoWO80DJlirWK2GBzXcgPoGAjw==
            =FQTN
            -----END WORMHOLE GUARDIAN PRIVATE KEY-----
        "
        .to_string();
        let guardian_key = crate::signer::FileSigner::parse_and_verify_proto_guardian_key(
            content,
            config::Mode::Production,
        )
        .expect("Failed to parse and verify guardian key");
        assert!(!guardian_key.unsafe_deterministic_key);
        let secret_key = SecretKey::from_slice(&guardian_key.data)
            .expect("Failed to create SecretKey from bytes");
        let signer = signer::FileSigner { secret_key };
        assert_eq!(
            hex::encode(secret_key.secret_bytes()),
            "f2f3127bff540c8441f99763f586858ef340c9962ad62b6181cd77203e81808f",
        );
        assert_eq!(
            hex::encode(signer.get_public_key().expect("Failed to get public key").1),
            "30e41be3f10d3ac813f91e49e189bbb948d030be",
        );
    }
}
