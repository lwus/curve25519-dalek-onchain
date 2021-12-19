use {
    clap::{crate_description, crate_name, crate_version, App, Arg},
    solana_clap_utils::{
        input_validators::{is_url_or_moniker, is_valid_signer, normalize_to_url_if_moniker},
        keypair::DefaultSigner,
    },
    solana_client::{client_error, rpc_client::RpcClient},
    solana_remote_wallet::remote_wallet::RemoteWalletManager,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        instruction::Instruction,
        message::Message,
        program_error::ProgramError,
        program_pack::Pack,
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        system_instruction,
        transaction::Transaction,
    },
    std::{convert::TryInto, process::exit, sync::Arc},
    curve25519_dalek_onchain::{
        id,
        instruction,
        processor::process_instruction,
        field::FieldElement,
    },
};

struct Config {
    commitment_config: CommitmentConfig,
    default_signer: Box<dyn Signer>,
    json_rpc_url: String,
    verbose: bool,
    compute_buffer: Option<String>,
}

fn send(
    rpc_client: &RpcClient,
    msg: &str,
    instructions: &[Instruction],
    signers: &[&dyn Signer],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("==> {}", msg);
    let mut transaction =
        Transaction::new_unsigned(Message::new(instructions, Some(&signers[0].pubkey())));

    let (recent_blockhash, _fee_calculator) = rpc_client
        .get_recent_blockhash()
        .map_err(|err| format!("error: unable to get recent blockhash: {}", err))?;

    transaction
        .try_sign(&signers.to_vec(), recent_blockhash)
        .map_err(|err| format!("error: failed to sign transaction: {}", err))?;

    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .map_err(|err| format!("error: send transaction: {}", err))?;
    println!("Signature: {}", signature);
    Ok(())
}

fn process_demo(
    rpc_client: &RpcClient,
    payer: &dyn Signer,
    compute_buffer: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {

    let compute_buffer = if let Some(kp) = compute_buffer {
        Keypair::from_base58_string(kp)
    } else {
        Keypair::new()
    };

    println!("Compute buffer keypair: {}", compute_buffer.to_base58_string());

    let buffer_len = 3200; // Arbitrary
    let buffer_minimum_balance_for_rent_exemption = rpc_client
        .get_minimum_balance_for_rent_exemption(buffer_len)?;

    let mut compute_buffer_data = rpc_client.get_account_data(&compute_buffer.pubkey());
    if compute_buffer_data.is_err() {
        send(
            rpc_client,
            &format!("Creating compute buffer"),
            &[
                system_instruction::create_account(
                    &payer.pubkey(),
                    &compute_buffer.pubkey(),
                    buffer_minimum_balance_for_rent_exemption,
                    buffer_len as u64,
                    &id(),
                ),
            ],
            &[payer, &compute_buffer],
        )?;
    }

    let element_bytes = [
        202 , 148 , 27  , 77  , 122 , 101 , 116 , 31  ,
        215 , 41  , 243 , 54  , 4   , 27  , 77  , 165 ,
        16  , 215 , 42  , 27  , 197 , 222 , 243 , 67  ,
        76  , 183 , 142 , 167 , 62  , 36  , 241 , 1   ,
    ];

    send(
        rpc_client,
        &format!("Computing x^(2^250-1)"),
        &[
            instruction::write_bytes(
                compute_buffer.pubkey(),
                0,
                &FieldElement::one().to_bytes()
            ),
            instruction::write_bytes(
                compute_buffer.pubkey(),
                0,
                &element_bytes,
            ),
            instruction::run_compute_routine(
                instruction::Curve25519Instruction::DecompressInit,
                compute_buffer.pubkey(),
                0,
            ),
            instruction::run_compute_routine(
                instruction::Curve25519Instruction::InvSqrtInit,
                compute_buffer.pubkey(),
                32,
            ),
            instruction::run_compute_routine(
                instruction::Curve25519Instruction::Pow22501P1,
                compute_buffer.pubkey(),
                64,
            ),
            instruction::run_compute_routine(
                instruction::Curve25519Instruction::Pow22501P2,
                compute_buffer.pubkey(),
                96,
            ),
            instruction::run_compute_routine(
                instruction::Curve25519Instruction::InvSqrtFini,
                compute_buffer.pubkey(),
                32,
            ),
            instruction::run_compute_routine(
                instruction::Curve25519Instruction::DecompressFini,
                compute_buffer.pubkey(),
                0,
            ),
            instruction::build_lookup_table(
                compute_buffer.pubkey(),
                // compute_buffer.pubkey(),
                32 * 8,
                32 * 12,
            ),
        ],
        &[payer],
    )?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .arg({
            let arg = Arg::with_name("config_file")
                .short("C")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::with_name("keypair")
                .long("keypair")
                .value_name("KEYPAIR")
                .validator(is_valid_signer)
                .takes_value(true)
                .global(true)
                .help("Filepath or URL to a keypair [default: client keypair]"),
        )
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .takes_value(false)
                .global(true)
                .help("Show additional information"),
        )
        .arg(
            Arg::with_name("json_rpc_url")
                .short("u")
                .long("url")
                .value_name("URL")
                .takes_value(true)
                .global(true)
                .validator(is_url_or_moniker)
                .help("JSON RPC URL for the cluster [default: value from configuration file]"),
        )
        .arg(
            Arg::with_name("compute_buffer")
                .long("compute_buffer")
                .value_name("COMPUTE_BUFFER")
                .takes_value(true)
                .global(true)
                .help("Compute buffer keypair to use (or create)"),
        )
        .get_matches();

    let mut wallet_manager: Option<Arc<RemoteWalletManager>> = None;

    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };

        let default_signer = DefaultSigner::new(
            "keypair",
            matches
                .value_of(&"keypair")
                .map(|s| s.to_string())
                .unwrap_or_else(|| cli_config.keypair_path.clone()),
        );

        Config {
            json_rpc_url: normalize_to_url_if_moniker(
                matches
                    .value_of("json_rpc_url")
                    .unwrap_or(&cli_config.json_rpc_url)
                    .to_string(),
            ),
            default_signer: default_signer
                .signer_from_path(&matches, &mut wallet_manager)
                .unwrap_or_else(|err| {
                    eprintln!("error: {}", err);
                    exit(1);
                }),
            verbose: matches.is_present("verbose"),
            commitment_config: CommitmentConfig::confirmed(),
            compute_buffer: matches.value_of("compute_buffer").map(|s| s.into()),
        }
    };
    solana_logger::setup_with_default("solana=info");

    if config.verbose {
        println!("JSON RPC URL: {}", config.json_rpc_url);
    }
    let rpc_client =
        RpcClient::new_with_commitment(config.json_rpc_url.clone(), config.commitment_config);

    process_demo(
        &rpc_client,
        config.default_signer.as_ref(),
        &config.compute_buffer,
    ).unwrap_or_else(|err| {
        eprintln!("error: {}", err);
        exit(1);
    });

    Ok(())
}
