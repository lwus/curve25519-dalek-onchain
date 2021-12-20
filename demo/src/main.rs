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

    let element_bytes = [
        202 , 148 , 27  , 77  , 122 , 101 , 116 , 31  ,
        215 , 41  , 243 , 54  , 4   , 27  , 77  , 165 ,
        16  , 215 , 42  , 27  , 197 , 222 , 243 , 67  ,
        76  , 183 , 142 , 167 , 62  , 36  , 241 , 1   ,
    ];

    let neg_element_bytes = [
        56  , 121 , 86  , 54  , 1   , 207 , 49  , 169 ,
        17  , 26  , 157 , 55  , 224 , 194 , 217 , 15  ,
        52  , 240 , 214 , 108 , 251 , 96  , 252 , 129 ,
        242 , 190 , 61  , 18  , 88  , 179 , 89  , 40  ,
    ];

    let scalars = vec![
        curve25519_dalek_onchain::scalar::Scalar::one(),
        curve25519_dalek_onchain::scalar::Scalar::one(),
        curve25519_dalek_onchain::scalar::Scalar::one(),
        curve25519_dalek_onchain::scalar::Scalar::one(),
        curve25519_dalek_onchain::scalar::Scalar::one(),
        curve25519_dalek_onchain::scalar::Scalar::one(),
    ];

    let points = vec![
        element_bytes,
        neg_element_bytes,
        element_bytes,
        neg_element_bytes,
        element_bytes,
        neg_element_bytes,
    ];

    let num_inputs = scalars.len() as u32;
    let tables_start = 32 * 12;

    let buffer_len = (tables_start + num_inputs * (128 * 8 + 32)) as usize;
    let buffer_minimum_balance_for_rent_exemption = rpc_client
        .get_minimum_balance_for_rent_exemption(buffer_len)?;

    assert_eq!(scalars.len(), points.len());

    let mut compute_buffer_data = rpc_client.get_account_data(&compute_buffer.pubkey());
    if let Ok(data) = compute_buffer_data {
        assert!(data.len() >= buffer_len);
    } else {
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

    let mut instructions = vec![];

    // write the point lookup tables
    for i in 0..num_inputs {
        instructions.extend_from_slice(
            instruction::prep_multiscalar_input(
                compute_buffer.pubkey(),
                &points[i as usize],
                i as u8,
                tables_start,
            ).as_slice(),
        );
    }

    send(
        rpc_client,
        &format!("Prepping mul input points"),
        instructions.as_slice(),
        &[payer],
    )?;
    instructions.clear();


    // write the scalars
    let tables_end = tables_start + num_inputs * 128 * 8;
    let mut scalars_as_bytes = vec![];
    for i in 0..num_inputs {
        scalars_as_bytes.extend_from_slice(&scalars[i as usize].bytes);
    }
    instructions.push(
        instruction::write_bytes(
            compute_buffer.pubkey(),
            tables_end,
            scalars_as_bytes.as_slice(),
        ),
    );

    // write the result point initial state
    use curve25519_dalek_onchain::traits::Identity;
    instructions.push(
        instruction::write_bytes(
            compute_buffer.pubkey(),
            0,
            &curve25519_dalek_onchain::edwards::EdwardsPoint::identity().to_bytes(),
        ),
    );

    send(
        rpc_client,
        &format!("Prepping mul scalars"),
        instructions.as_slice(),
        &[payer],
    )?;


    let instructions_per_tx = 32;
    let transactions = 64 / instructions_per_tx;
    for i in (0..transactions).rev() {
        instructions.clear();
        for j in (0..instructions_per_tx).rev() {
            let iter = i * instructions_per_tx + j;
            instructions.push(
                instruction::multiscalar_mul(
                    compute_buffer.pubkey(),
                    iter, // start
                    iter+1, // end
                    num_inputs as u8,
                    tables_end, // scalars_offset
                    tables_start, // tables_offset
                    0,  // result_offset
                ),
            );
        }
        send(
            rpc_client,
            &format!(
                "Iterations {}..{}",
                i * instructions_per_tx,
                (i + 1) * instructions_per_tx - 1
            ),
            instructions.as_slice(),
            &[payer],
        )?;
    }

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
