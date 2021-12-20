use {
    clap::{crate_description, crate_name, crate_version, App, Arg},
    solana_clap_utils::{
        input_validators::{is_url_or_moniker, is_valid_signer, normalize_to_url_if_moniker},
        keypair::DefaultSigner,
    },
    solana_client::{rpc_client::RpcClient},
    solana_remote_wallet::remote_wallet::RemoteWalletManager,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        instruction::Instruction,
        message::Message,
        signature::{Keypair, Signer},
        system_instruction,
        transaction::Transaction,
    },
    std::{process::exit, sync::Arc},
    curve25519_dalek_onchain::{
        id,
        instruction,
    },
};

struct Config {
    commitment_config: CommitmentConfig,
    default_signer: Box<dyn Signer>,
    json_rpc_url: String,
    verbose: bool,
    instruction_buffer: Option<String>,
    input_buffer: Option<String>,
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
    instruction_buffer: &Option<String>,
    input_buffer: &Option<String>,
    compute_buffer: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {

    let input_buffer = if let Some(kp) = input_buffer {
        Keypair::from_base58_string(kp)
    } else {
        Keypair::new()
    };

    let instruction_buffer = if let Some(kp) = instruction_buffer {
        Keypair::from_base58_string(kp)
    } else {
        Keypair::new()
    };

    let compute_buffer = if let Some(kp) = compute_buffer {
        Keypair::from_base58_string(kp)
    } else {
        Keypair::new()
    };

    println!("Instruction buffer keypair: {}", instruction_buffer.to_base58_string());
    println!("Input buffer keypair: {}", input_buffer.to_base58_string());
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

    assert_eq!(scalars.len(), points.len());

    let dsl = instruction::transer_proof_instructions(vec![scalars.len()]);

    let instruction_buffer_len = (instruction::HEADER_SIZE + dsl.len()) as usize;
    let input_buffer_len = instruction::HEADER_SIZE + scalars.len() * 32 * 2 + 128;

    // pick a large number... at least > 8 * 128 * scalars.len()
    let compute_buffer_len = instruction::HEADER_SIZE + 10000;

    let buffers = [
        (&instruction_buffer, instruction_buffer_len, "instruction", instruction::Curve25519Instruction::InitializeInstructionBuffer),
        (&input_buffer, input_buffer_len, "input", instruction::Curve25519Instruction::InitializeInputBuffer),
        (&compute_buffer, compute_buffer_len, "compute", instruction::Curve25519Instruction::InitializeComputeBuffer),
    ];

    for (buffer, buffer_len, name, instruction_type) in buffers {
        let buffer_data = rpc_client.get_account_data(&buffer.pubkey());
        if let Ok(data) = buffer_data {
            assert!(data.len() >= buffer_len);
        } else {
            send(
                rpc_client,
                &format!("Creating {} buffer", name),
                &[
                    system_instruction::create_account(
                        &payer.pubkey(),
                        &buffer.pubkey(),
                        rpc_client.get_minimum_balance_for_rent_exemption(buffer_len)?,
                        buffer_len as u64,
                        &id(),
                    ),
                    instruction::initialize_buffer(
                        buffer.pubkey(),
                        instruction_type,
                    ),
                ],
                &[payer, buffer],
            )?;
        }
    }

    let mut instructions = vec![];

    // write the instructions
    let mut dsl_idx = 0;
    let dsl_chunk = 800;
    while dsl_idx < dsl.len() {
        instructions.push(
            instruction::write_bytes(
                instruction_buffer.pubkey(),
                (instruction::HEADER_SIZE + dsl_idx) as u32,
                &dsl[dsl_idx..(dsl_idx+dsl_chunk).min(dsl.len())],
            )
        );
        send(
            rpc_client,
            &format!("Writing instructions"),
            instructions.as_slice(),
            &[payer],
        )?;
        instructions.clear();
        dsl_idx += dsl_chunk;
    }

    // write the points
    let mut points_as_bytes = vec![];
    for i in 0..points.len(){
        points_as_bytes.extend_from_slice(&points[i]);
    }
    instructions.push(
        instruction::write_bytes(
            input_buffer.pubkey(),
            instruction::HEADER_SIZE as u32,
            points_as_bytes.as_slice()
        ),
    );
    send(
        rpc_client,
        &format!("Writing mul points"),
        instructions.as_slice(),
        &[payer],
    )?;
    instructions.clear();


    // write the scalars
    let mut scalars_as_bytes = vec![];
    for i in 0..scalars.len() {
        scalars_as_bytes.extend_from_slice(&scalars[i].bytes);
    }
    instructions.push(
        instruction::write_bytes(
            input_buffer.pubkey(),
            (instruction::HEADER_SIZE + scalars.len() * 32) as u32,
            scalars_as_bytes.as_slice()
        ),
    );

    // write identity for results
    use curve25519_dalek_onchain::traits::Identity;
    instructions.push(
        instruction::write_bytes(
            input_buffer.pubkey(),
            (instruction::HEADER_SIZE + scalars.len() * 32 * 2) as u32,
            &curve25519_dalek_onchain::edwards::EdwardsPoint::identity().to_bytes(),
        ),
    );

    send(
        rpc_client,
        &format!("Writing mul scalars and ident"),
        instructions.as_slice(),
        &[payer],
    )?;
    instructions.clear();


    let instructions_per_tx = 32;
    let num_cranks = dsl.len() / instruction::INSTRUCTION_SIZE;
    for _i in 0..num_cranks {
        instructions.push(
            instruction::crank_compute(
                instruction_buffer.pubkey(),
                input_buffer.pubkey(),
                compute_buffer.pubkey(),
            ),
        );
    }
    let mut current = 0;
    while current < num_cranks {
        instructions.clear();
        let iter_start = current;
        for j in 0..instructions_per_tx {
            if current >= num_cranks {
                break;
            }
            instructions.push(
                instruction::crank_compute(
                    instruction_buffer.pubkey(),
                    input_buffer.pubkey(),
                    compute_buffer.pubkey(),
                ),
            );
            current += 1;
        }
        send(
            rpc_client,
            &format!(
                "Iterations {}..{}",
                iter_start,
                current,
            ),
            instructions.as_slice(),
            &[payer],
        )?;
    }

    let compute_buffer_data = rpc_client.get_account_data(&compute_buffer.pubkey())?;
    let mul_result_bytes = &compute_buffer_data[32..128+32];
    let mul_result = curve25519_dalek_onchain::edwards::EdwardsPoint::from_bytes(
        mul_result_bytes
    );

    println!("Data {:x?}", mul_result_bytes);

    use curve25519_dalek_onchain::traits::IsIdentity;
    assert!(curve25519_dalek_onchain::ristretto::RistrettoPoint(mul_result).is_identity());

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
            Arg::with_name("instruction_buffer")
                .long("instruction_buffer")
                .value_name("INSTRUCTION_BUFFER")
                .takes_value(true)
                .global(true)
                .help("Instruction buffer keypair to use (or create)"),
        )
        .arg(
            Arg::with_name("input_buffer")
                .long("input_buffer")
                .value_name("INPUT_BUFFER")
                .takes_value(true)
                .global(true)
                .help("Input buffer keypair to use (or create)"),
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
            instruction_buffer: matches.value_of("instruction_buffer").map(|s| s.into()),
            input_buffer: matches.value_of("input_buffer").map(|s| s.into()),
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
        &config.instruction_buffer,
        &config.input_buffer,
        &config.compute_buffer,
    ).unwrap_or_else(|err| {
        eprintln!("error: {}", err);
        exit(1);
    });

    Ok(())
}
