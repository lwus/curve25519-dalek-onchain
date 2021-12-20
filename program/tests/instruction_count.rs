#![cfg(feature = "test-bpf")]

use {
    solana_program::pubkey::Pubkey,
    solana_program_test::*,
    solana_sdk::{
        signer::keypair::Keypair,
        signature::Signer,
        system_instruction,
        transaction::Transaction,
    },
    curve25519_dalek_onchain::{
        id,
        instruction,
        processor::process_instruction,
    },
};

#[tokio::test]
async fn test_pow22501_p1() {
    let pc = ProgramTest::new("curve25519_dalek_onchain", id(), processor!(process_instruction));

    // pc.set_bpf_compute_max_units(350_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let rent = banks_client.get_rent().await;
    let rent = rent.unwrap();

    let compute_buffer = Keypair::new();
    let input_buffer = Keypair::new();
    let instruction_buffer = Keypair::new();

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
        neg_element_bytes,
        element_bytes,
        neg_element_bytes,
        element_bytes,
        neg_element_bytes,
        element_bytes,
    ];

    assert_eq!(scalars.len(), points.len());

    let dsl = instruction::transer_proof_instructions(vec![scalars.len()]);

    let instruction_buffer_len = (instruction::HEADER_SIZE + dsl.len()) as usize;
    let input_buffer_len = instruction::HEADER_SIZE + scalars.len() * 32 * 2 + 128;

    // pick a large number... at least > 8 * 128 * scalars.len()
    let compute_buffer_len = instruction::HEADER_SIZE + 10000;

    let mut instructions = vec![
        system_instruction::create_account(
            &payer.pubkey(),
            &instruction_buffer.pubkey(),
            rent.minimum_balance(instruction_buffer_len),
            instruction_buffer_len as u64,
            &id(),
        ),
        system_instruction::create_account(
            &payer.pubkey(),
            &input_buffer.pubkey(),
            rent.minimum_balance(input_buffer_len),
            input_buffer_len as u64,
            &id(),
        ),
        system_instruction::create_account(
            &payer.pubkey(),
            &compute_buffer.pubkey(),
            rent.minimum_balance(compute_buffer_len),
            compute_buffer_len as u64,
            &id(),
        ),
        instruction::initialize_buffer(
            instruction_buffer.pubkey(),
            instruction::Curve25519Instruction::InitializeInstructionBuffer,
        ),
        instruction::initialize_buffer(
            input_buffer.pubkey(),
            instruction::Curve25519Instruction::InitializeInputBuffer,
        ),
        instruction::initialize_buffer(
            compute_buffer.pubkey(),
            instruction::Curve25519Instruction::InitializeComputeBuffer,
        ),
    ];

    // write the instructions
    let mut dsl_idx = 0;
    while dsl_idx < dsl.len() {
        instructions.push(
            instruction::write_bytes(
                instruction_buffer.pubkey(),
                (instruction::HEADER_SIZE + dsl_idx) as u32,
                &dsl[dsl_idx..(dsl_idx+1000).min(dsl.len())],
            )
        );
        dsl_idx += 1000;
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

    let mut transaction = Transaction::new_with_payer(
        instructions.as_slice(),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &instruction_buffer, &input_buffer, &compute_buffer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();


    instructions.clear();
    // crank baby
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

    let mut transaction = Transaction::new_with_payer(
        instructions.as_slice(),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    let account = banks_client.get_account(compute_buffer.pubkey()).await.unwrap().unwrap();
    let mul_result_bytes = &account.data[32..128+32];
    let mul_result = curve25519_dalek_onchain::edwards::EdwardsPoint::from_bytes(
        mul_result_bytes
    );

    println!("Data {:x?}", mul_result_bytes);

    use curve25519_dalek_onchain::traits::IsIdentity;
    println!("Result {:?}", curve25519_dalek_onchain::ristretto::RistrettoPoint(mul_result).is_identity());
}
