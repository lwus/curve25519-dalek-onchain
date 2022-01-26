#![cfg(feature = "test-bpf")]

use {
    solana_program::pubkey::Pubkey,
    solana_program_test::*,
    solana_sdk::{
        compute_budget::ComputeBudgetInstruction,
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
async fn test_multiscalar_mul() {
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

    use curve25519_dalek_onchain::scalar::Scalar;
    let scalars = vec![
        -Scalar::one(),
        Scalar::one(),
        Scalar::one(),
        -Scalar::one(),
    ];

    let points = vec![
        element_bytes,
        element_bytes,
        neg_element_bytes,
        neg_element_bytes,
    ];

    assert_eq!(scalars.len(), points.len());

    let proof_groups = vec![2, 2];
    let dsl = instruction::transer_proof_instructions(proof_groups.clone());

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
            payer.pubkey(),
            instruction::Key::InstructionBufferV1,
            vec![],
        ),
        instruction::initialize_buffer(
            input_buffer.pubkey(),
            payer.pubkey(),
            instruction::Key::InputBufferV1,
            vec![],
        ),
        instruction::initialize_buffer(
            compute_buffer.pubkey(),
            payer.pubkey(),
            instruction::Key::ComputeBufferV1,
            vec![instruction_buffer.pubkey(), input_buffer.pubkey()],
        ),
    ];

    // write the instructions
    let mut dsl_idx = 0;
    let dsl_chunk = 800;
    loop {
        let end = (dsl_idx+dsl_chunk).min(dsl.len());
        let done = end == dsl.len();
        instructions.push(
            instruction::write_bytes(
                instruction_buffer.pubkey(),
                payer.pubkey(),
                (instruction::HEADER_SIZE + dsl_idx) as u32,
                done,
                &dsl[dsl_idx..end],
            )
        );
        if done {
            break;
        } else {
            dsl_idx = end;
        }
    }

    instructions.extend_from_slice(
        instruction::write_input_buffer(
            input_buffer.pubkey(),
            payer.pubkey(),
            points.as_slice(),
            scalars.as_slice(),
        ).as_slice(),
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

    let mut buffer_idx = instruction::HEADER_SIZE;
    for _i in 0..proof_groups.len() {
        use curve25519_dalek::traits::IsIdentity;
        let mul_result_bytes = &account.data[buffer_idx..128+buffer_idx];
        let mul_result = curve25519_dalek::edwards::EdwardsPoint::from_bytes(
            mul_result_bytes
        );

        println!("Data {:x?}", mul_result_bytes);

        assert!(curve25519_dalek::ristretto::RistrettoPoint(mul_result).is_identity());
        buffer_idx += 128;
    }


    let mut transaction = Transaction::new_with_payer(
        &[
            instruction::close_buffer(
                instruction_buffer.pubkey(),
                payer.pubkey(),
            ),
            instruction::close_buffer(
                input_buffer.pubkey(),
                payer.pubkey(),
            ),
            instruction::close_buffer(
                compute_buffer.pubkey(),
                payer.pubkey(),
            ),
        ],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}

#[tokio::test]
async fn test_elligator() {
    let pc = ProgramTest::new("curve25519_dalek_onchain", id(), processor!(process_instruction));

    // pc.set_bpf_compute_max_units(350_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let rent = banks_client.get_rent().await;
    let rent = rent.unwrap();

    let compute_buffer = Keypair::new();
    let input_buffer = Keypair::new();
    let instruction_buffer = Keypair::new();

    // TODO
    let hash_bytes = [
        0, 1, 2, 3, 4, 5, 6, 7,
        0, 1, 2, 3, 4, 5, 6, 7,
        0, 1, 2, 3, 4, 5, 6, 7,
        0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let dsl = instruction::elligator_to_curve_instructions();

    let instruction_buffer_len = (instruction::HEADER_SIZE + dsl.len()) as usize;
    let input_buffer_len = instruction::HEADER_SIZE + 32;

    // scratch + result space
    let compute_buffer_len = instruction::HEADER_SIZE + 1000;

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
            payer.pubkey(),
            instruction::Key::InstructionBufferV1,
            vec![],
        ),
        instruction::initialize_buffer(
            input_buffer.pubkey(),
            payer.pubkey(),
            instruction::Key::InputBufferV1,
            vec![],
        ),
        instruction::initialize_buffer(
            compute_buffer.pubkey(),
            payer.pubkey(),
            instruction::Key::ComputeBufferV1,
            vec![instruction_buffer.pubkey(), input_buffer.pubkey()],
        ),
    ];

    // write the instructions
    let mut dsl_idx = 0;
    let dsl_chunk = 800;
    loop {
        let end = (dsl_idx+dsl_chunk).min(dsl.len());
        let done = end == dsl.len();
        instructions.push(
            instruction::write_bytes(
                instruction_buffer.pubkey(),
                payer.pubkey(),
                (instruction::HEADER_SIZE + dsl_idx) as u32,
                done,
                &dsl[dsl_idx..end],
            )
        );
        if done {
            break;
        } else {
            dsl_idx = end;
        }
    }

    instructions.push(
        instruction::write_bytes(
            input_buffer.pubkey(),
            payer.pubkey(),
            instruction::HEADER_SIZE as u32,
            true,
            &hash_bytes,
        ),
    );

    let mut transaction = Transaction::new_with_payer(
        instructions.as_slice(),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &instruction_buffer, &input_buffer, &compute_buffer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();


    instructions.clear();

    instructions.push(
        ComputeBudgetInstruction::request_units(500_000),
    );
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

    let buffer_idx = instruction::HEADER_SIZE + 32 * 4 + 32 * 6;
    let elligator_result_bytes = &account.data[buffer_idx..128+buffer_idx];
    let elligator_result = curve25519_dalek::edwards::EdwardsPoint::from_bytes(
        elligator_result_bytes
    );

    println!("F {:?}", &curve25519_dalek::field::FieldElement::from_bytes(&hash_bytes));
    println!("Elligator {:x?}", elligator_result_bytes);

    assert_eq!(
        elligator_result,
        curve25519_dalek::ristretto::RistrettoPoint::elligator_ristretto_flavor(
            &curve25519_dalek::field::FieldElement::from_bytes(&hash_bytes),
        ).0,
    );
}
