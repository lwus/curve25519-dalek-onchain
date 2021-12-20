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
    let buffer_minimum_balance_for_rent_exemption = rent
        .minimum_balance(buffer_len);

    assert_eq!(scalars.len(), points.len());

    let mut instructions = vec![
        system_instruction::create_account(
            &payer.pubkey(),
            &compute_buffer.pubkey(),
            buffer_minimum_balance_for_rent_exemption,
            buffer_len as u64,
            &id(),
        ),
    ];

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

    for i in (0..64).rev() {
        instructions.push(
            instruction::multiscalar_mul(
                compute_buffer.pubkey(),
                i, // start
                i+1, // end
                num_inputs as u8,
                tables_end, // scalars_offset
                tables_start, // tables_offset
                0,  // result_offset
            ),
        );
    }

    let mut transaction = Transaction::new_with_payer(
        instructions.as_slice(),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &compute_buffer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    let account = banks_client.get_account(compute_buffer.pubkey()).await.unwrap().unwrap();
    let mul_result = curve25519_dalek_onchain::edwards::EdwardsPoint::from_bytes(
        &account.data[..128]
    );

    println!("Data {:x?}", &account.data[..128]);

    use curve25519_dalek_onchain::traits::IsIdentity;
    println!("Result {:?}", curve25519_dalek_onchain::ristretto::RistrettoPoint(mul_result).is_identity());
}
