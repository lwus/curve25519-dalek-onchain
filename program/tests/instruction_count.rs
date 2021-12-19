#![cfg(feature = "test-bpf")]

use {
    solana_program::pubkey::Pubkey,
    solana_program_test::*,
    solana_sdk::{
        signer::keypair::Keypair,
        signature::Signer,
        system_instruction,
        transaction::Transaction,
        instruction::AccountMeta,
    },
    curve25519_dalek_onchain::{
        id,
        instruction,
        processor::process_instruction,
        field::FieldElement,
    },
};

#[tokio::test]
async fn test_pow22501_p1() {
    let mut pc = ProgramTest::new("curve25519_dalek_onchain", id(), processor!(process_instruction));

    // pc.set_bpf_compute_max_units(350_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let rent = banks_client.get_rent().await;
    let rent = rent.unwrap();

    let compute_buffer = Keypair::new();
    let buffer_len = 3200; // Arbitrary
    let buffer_minimum_balance_for_rent_exemption = rent
        .minimum_balance(buffer_len);

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

    {
        use curve25519_dalek::traits::IsIdentity;
        use curve25519_dalek::traits::MultiscalarMul;
        let s = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&element_bytes);
        let r = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&neg_element_bytes);
        if let Some(p) = s.decompress() {
            if let Some(q) = r.decompress() {
                println!("p {:?}", p);
                println!("q {:?}", q);
                let v = curve25519_dalek::ristretto::RistrettoPoint::multiscalar_mul(
                    vec![
                        curve25519_dalek::scalar::Scalar::one(),
                        curve25519_dalek::scalar::Scalar::one(),
                    ],
                    vec![
                        p,
                        q,
                    ]
                );
                println!("{:?}", v);
            }
        }
    }

    let mut instructions = vec![
        system_instruction::create_account(
            &payer.pubkey(),
            &compute_buffer.pubkey(),
            buffer_minimum_balance_for_rent_exemption,
            buffer_len as u64,
            &id(),
        ),
    ];

    instructions.extend_from_slice(
        instruction::prep_multiscalar_input(
            compute_buffer.pubkey(),
            &element_bytes,
            0,
        ).as_slice(),
    );

    instructions.extend_from_slice(
        instruction::prep_multiscalar_input(
            compute_buffer.pubkey(),
            &neg_element_bytes,
            1,
        ).as_slice(),
    );

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
                0,  // point offset
                vec![ // scalars
                    curve25519_dalek_onchain::scalar::Scalar::one(),
                    curve25519_dalek_onchain::scalar::Scalar::one(),
                ],
                vec![ // table offsets
                    32 * 12 + 128 * 8 * 0,
                    32 * 12 + 128 * 8 * 1,
                ],
                i, // start
                i+1, // end
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
    println!("{} {:?}", account.data.len(), &account.data[..128]);
}
