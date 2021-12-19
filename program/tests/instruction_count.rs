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

    {
        let s = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&element_bytes);
        if let Some(p) = s.decompress() {
            println!("X {:x?}", p.0.X.to_bytes());
            println!("Y {:x?}", p.0.Y.to_bytes());
            println!("Z {:x?}", p.0.Z.to_bytes());
            println!("T {:x?}", p.0.T.to_bytes());
        }
    }

    let mut transaction = Transaction::new_with_payer(
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &compute_buffer.pubkey(),
                buffer_minimum_balance_for_rent_exemption,
                buffer_len as u64,
                &id(),
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
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &compute_buffer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}
