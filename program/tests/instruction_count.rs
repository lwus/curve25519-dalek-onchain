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
        field::FieldElement,
    },
};

#[tokio::test]
async fn test_pow22501_p1() {
    let mut pc = ProgramTest::new("curve25519_dalek_onchain", id(), processor!(process_instruction));

    // Arbitrary number for now
    pc.set_bpf_compute_max_units(350_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let rent = banks_client.get_rent().await;
    let rent = rent.unwrap();

    let compute_buffer = Keypair::new();
    let buffer_len = 960; // Arbitrary
    let buffer_minimum_balance_for_rent_exemption = rent
        .minimum_balance(buffer_len);

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
                &FieldElement::minus_one().to_bytes()
            ),
            instruction::pow22501_p1(
                compute_buffer.pubkey(),
                0,
            ),
            instruction::pow22501_p2(
                compute_buffer.pubkey(),
                32,
            ),
        ],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &compute_buffer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}
