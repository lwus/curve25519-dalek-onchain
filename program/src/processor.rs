use crate::{
    instruction::*,
    field::*,
};

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use std::{
    convert::TryInto,
    mem,
};

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    match decode_instruction_type(input)? {
        Curve25519Instruction::WriteBytes => {
            let offset = u32::from_le_bytes(
                input[1..5].try_into().map_err(|_| ProgramError::InvalidArgument)?
            );
            process_write_bytes(
                accounts,
                offset,
                &input[5..],
            )
        }
        // reads 32 bytes and writes 96
        Curve25519Instruction::Pow22501P1 => {
            let offset = u32::from_le_bytes(
                input[1..5].try_into().map_err(|_| ProgramError::InvalidArgument)?
            );
            process_pow22501_p1(
                accounts,
                offset,
            )
        }
        // reads 64 bytes, skips 32, and writes 32
        Curve25519Instruction::Pow22501P2 => {
            let offset = u32::from_le_bytes(
                input[1..5].try_into().map_err(|_| ProgramError::InvalidArgument)?
            );
            process_pow22501_p2(
                accounts,
                offset,
            )
        }
    }
}

fn process_write_bytes(
    accounts: &[AccountInfo],
    offset: u32,
    bytes: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let compute_buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let offset = offset as usize;
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    compute_buffer_data[offset..offset+bytes.len()].copy_from_slice(bytes);

    Ok(())
}

fn process_pow22501_p1(
    accounts: &[AccountInfo],
    offset: u32,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let compute_buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let element = FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    );

    let (t17, t13, t3) = FieldElement::pow22001(&element);

    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&t17.to_bytes());

    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&t13.to_bytes());

    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&t3.to_bytes());

    Ok(())
}

fn process_pow22501_p2(
    accounts: &[AccountInfo],
    offset: u32,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let compute_buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let t17 = FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    );

    let offset = offset + 32;
    let t13 = FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    );

    let t19 = FieldElement::pow22501(&t17, &t13);

    let offset = offset + 32; // skip t3
    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&t19.to_bytes());

    Ok(())
}
