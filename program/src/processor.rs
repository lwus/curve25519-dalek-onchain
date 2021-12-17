use crate::{
    instruction::*,
    field::*,
    ristretto::*,
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
    let offset = || -> Result<u32, ProgramError> {
        input[1..5]
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| ProgramError::InvalidArgument)
    };
    match decode_instruction_type(input)? {
        Curve25519Instruction::WriteBytes => {
            msg!("WriteBytes");
            process_write_bytes(
                accounts,
                offset()?,
                &input[5..],
            )
        }

        // [
        //   x,
        //   pow_input,         // init
        //   t17, t13, t3,      // p1
        //   t19,               // pow_output
        //   invsqrt_output     // fini
        //  ]
        // reads 32 bytes and writes 32
        Curve25519Instruction::InvSqrtInit => {
            msg!("InvSqrtInit");
            process_invsqrt_init(
                accounts,
                offset()?,
            )
        }
        // reads 32 bytes and writes 96
        Curve25519Instruction::Pow22501P1 => {
            msg!("Pow22501P1");
            process_pow22501_p1(
                accounts,
                offset()?,
            )
        }
        // reads 64 bytes, skips 32, and writes 32
        Curve25519Instruction::Pow22501P2 => {
            msg!("Pow22501P2");
            process_pow22501_p2(
                accounts,
                offset()?,
            )
        }
        // reads 32 bytes, skips 96, reads 32, and writes 32
        Curve25519Instruction::InvSqrtFini => {
            msg!("InvSqrtFini");
            process_invsqrt_fini(
                accounts,
                offset()?,
            )
        }

        Curve25519Instruction::DecompressInit => {
            msg!("DecompressInit");
            process_decompress_init(
                accounts,
                offset()?,
            )
        }
        Curve25519Instruction::DecompressFini => {
            msg!("DecompressFini");
            process_decompress_fini(
                accounts,
                offset()?,
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

fn process_invsqrt_init(
    accounts: &[AccountInfo],
    offset: u32,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let compute_buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;

    let u = FieldElement::one();
    let v = FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    );

    let v3 = &v.square()  * &v;
    let v7 = &v3.square() * &v;

    let pow_p22501_input = &u * &v7;

    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&pow_p22501_input.to_bytes());

    Ok(())
}

fn process_invsqrt_fini(
    accounts: &[AccountInfo],
    offset: u32,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let compute_buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;

    let u = FieldElement::one();
    let v = FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    );

    let v3 = &v.square()  * &v;
    let v7 = &v3.square() * &v;

    let pow_p22501_input = &u * &v7;

    let offset = offset + 32 * 5;
    let pow_p22501_output = FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    );

    let pow_p58_output = FieldElement::pow_p58(&pow_p22501_input, &pow_p22501_output);

    let r = &(&u * &v3) * &pow_p58_output;

    let (ok, r) = FieldElement::sqrt_ratio_i(&u, &v, &r);

    if ok.unwrap_u8() == 0u8 {
        return Err(ProgramError::InvalidArgument);
    }

    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&r.to_bytes());

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

fn process_decompress_init(
    accounts: &[AccountInfo],
    offset: u32,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let compute_buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let point = CompressedRistretto::from_slice(
        &compute_buffer_data[offset..offset+32]
    );

    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(
        &point.decompress_init().ok_or(ProgramError::InvalidArgument)?.to_bytes()
    );

    Ok(())
}

fn process_decompress_fini(
    accounts: &[AccountInfo],
    offset: u32,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let compute_buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let point = CompressedRistretto::from_slice(
        &compute_buffer_data[offset..offset+32]
    );

    let offset = offset + 32 * 7;
    let element = FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    );

    msg!("I {:?}", element.to_bytes());

    let res = point.decompress_fini(&element).ok_or(ProgramError::InvalidArgument)?;

    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&res.0.X.to_bytes());
    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&res.0.Y.to_bytes());
    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&res.0.Z.to_bytes());
    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(&res.0.T.to_bytes());

    Ok(())
}
