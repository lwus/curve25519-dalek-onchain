#![allow(non_snake_case)]

use crate::{
    instruction::*,
    field::*,
    ristretto::*,
    window::*,
    edwards::*,
};

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use borsh::{BorshDeserialize, BorshSerialize};
use num_traits::{FromPrimitive};
use std::{
    borrow::Borrow,
    convert::TryInto,
};

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let bytes_as_u32 = |bytes: &[u8]| -> Result<u32, ProgramError> {
        bytes
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| ProgramError::InvalidArgument)
    };
    let offset = || -> Result<u32, ProgramError> {
        bytes_as_u32(&input[1..5])
    };
    match decode_instruction_type(input)? {
        Curve25519Instruction::InitializeInstructionBuffer => {
            msg!("InitializeInstructionBuffer");
            process_initialize_buffer(
                accounts,
                |authority| InstructionHeader {
                    key: Key::InstructionBufferV1,
                    authority,
                    finalized: false,
                },
            )
        }
        Curve25519Instruction::InitializeInputBuffer => {
            msg!("InitializeInputBuffer");
            process_initialize_buffer(
                accounts,
                |authority| InputHeader {
                    key: Key::InputBufferV1,
                    authority,
                    finalized: false,
                },
            )
        }
        Curve25519Instruction::InitializeComputeBuffer => {
            msg!("InitializeComputeBuffer");
            process_initialize_buffer(
                accounts,
                |authority| ComputeHeader {
                    key: Key::ComputeBufferV1,
                    instruction_num: 0,
                    authority,
                    instruction_buffer: Pubkey::new(&input[1..33]),
                    input_buffer: Pubkey::new(&input[33..65]),
                },
            )
        }
        Curve25519Instruction::CloseBuffer => {
            msg!("CloseBuffer");
            process_close_buffer(
                accounts,
            )
        }
        Curve25519Instruction::WriteBytes => {
            msg!("WriteBytes");
            process_write_bytes(
                accounts,
                offset()?,
                input[5] == 0x00, // set to 0x00 for finalization
                &input[6..],
            )
        }
        Curve25519Instruction::CrankCompute => {
            msg!("CrankCompute");
            process_dsl_instruction(
                accounts,
            )
        }
        Curve25519Instruction::Noop => {
            msg!("Noop");
            Ok(())
        }
    }
}

fn process_dsl_instruction(
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let instruction_buffer_info = next_account_info(account_info_iter)?;
    // kind of sucks that this always needs to be passed in...
    let input_buffer_info = next_account_info(account_info_iter)?;
    let compute_buffer_info = next_account_info(account_info_iter)?;

    if *instruction_buffer_info.owner != crate::ID || instruction_buffer_info.is_writable {
        msg!("Bad instruction buffer {} vs {}", instruction_buffer_info.owner, crate::ID);
        return Err(ProgramError::InvalidArgument);
    }
    if *input_buffer_info.owner != crate::ID {
        msg!("Bad input buffer");
        return Err(ProgramError::InvalidArgument);
    }
    if *compute_buffer_info.owner != crate::ID {
        msg!("Bad compute buffer");
        return Err(ProgramError::InvalidArgument);
    }

    // deserialize headers and verify
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;
    let mut compute_header = {
        let mut compute_buffer_ptr: &[u8] = *compute_buffer_data;
        ComputeHeader::deserialize(&mut compute_buffer_ptr)?
    };
    if compute_header.key != Key::ComputeBufferV1 {
        msg!("Invalid compute buffer type");
        return Err(ProgramError::InvalidArgument);
    }
    if compute_header.instruction_buffer != *instruction_buffer_info.key {
        msg!("Mismatched instruction buffer {} vs {}", compute_header.instruction_buffer, *instruction_buffer_info.key);
        return Err(ProgramError::InvalidArgument);
    }
    if compute_header.input_buffer != *input_buffer_info.key {
        msg!("Mismatched input buffer");
        return Err(ProgramError::InvalidArgument);
    }

    let instruction_buffer_data = instruction_buffer_info.try_borrow_data()?;
    let instruction_header = {
        let mut instruction_buffer_ptr: &[u8] = *instruction_buffer_data;
        InstructionHeader::deserialize(&mut instruction_buffer_ptr)?
    };
    if instruction_header.key != Key::InstructionBufferV1 {
        msg!("Invalid instruction buffer type");
        return Err(ProgramError::InvalidArgument);
    }
    if !instruction_header.finalized {
        msg!("Instruction buffer not finalized");
        return Err(ProgramError::InvalidArgument);
    }


    // find instruction and increment counter
    let instruction_offset = HEADER_SIZE + INSTRUCTION_SIZE * compute_header.instruction_num as usize;
    let mut instruction_data = &instruction_buffer_data[
        instruction_offset..instruction_offset+INSTRUCTION_SIZE
    ];

    compute_header.instruction_num += 1;
    // TODO: directly doing serialize like
    //   compute_header.serialize(&mut *compute_buffer_data)?;
    // seems to do weird things...
    let compute_header_bytes = compute_header.try_to_vec()?;
    compute_buffer_data[..compute_header_bytes.len()].copy_from_slice(
        compute_header_bytes.as_slice());
    drop(compute_buffer_data);

    match DSLInstruction::deserialize(&mut instruction_data)? {
        DSLInstruction::CopyInput(offsets) => {
            msg!("CopyInput");
            process_copy_input(
                input_buffer_info,
                compute_buffer_info,
                &offsets,
            )
        }
        DSLInstruction::WriteEdwardsIdentity(RunDecompressData { offset }) => {
            msg!("WriteEdwardsIdentity");
            process_write_edwards_identity(
                compute_buffer_info,
                offset,
            )
        }

        // [
        //   x,
        //   pow_input,         // init
        //   t17, t13, t3,      // p1
        //   t19,               // pow_output
        //   invsqrt_output,    // fini
        //   decompress_output_start
        //  ]
        // reads 32 bytes and writes 32
        DSLInstruction::InvSqrtInit(RunDecompressData{ offset }) => {
            msg!("InvSqrtInit");
            process_invsqrt_init(
                compute_buffer_info,
                offset,
            )
        }
        // reads 32 bytes and writes 96
        DSLInstruction::Pow22501P1(RunDecompressData{ offset })=> {
            msg!("Pow22501P1");
            process_pow22501_p1(
                compute_buffer_info,
                offset,
            )
        }
        // reads 64 bytes, skips 32, and writes 32
        DSLInstruction::Pow22501P2(RunDecompressData{ offset }) => {
            msg!("Pow22501P2");
            process_pow22501_p2(
                compute_buffer_info,
                offset,
            )
        }
        // reads 32 bytes, skips 96, reads 32, and writes 32
        DSLInstruction::InvSqrtFini(RunDecompressData{ offset }) => {
            msg!("InvSqrtFini");
            process_invsqrt_fini(
                compute_buffer_info,
                offset,
            )
        }

        DSLInstruction::DecompressInit(RunDecompressData{ offset }) => {
            msg!("DecompressInit");
            process_decompress_init(
                compute_buffer_info,
                offset,
            )
        }
        DSLInstruction::DecompressFini(RunDecompressData{ offset }) => {
            msg!("DecompressFini");
            process_decompress_fini(
                compute_buffer_info,
                offset,
            )
        }

        DSLInstruction::DecompressEdwards(RunSplitComputeData{ offset, step }) => {
            msg!("DecompressEdwards {}", step);
            process_decompress_edwards(
                compute_buffer_info,
                offset,
                step,
            )
        }
        DSLInstruction::CompressEdwards(RunSplitComputeData{ offset, step }) => {
            msg!("CompressEdwards {}", step);
            process_compress_edwards(
                compute_buffer_info,
                offset,
                step,
            )
        }
        DSLInstruction::Elligator(RunSplitComputeData{ offset, step }) => {
            msg!("Elligator {}", step);
            process_elligator(
                compute_buffer_info,
                offset,
                step,
            )
        }
        DSLInstruction::MontgomeryElligator(RunSplitComputeData{ offset, step }) => {
            msg!("MontgomeryElligator {}", step);
            process_montgomery_elligator(
                compute_buffer_info,
                offset,
                step,
            )
        }

        DSLInstruction::MontgomeryToEdwards(MontgomeryToEdwardsData{ offset, sign_offset, step }) => {
            msg!("MontgomeryToEdwards {}", step);
            process_montgomery_to_edwards(
                compute_buffer_info,
                offset,
                sign_offset,
                step,
            )
        }
        // decompress edwards after...
        DSLInstruction::MulByCofactor(BuildLookupTableData{ point_offset, table_offset }) => {
            msg!("MulByCofactor");
            process_mul_by_cofactor(
                compute_buffer_info,
                point_offset,
                table_offset,
            )
        }

        DSLInstruction::BuildLookupTable(data) => {
            msg!("BuildLookupTable");
            process_build_lookup_table(
                compute_buffer_info,
                &data,
            )
        }
        DSLInstruction::MultiscalarMul(data) => {
            msg!("MultiscalarMul");
            process_multiscalar_mul(
                compute_buffer_info,
                &data,
            )
        }

        DSLInstruction::DecompressWithWitness(RunDecompressData{ offset }) => {
            msg!("DecompressWithWitness");
            process_decompress_with_witness(
                compute_buffer_info,
                offset,
            )
        }
    }
}

fn process_initialize_buffer<F, T: BorshSerialize>(
    accounts: &[AccountInfo],
    header_fn: F,
) -> ProgramResult
where
    F: FnOnce(Pubkey) -> T,
{
    let account_info_iter = &mut accounts.iter();
    let buffer_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    if !authority_info.is_signer {
        msg!("Authority is not a signer");
        return Err(ProgramError::InvalidArgument);
    }

    use solana_program::sysvar::Sysvar;
    let rent = solana_program::rent::Rent::get()?;
    if !rent.is_exempt(buffer_info.lamports(), buffer_info.data_len()) {
        msg!("Buffer is not rent exempt");
        return Err(ProgramError::InvalidArgument);
    }

    let mut buffer_data = buffer_info.try_borrow_mut_data()?;

    if buffer_data[0] != Key::Uninitialized as u8 {
        msg!("Buffer already initialized");
        return Err(ProgramError::InvalidArgument);
    }

    // TODO: does this write correctly?
    header_fn(*authority_info.key).serialize(&mut *buffer_data)?;

    Ok(())
}

fn process_close_buffer(
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let buffer_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    if !authority_info.is_signer {
        msg!("Authority is not a signer");
        return Err(ProgramError::InvalidArgument);
    }

    let buffer_data = buffer_info.try_borrow_data()?;
    let mut buffer_ptr: &[u8] = *buffer_data;

    match Key::from_u8(buffer_data[0]).ok_or(ProgramError::InvalidArgument)? {
        Key::InputBufferV1 => {
            let header = InputHeader::deserialize(&mut buffer_ptr)?;
            if header.authority != *authority_info.key {
                msg!("Invalid input buffer authority");
                return Err(ProgramError::InvalidArgument);
            }
        }
        Key::ComputeBufferV1 => {
            let header = ComputeHeader::deserialize(&mut buffer_ptr)?;
            if header.authority != *authority_info.key {
                msg!("Invalid compute buffer authority");
                return Err(ProgramError::InvalidArgument);
            }
        }
        Key::InstructionBufferV1 => {
            let header = InstructionHeader::deserialize(&mut buffer_ptr)?;
            if header.authority != *authority_info.key {
                msg!("Invalid instruction buffer authority");
                return Err(ProgramError::InvalidArgument);
            }
        }
        Key::Uninitialized => {
            msg!("Buffer not initialized");
            return Err(ProgramError::InvalidArgument);
        }
    }

    let dest_starting_lamports = authority_info.lamports();
    **authority_info.lamports.borrow_mut() = dest_starting_lamports
        .checked_add(buffer_info.lamports())
        .ok_or(ProgramError::InvalidArgument)?;

    **buffer_info.lamports.borrow_mut() = 0;

    Ok(())
}

fn process_write_bytes(
    accounts: &[AccountInfo],
    offset: u32,
    finalized: bool,
    bytes: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let buffer_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    if !authority_info.is_signer {
        msg!("Authority is not a signer");
        return Err(ProgramError::InvalidArgument);
    }

    let offset = offset as usize;
    let mut buffer_data = buffer_info.try_borrow_mut_data()?;

    match Key::from_u8(buffer_data[0]).ok_or(ProgramError::InvalidArgument)? {
        Key::InputBufferV1 => {
            let mut header = {
                let mut buffer_ptr: &[u8] = buffer_data.borrow();
                InputHeader::deserialize(&mut buffer_ptr)?
            };
            if header.authority != *authority_info.key {
                msg!("Invalid input buffer authority");
                return Err(ProgramError::InvalidArgument);
            }

            if header.finalized {
                msg!("Input buffer already finalized");
                return Err(ProgramError::InvalidArgument);
            }

            header.finalized = finalized;

            use std::borrow::BorrowMut;
            let mut buffer_ptr: &mut [u8] = buffer_data.borrow_mut();
            header.serialize(&mut buffer_ptr)?;
        }
        Key::InstructionBufferV1 => {
            let mut header = {
                let mut buffer_ptr: &[u8] = buffer_data.borrow();
                InstructionHeader::deserialize(&mut buffer_ptr)?
            };
            if header.authority != *authority_info.key {
                msg!("Invalid instruction buffer authority");
                return Err(ProgramError::InvalidArgument);
            }

            if header.finalized {
                msg!("Input buffer already finalized");
                return Err(ProgramError::InvalidArgument);
            }

            header.finalized = finalized;

            use std::borrow::BorrowMut;
            let mut buffer_ptr: &mut [u8] = buffer_data.borrow_mut();
            header.serialize(&mut buffer_ptr)?;
        }
        _ => {
            msg!("Invalid buffer type");
            return Err(ProgramError::InvalidArgument);
        }
    };

    if offset < HEADER_SIZE {
        msg!("Cannot write to header");
        return Err(ProgramError::InvalidArgument);
    }

    buffer_data[offset..offset+bytes.len()].copy_from_slice(bytes);

    Ok(())
}

fn process_copy_input(
    input_buffer_info: &AccountInfo,
    compute_buffer_info: &AccountInfo,
    offsets: &CopyInputData,
) -> ProgramResult {
    let input_buffer_data = input_buffer_info.try_borrow_data()?;

    let mut input_buffer_ptr: &[u8] = input_buffer_data.borrow();
    let input_header = InputHeader::deserialize(&mut input_buffer_ptr)?;

    if input_header.key != Key::InputBufferV1 {
        msg!("Invalid buffer type");
        return Err(ProgramError::InvalidArgument);
    }
    if !input_header.finalized {
        msg!("Input buffer not finalized");
        return Err(ProgramError::InvalidArgument);
    }

    let input_offset = offsets.input_offset as usize;
    if input_offset < HEADER_SIZE {
        msg!("Cannot copy from header");
        return Err(ProgramError::InvalidArgument);
    }

    let compute_offset = offsets.compute_offset as usize;
    if compute_offset < HEADER_SIZE {
        msg!("Cannot copy to header");
        return Err(ProgramError::InvalidArgument);
    }

    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;
    let copy_bytes = offsets.bytes as usize;
    compute_buffer_data[
        compute_offset..compute_offset+copy_bytes
    ].copy_from_slice(&input_buffer_data[
        input_offset..input_offset+copy_bytes
    ]);

    Ok(())
}

fn process_write_edwards_identity(
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
    let offset = offset as usize;
    if offset < HEADER_SIZE {
        msg!("Cannot copy to header");
        return Err(ProgramError::InvalidArgument);
    }

    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    use crate::traits::Identity;
    compute_buffer_data[
        offset..offset+128
    ].copy_from_slice(&EdwardsPoint::identity().to_bytes());

    Ok(())
}

fn process_invsqrt_init(
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;

    let u = FieldElement::one();
    let v = read_field_element(&compute_buffer_data, offset)?;

    let offset = offset + 32;
    compute_buffer_data[offset..offset+32].copy_from_slice(
        &FieldElement::sqrt_ratio_i_pow_p58_input(&u, &v).to_bytes(),
    );

    Ok(())
}

fn process_invsqrt_fini(
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;

    let u = FieldElement::one();
    let v = read_field_element(&compute_buffer_data, offset)?;
    let pow_p22501_output = read_field_element(&compute_buffer_data, offset + 32 * 5)?;

    let (ok, r) = FieldElement::sqrt_ratio_i_pow_p58_output(&u, &v, &pow_p22501_output);

    if ok.unwrap_u8() == 0u8 {
        return Err(ProgramError::InvalidArgument);
    }

    let offset = offset + 32 * 6;
    compute_buffer_data[offset..offset+32].copy_from_slice(&r.to_bytes());

    Ok(())
}

fn process_pow22501_p1(
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let element = read_field_element(&compute_buffer_data, offset)?;

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
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let t17 = read_field_element(&compute_buffer_data, offset)?;
    let t13 = read_field_element(&compute_buffer_data, offset + 32)?;

    let t19 = FieldElement::pow22501(&t17, &t13);

    let offset = offset + 32 * 3; // skip t3
    compute_buffer_data[offset..offset+32].copy_from_slice(&t19.to_bytes());

    Ok(())
}

fn process_decompress_init(
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
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
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let point = CompressedRistretto::from_slice(
        &compute_buffer_data[offset..offset+32]
    );

    let offset = offset + 32 * 7;
    let element = read_field_element(&compute_buffer_data, offset)?;

    let res = point.decompress_fini(&element).ok_or(ProgramError::InvalidArgument)?;

    let offset = offset + 32;
    compute_buffer_data[offset..offset+128].copy_from_slice(
        &res.0.to_bytes());

    Ok(())
}

fn process_decompress_edwards(
    compute_buffer_info: &AccountInfo,
    offset: u32,
    step: u8,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let compressed_bytes = &compute_buffer_data[offset..offset+32];
    let Y = read_field_element(&compute_buffer_data, offset)?;
    let Z = FieldElement::one();
    let YY = Y.square();
    let u = &YY - &Z;                            // u =  y??-1
    let v = &(&YY * &constants::EDWARDS_D) + &Z; // v = dy??+1

    if step == 0 {
        let offset = offset + 32;
        compute_buffer_data[offset..offset+32].copy_from_slice(
            &FieldElement::sqrt_ratio_i_pow_p58_input(&u, &v).to_bytes(),
        );
        return Ok(());
    }

    let pow_p22501_output = read_field_element(&compute_buffer_data, offset + 32 * 5)?;
    let (is_valid_y_coord, mut X) = FieldElement::sqrt_ratio_i_pow_p58_output(&u, &v, &pow_p22501_output);

    if is_valid_y_coord.unwrap_u8() != 1u8 {
        msg!("Invalid y coordinate");
        return Err(ProgramError::InvalidArgument);
    }

    use subtle::{Choice, ConditionallyNegatable};
    let compressed_sign_bit = Choice::from(compressed_bytes[31] >> 7);
    X.conditional_negate(compressed_sign_bit);

    let res = EdwardsPoint{ X, Y, Z, T: &X * &Y };

    let offset = offset + 32 * 6;
    compute_buffer_data[offset..offset+128].copy_from_slice(
        &res.to_bytes());

    Ok(())
}

fn process_compress_edwards(
    compute_buffer_info: &AccountInfo,
    offset: u32,
    step: u8,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let point = EdwardsPoint::from_bytes(
        &compute_buffer_data[offset..offset+128]
    );

    if step == 0 {
        // could be probably skip this if adding some kind of result offset to every
        // instruction...
        let offset = offset + 32 * 4;
        compute_buffer_data[offset..offset+32].copy_from_slice(
            &point.Z.to_bytes()
        );
        return Ok(());
    }

    // invert
    let t3 = read_field_element(&compute_buffer_data, offset + 32 * 7)?;
    let t19 = read_field_element(&compute_buffer_data, offset + 32 * 8)?;
    let recip = &t19.pow2k(5) * &t3;

    let x = &point.X * &recip;
    let y = &point.Y * &recip;
    let mut s: [u8; 32];

    s = y.to_bytes();
    s[31] ^= x.is_negative().unwrap_u8() << 7;

    let offset = offset + 32 * 9;
    compute_buffer_data[offset..offset+32].copy_from_slice(&s);

    Ok(())
}

fn process_elligator(
compute_buffer_info: &AccountInfo,
    offset: u32,
    step: u8,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;

    let i = &constants::SQRT_M1;
    let d = &constants::EDWARDS_D;
    let d_minus_one_sq = &constants::EDWARDS_D_MINUS_ONE_SQUARED;
    let one_minus_d_sq = &constants::ONE_MINUS_EDWARDS_D_SQUARED;
    let mut c = constants::MINUS_ONE;

    let one = FieldElement::one();

    let r_0 = read_field_element(&compute_buffer_data, offset)?;
    let r = i * &r_0.square();
    let N_s = &(&r + &one) * &one_minus_d_sq;
    let D = &(&c - &(d * &r)) * &(&r + d);

    if step == 0 {
        let offset = offset + 32;
        compute_buffer_data[offset..offset+32].copy_from_slice(
            &FieldElement::sqrt_ratio_i_pow_p58_input(&N_s, &D).to_bytes(),
        );
        return Ok(());
    }

    let pow_p22501_output = read_field_element(&compute_buffer_data, offset + 32 * 5)?;
    let (Ns_D_is_sq, mut s) = FieldElement::sqrt_ratio_i_pow_p58_output(&N_s, &D, &pow_p22501_output);

    use subtle::{ConditionallySelectable, ConditionallyNegatable};
    let mut s_prime = &s * &r_0;
    let s_prime_is_pos = !s_prime.is_negative();
    s_prime.conditional_negate(s_prime_is_pos);

    s.conditional_assign(&s_prime, !Ns_D_is_sq);
    c.conditional_assign(&r, !Ns_D_is_sq);

    let N_t = &(&(&c * &(&r - &one)) * &d_minus_one_sq) - &D;
    let s_sq = s.square();

    // The conversion from W_i is exactly the conversion from P1xP1.
    let res = RistrettoPoint(CompletedPoint{
        X: &(&s + &s) * &D,
        Z: &N_t * &constants::SQRT_AD_MINUS_ONE,
        Y: &FieldElement::one() - &s_sq,
        T: &FieldElement::one() + &s_sq,
    }.to_extended());

    let offset = offset + 32 * 6;
    compute_buffer_data[offset..offset+128].copy_from_slice(
        &res.0.to_bytes());

    Ok(())
}

fn process_montgomery_elligator(
    compute_buffer_info: &AccountInfo,
    offset: u32,
    step: u8,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;

    let one = FieldElement::one();

    if step == 0 {
        let r_0 = read_field_element(&compute_buffer_data, offset)?;
        let d_1 = &one + &r_0.square2(); /* 2r^2 */

        let offset = offset + 32;
        compute_buffer_data[offset..offset+32].copy_from_slice(
            &d_1.to_bytes()
        );
        return Ok(());
    }

    // invert
    let t3 = read_field_element(&compute_buffer_data, offset + 32 * 4)?;
    let t19 = read_field_element(&compute_buffer_data, offset + 32 * 5)?;
    let d_1_inv = &t19.pow2k(5) * &t3;

    let d = &constants::MONTGOMERY_A_NEG * &d_1_inv; /* A/(1+2r^2) */

    let d_sq = &d.square();
    let au = &constants::MONTGOMERY_A * &d;

    let inner = &(d_sq + &au) + &one;
    let eps = &d * &inner; /* eps = d^3 + Ad^2 + d */

    if step == 1 {
        let offset = offset + 32 * 6;
        compute_buffer_data[offset..offset+32].copy_from_slice(
            &FieldElement::sqrt_ratio_i_pow_p58_input(&eps, &one).to_bytes(),
        );
        return Ok(());
    }

    let pow_p22501_output = read_field_element(&compute_buffer_data, offset + 32 * 10)?;
    let (eps_is_sq, _eps) = FieldElement::sqrt_ratio_i_pow_p58_output(&eps, &one, &pow_p22501_output);

    use subtle::{ConditionallySelectable, ConditionallyNegatable};

    let zero = FieldElement::zero();
    let Atemp = FieldElement::conditional_select(&constants::MONTGOMERY_A, &zero, eps_is_sq); /* 0, or A if nonsquare*/

    let mut u = &d + &Atemp; /* d, or d+A if nonsquare */
    u.conditional_negate(!eps_is_sq); /* d, or -d-A if nonsquare */

    // write the compressed MontgomeryPoint
    let offset = offset + 32 * 11;
    compute_buffer_data[offset..offset+32].copy_from_slice(
        &u.to_bytes());

    Ok(())
}

fn process_montgomery_to_edwards(
    compute_buffer_info: &AccountInfo,
    offset: u32,
    sign_offset: u32,
    step: u8,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;

    let u = read_field_element(&compute_buffer_data, offset)?;
    if u == FieldElement::minus_one() {
        return Err(ProgramError::InvalidArgument);
    }

    let one = FieldElement::one();

    if step == 0 {
        let offset = offset + 32;
        compute_buffer_data[offset..offset+32].copy_from_slice(
            &(&u + &one).to_bytes()
        );
        return Ok(());
    }

    // invert
    let t3 = read_field_element(&compute_buffer_data, offset + 32 * 4)?;
    let t19 = read_field_element(&compute_buffer_data, offset + 32 * 5)?;
    let up1_inv = &t19.pow2k(5) * &t3;

    let y = &(&u - &one) * &up1_inv;

    let sign = (compute_buffer_data[sign_offset as usize] & 0x80) >> 7;

    let mut y_bytes = y.to_bytes();
    y_bytes[31] ^= sign << 7;

    let offset = offset + 32 * 6;
    compute_buffer_data[offset..offset+32].copy_from_slice(&y_bytes);

    Ok(())
}

fn process_mul_by_cofactor(
    compute_buffer_info: &AccountInfo,
    offset: u32,
    result_offset: u32,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let point = EdwardsPoint::from_bytes(
        &compute_buffer_data[offset..offset+128]
    );

    let result_offset = result_offset as usize;
    compute_buffer_data[result_offset..result_offset+128].copy_from_slice(
        &point.mul_by_cofactor().to_bytes()
    );

    Ok(())
}

fn process_build_lookup_table(
    compute_buffer_info: &AccountInfo,
    data: &BuildLookupTableData,
) -> ProgramResult {
    let compute_buffer_data = compute_buffer_info.try_borrow_data()?;

    let point_offset = data.point_offset as usize;
    let point = EdwardsPoint::from_bytes(
        &compute_buffer_data[point_offset..point_offset+128]
    );

    let table = LookupTable::<ProjectiveNielsPoint>::from(&point);


    drop(compute_buffer_data);
    let mut table_buffer_data = compute_buffer_info.try_borrow_mut_data()?;
    let table_offset = data.table_offset as usize;
    type LUT = LookupTable::<ProjectiveNielsPoint>;
    table_buffer_data[table_offset..table_offset + LUT::TABLE_SIZE].copy_from_slice(
        bytemuck::cast_slice::<LUT, u8>(std::slice::from_ref(&table)));

    Ok(())
}

fn process_multiscalar_mul(
    compute_buffer_info: &AccountInfo,
    data: &MultiscalarMulData,
) -> ProgramResult {
    let num_inputs = data.num_inputs as usize;
    if num_inputs > MAX_MULTISCALAR_POINTS {
        msg!("Too many points");
        return Err(ProgramError::InvalidArgument);
    }

    // deserialize lookup tables
    let compute_buffer_data = compute_buffer_info.try_borrow_data()?;
    let table_offset = u32::from(data.tables_offset) as usize;
    type LUT = LookupTable::<ProjectiveNielsPoint>;
    let lookup_tables = bytemuck::cast_slice::<u8, LUT>(
        &compute_buffer_data[table_offset..table_offset + LUT::TABLE_SIZE * num_inputs]);

    // deserialize scalars
    // TODO: just encode the radix_16 values directly?
    let scalar_offset = u32::from(data.scalars_offset) as usize;
    let packed_scalar_digits = bytemuck::cast_slice::<u8, [u8; 32]>(
        &compute_buffer_data[scalar_offset..scalar_offset + 32 * num_inputs]);

    // deserialize point computation
    let result_offset = u32::from(data.result_offset) as usize;
    let mut Q = EdwardsPoint::from_bytes(
        &compute_buffer_data[result_offset..result_offset+128]
    );

    // run compute
    for j in (data.start..data.end).rev() {
        Q = Q.mul_by_pow_2(4);
        let it = packed_scalar_digits.iter().zip(lookup_tables.iter());
        for (s_i, lookup_table_i) in it {
            // R_i = s_{i,j} * P_i
            let packed_radix = if j & 1 == 1 {
                (s_i[(j >> 1) as usize] as i8) >> 4
            } else {
                (s_i[(j >> 1) as usize] as i8) << 4 >> 4
            };
            let R_i = lookup_table_i.select(packed_radix);
            // Q = Q + R_i
            Q = (&Q + &R_i).to_extended();
        }
    }

    // serialize
    drop(compute_buffer_data);
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;
    compute_buffer_data[result_offset..result_offset+128].copy_from_slice(
        &Q.to_bytes());

    Ok(())
}

fn process_decompress_with_witness(
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
    let mut compute_buffer_data = compute_buffer_info.try_borrow_mut_data()?;

    let offset = offset as usize;
    let point = CompressedRistretto::from_slice(
        &compute_buffer_data[offset..offset+32]
    );

    let witness = read_field_element(&compute_buffer_data, offset + 32)?;

    let Iinv_sq = point.decompress_init().ok_or(ProgramError::InvalidArgument)?;
    // if !ok the witness should multiply to sqrt(-1) (aka i)
    if &Iinv_sq * &witness.square() != FieldElement::one() {
        msg!("Bad witness");
        return Err(ProgramError::InvalidArgument);
    }

    // some duplicate work in this...
    let point = point.decompress_fini(&witness).ok_or(ProgramError::InvalidArgument)?;

    let offset = offset + 32 * 2;
    compute_buffer_data[offset..offset+128].copy_from_slice(
        &point.0.to_bytes()
    );

    Ok(())
}


fn read_field_element(
    compute_buffer_data: &[u8],
    offset: usize,
) -> Result<FieldElement, ProgramError> {
    Ok(FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    ))
}
