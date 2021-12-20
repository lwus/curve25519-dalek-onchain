#![allow(non_snake_case)]

use crate::{
    instruction::*,
    field::*,
    ristretto::*,
    window::*,
    edwards::*,
    scalar,
};

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use borsh::{BorshDeserialize, BorshSerialize};
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
                InstructionHeader{ key: Key::InstructionBufferV1 },
            )
        }
        Curve25519Instruction::InitializeInputBuffer => {
            msg!("InitializeInputBuffer");
            process_initialize_buffer(
                accounts,
                InputHeader{ key: Key::InputBufferV1 },
            )
        }
        Curve25519Instruction::InitializeComputeBuffer => {
            msg!("InitializeComputeBuffer ");
            process_initialize_buffer(
                accounts,
                ComputeHeader{
                    key: Key::ComputeBufferV1,
                    instruction_num: 0,
                },
            )
        }
        Curve25519Instruction::WriteBytes => {
            msg!("WriteBytes");
            process_write_bytes(
                accounts,
                offset()?,
                &input[5..],
            )
        }
        Curve25519Instruction::CrankCompute => {
            msg!("CrankCompute");
            process_dsl_instruction(
                accounts,
            )
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

    if *instruction_buffer_info.owner != crate::ID {
        msg!("Bad instruction buffer");
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

    let instruction_buffer_data = instruction_buffer_info.try_borrow_data()?;
    let instruction_header = {
        let mut instruction_buffer_ptr: &[u8] = *instruction_buffer_data;
        InstructionHeader::deserialize(&mut instruction_buffer_ptr)?
    };
    if instruction_header.key != Key::InstructionBufferV1 {
        msg!("Invalid instruction buffer type");
        return Err(ProgramError::InvalidArgument);
    }


    // find instruction and increment counter
    let instruction_offset = HEADER_SIZE + INSTRUCTION_SIZE * compute_header.instruction_num as usize;
    let mut instruction_data = &instruction_buffer_data[
        instruction_offset..instruction_offset+INSTRUCTION_SIZE
    ];

    compute_header.instruction_num += 1;
    compute_header.serialize(&mut *compute_buffer_data)?;
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
    }
}

fn process_initialize_buffer<T: BorshSerialize>(
    accounts: &[AccountInfo],
    header: T,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let mut buffer_data = buffer_info.try_borrow_mut_data()?;

    if buffer_data[0] != Key::Uninitialized as u8 {
        msg!("Buffer already initialized");
        return Err(ProgramError::InvalidArgument);
    }

    // TODO: does this write correctly?
    header.serialize(&mut *buffer_data)?;

    Ok(())
}

fn process_write_bytes(
    accounts: &[AccountInfo],
    offset: u32,
    bytes: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let input_buffer_info = next_account_info(account_info_iter)?;
    let _system_program_info = next_account_info(account_info_iter)?;

    let offset = offset as usize;
    let mut input_buffer_data = input_buffer_info.try_borrow_mut_data()?;

    let mut input_buffer_ptr: &[u8] = input_buffer_data.borrow();
    let header = InputHeader::deserialize(&mut input_buffer_ptr)?;

    if header.key != Key::InputBufferV1 && header.key != Key::InstructionBufferV1 {
        msg!("Invalid buffer type");
        return Err(ProgramError::InvalidArgument);
    }

    if offset < HEADER_SIZE {
        msg!("Cannot write to header");
        return Err(ProgramError::InvalidArgument);
    }

    input_buffer_data[offset..offset+bytes.len()].copy_from_slice(bytes);

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

    let copy_bytes = offsets.bytes as usize;
    if copy_bytes > 128 {
        msg!("Copy slice size too large");
        return Err(ProgramError::InvalidArgument);
    }

    if input_header.key != Key::InputBufferV1 {
        msg!("Invalid buffer type");
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
    compute_buffer_data[
        compute_offset..compute_offset+copy_bytes
    ].copy_from_slice(&input_buffer_data[
        input_offset..input_offset+copy_bytes
    ]);

    Ok(())
}

fn process_invsqrt_init(
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
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
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
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
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
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
    compute_buffer_info: &AccountInfo,
    offset: u32,
) -> ProgramResult {
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
    let element = FieldElement::from_bytes(
        compute_buffer_data[offset..offset+32]
            .try_into().map_err(|_| ProgramError::InvalidArgument)?,
    );

    msg!("I {:?}", element.to_bytes());

    let res = point.decompress_fini(&element).ok_or(ProgramError::InvalidArgument)?;

    let offset = offset + 32;
    compute_buffer_data[offset..offset+128].copy_from_slice(
        &res.0.to_bytes());

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

    msg!("Read point {} {:?}", point_offset, point);

    let table = LookupTable::<ProjectiveNielsPoint>::from(&point);


    drop(compute_buffer_data);
    let mut table_buffer_data = compute_buffer_info.try_borrow_mut_data()?;
    let mut table_offset = data.table_offset as usize;
    for i in 0..table.0.len() {
        table_buffer_data[table_offset..table_offset+128].copy_from_slice(
            &table.0[i].to_bytes());
        table_offset += 128;
    }

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
    let mut lookup_tables = Vec::with_capacity(num_inputs);
    let compute_buffer_data = compute_buffer_info.try_borrow_data()?;

    let mut table_offset = u32::from(data.tables_offset) as usize;
    for _i in 0..num_inputs {
        let mut buffer: [ProjectiveNielsPoint; 8] = Default::default();
        // table_offset tracks the ProjectiveNielsPoint offset inside the loop
        for j in 0..8 {
            buffer[j] = ProjectiveNielsPoint::from_bytes(
                &compute_buffer_data[table_offset..table_offset+128]
            );
            table_offset += 128;
        }
        lookup_tables.push(LookupTable(buffer));
    }

    // deserialize scalars
    // TODO: just encode the radix_16 values directly?
    let mut scalar_offset = u32::from(data.scalars_offset) as usize;
    let mut scalar_digits_vec = Vec::with_capacity(num_inputs);
    let mut bytes = [0; 32];
    for _i in 0..num_inputs {
        bytes.copy_from_slice(&compute_buffer_data[scalar_offset..scalar_offset+32]);
        scalar_digits_vec.push(scalar::Scalar{ bytes }.to_radix_16());
        scalar_offset += 32;
    }
    let scalar_digits = zeroize::Zeroizing::new(scalar_digits_vec);

    // deserialize point computation
    let result_offset = u32::from(data.result_offset) as usize;
    let mut Q = EdwardsPoint::from_bytes(
        &compute_buffer_data[result_offset..result_offset+128]
    );

    // run compute
    for j in (data.start..data.end).rev() {
        Q = Q.mul_by_pow_2(4);
        let it = scalar_digits.iter().zip(lookup_tables.iter());
        for (s_i, lookup_table_i) in it {
            // R_i = s_{i,j} * P_i
            let R_i = lookup_table_i.select(s_i[j as usize]);
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
