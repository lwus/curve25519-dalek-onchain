use {
    borsh::{BorshDeserialize, BorshSerialize},
    num_derive::{FromPrimitive, ToPrimitive},
    num_traits::{FromPrimitive},
    solana_program::{
        program_error::ProgramError,
        pubkey::Pubkey,
    },
};

#[cfg(not(target_arch = "bpf"))]
use {
    crate::{
        window::LookupTable,
        edwards::ProjectiveNielsPoint,
    },
    num_traits::ToPrimitive,
    solana_program::{
        instruction::{AccountMeta, Instruction},
    },
    std::convert::TryInto,
};

#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Curve25519Instruction {
    InitializeInstructionBuffer,
    InitializeInputBuffer,
    InitializeComputeBuffer,
    WriteBytes,
    CrankCompute,
    CloseBuffer,
    Noop,
}

// TODO: move to state
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Key {
    Uninitialized,
    InputBufferV1,
    ComputeBufferV1,
    InstructionBufferV1,
}

// All headers should be smaller than HEADER_SIZE
// TODO: split up since ComputeHeader is the largest by far...
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct ComputeHeader {
    pub key: Key,
    pub instruction_num: u32,
    pub authority: Pubkey,
    pub instruction_buffer: Pubkey,
    pub input_buffer: Pubkey,
}
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct InputHeader {
    pub key: Key,
    pub authority: Pubkey,
    pub finalized: bool,
}
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct InstructionHeader {
    pub key: Key,
    pub authority: Pubkey,
    pub finalized: bool,
}

pub const HEADER_SIZE: usize = 128;
pub const INSTRUCTION_SIZE: usize = 16;


#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(u8)]
pub enum DSLInstruction {
    CopyInput(CopyInputData),

    DecompressInit(RunDecompressData),
    InvSqrtInit(RunDecompressData),
    Pow22501P1(RunDecompressData),
    Pow22501P2(RunDecompressData),
    InvSqrtFini(RunDecompressData),
    DecompressFini(RunDecompressData),

    BuildLookupTable(BuildLookupTableData),
    MultiscalarMul(MultiscalarMulData),

    ElligatorInit(RunDecompressData),
    ElligatorFini(RunDecompressData),
}

// fits under the compute limits for deserialization + one iteration + serialization
pub const MAX_MULTISCALAR_POINTS: usize = 6;

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct CopyInputData { // 32 bytes at a time.. TODO: more flexible
    pub input_offset: u32,
    pub compute_offset: u32,
    pub bytes: u32,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct RunDecompressData {
    pub offset: u32,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct BuildLookupTableData {
    pub point_offset: u32,
    pub table_offset: u32,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct MultiscalarMulData {
    // reversed
    pub start: u8,
    pub end: u8,

    pub num_inputs: u8,
    pub scalars_offset: u32,
    // Offsets to LUTs computed from points. Expected to be a packed array
    pub tables_offset: u32,

    // Result of previous computation and where this result will be stored
    pub result_offset: u32,
}

pub fn decode_instruction_type<T: FromPrimitive>(
    input: &[u8]
) -> Result<T, ProgramError> {
    if input.is_empty() {
        Err(ProgramError::InvalidInstructionData)
    } else {
        FromPrimitive::from_u8(input[0]).ok_or(ProgramError::InvalidInstructionData)
    }
}

#[cfg(not(target_arch = "bpf"))]
pub fn write_bytes(
    buffer: Pubkey,
    authority: Pubkey,
    offset: u32,
    finalized: bool,
    bytes: &[u8],
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(buffer, false),
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    let mut data = vec![ToPrimitive::to_u8(&Curve25519Instruction::WriteBytes).unwrap()];
    data.extend_from_slice(bytemuck::bytes_of(&offset));
    data.push(if finalized { 0x00 } else { 0x01 });
    data.extend_from_slice(bytes);
    Instruction {
        program_id: crate::ID,
        accounts,
        data,
    }
}

#[cfg(not(target_arch = "bpf"))]
pub fn write_input_buffer(
    input_buffer: Pubkey,
    authority: Pubkey,
    points: &[[u8; 32]],
    scalars: &[crate::scalar::Scalar],
) -> Vec<Instruction> {
    assert_eq!(points.len(), scalars.len());

    use crate::traits::Identity;
    return vec![
        // write the points
        write_bytes(
            input_buffer,
            authority,
            HEADER_SIZE as u32,
            false,
            bytemuck::cast_slice::<[u8; 32], u8>(points)
        ),

        // write the scalars
        write_bytes(
            input_buffer,
            authority,
            (HEADER_SIZE + scalars.len() * 32) as u32,
            false,
            bytemuck::cast_slice::<[u8; 32], u8>(
                scalars.iter().map(|s| s.bytes).collect::<Vec<_>>().as_slice()),
        ),

        // write identity for results
        write_bytes(
            input_buffer,
            authority,
            (HEADER_SIZE + scalars.len() * 32 * 2) as u32,
            true,
            &crate::edwards::EdwardsPoint::identity().to_bytes(),
        ),
    ];
}

#[cfg(not(target_arch = "bpf"))]
pub fn initialize_buffer(
    buffer: Pubkey,
    authority: Pubkey,
    buffer_type: Key,
    inputkeys: Vec<Pubkey>,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(buffer, false),
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    let instruction_type = match buffer_type {
        Key::InstructionBufferV1 => {
            assert!(inputkeys.len() == 0);
            Curve25519Instruction::InitializeInstructionBuffer
        },
        Key::InputBufferV1 => {
            assert!(inputkeys.len() == 0);
            Curve25519Instruction::InitializeInputBuffer
        },
        Key::ComputeBufferV1 => {
            assert!(
                inputkeys.len() == 2,
                "InitializeComputeBuffer needs input_buffer and instruction_buffer as pubkeys",
            );
            Curve25519Instruction::InitializeComputeBuffer
        },
        _ => {
            assert!(false, "Invalid buffer type");
            unreachable!();
        },
    };

    let mut data = vec![ToPrimitive::to_u8(&instruction_type).unwrap()];
    for k in inputkeys {
        data.extend_from_slice(&k.to_bytes());
    }
    Instruction {
        program_id: crate::ID,
        accounts,
        data,
    }
}

#[cfg(not(target_arch = "bpf"))]
pub fn close_buffer(
    buffer: Pubkey,
    authority: Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(buffer, false),
        AccountMeta::new_readonly(authority, true),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    Instruction {
        program_id: crate::ID,
        accounts,
        data: vec![ToPrimitive::to_u8(&Curve25519Instruction::CloseBuffer).unwrap()],
    }
}

#[cfg(not(target_arch = "bpf"))]
pub fn crank_compute(
    instruction_buffer: Pubkey,
    input_buffer: Pubkey,
    compute_buffer: Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new_readonly(instruction_buffer, false),
        AccountMeta::new_readonly(input_buffer, false),
        AccountMeta::new(compute_buffer, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    Instruction {
        program_id: crate::ID,
        accounts,
        data: vec![ToPrimitive::to_u8(&Curve25519Instruction::CrankCompute).unwrap()],
    }
}

#[cfg(not(target_arch = "bpf"))]
pub fn noop(
    discriminant: u64,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    let mut data = vec![ToPrimitive::to_u8(&Curve25519Instruction::Noop).unwrap()];
    data.extend_from_slice(&discriminant.to_le_bytes());

    Instruction {
        program_id: crate::ID,
        accounts,
        data,
    }
}

#[cfg(not(target_arch = "bpf"))]
pub fn transer_proof_instructions(
    proof_groups: Vec<usize>,
) -> Vec<u8> {
    // input buffer is laid out as
    // [ ..header.., ..proof_inputs.., ..proof_scalars.. ]

    // some duplicates
    let num_proof_inputs = proof_groups.iter().sum();
    let num_proof_scalars = num_proof_inputs;

    // compute buffer is laid out as
    // [
    //   ..header..,
    //   ..result_space..,
    //   ..scratch_space..,
    //   ..scalars..,
    //   ..tables..,
    // ]
    let result_space_size = proof_groups.len() * 32 * 4;
    let scratch_space = HEADER_SIZE + result_space_size;
    let scratch_space_size = 32 * 12; // space needed for decompression
    let decompress_res_offset = 32 * 8; // where decompressed result is written

    let scalars_offset = scratch_space + scratch_space_size;
    let tables_offset  = scalars_offset + 32 * num_proof_scalars;
    let table_size = LookupTable::<ProjectiveNielsPoint>::TABLE_SIZE;

    let mut instructions = vec![];

    // build the lookup tables
    for input_num in 0..num_proof_inputs {
        let input_offset = HEADER_SIZE + input_num * 32;
        let table_offset = tables_offset + input_num * table_size;
        let scratch_space = scratch_space.try_into().unwrap();
        instructions.extend_from_slice(&[
            DSLInstruction::CopyInput(CopyInputData{
                input_offset: input_offset.try_into().unwrap(),
                compute_offset: scratch_space,
                bytes: 32,
            }),
            DSLInstruction::DecompressInit(RunDecompressData{
                offset: scratch_space,
            }),
            DSLInstruction::InvSqrtInit(RunDecompressData{
                offset: scratch_space + 32,
            }),
            DSLInstruction::Pow22501P1(RunDecompressData{
                offset: scratch_space + 64,
            }),
            DSLInstruction::Pow22501P2(RunDecompressData{
                offset: scratch_space + 96,
            }),
            DSLInstruction::InvSqrtFini(RunDecompressData{
                offset: scratch_space + 32,
            }),
            DSLInstruction::DecompressFini(RunDecompressData{
                offset: scratch_space,
            }),
            DSLInstruction::BuildLookupTable(BuildLookupTableData{
                point_offset: scratch_space + decompress_res_offset,
                table_offset: table_offset.try_into().unwrap(),
            }),
        ]);
    }

    // copy the scalars
    let input_scalars_offset =
        HEADER_SIZE + num_proof_inputs * 32;
    for scalar_num in 0..num_proof_scalars {
        let input_offset = input_scalars_offset + scalar_num * 32;
        let compute_offset = scalars_offset + scalar_num * 32;
        instructions.push(
            DSLInstruction::CopyInput(CopyInputData{
                input_offset: input_offset.try_into().unwrap(),
                compute_offset: compute_offset.try_into().unwrap(),
                bytes: 32,
            }),
        );
    }

    // copy the identity inputs
    let mut result_offset = HEADER_SIZE;
    let input_identity_offset =
        input_scalars_offset + num_proof_scalars * 32;
    for _group_size in proof_groups.iter() {
        instructions.push(
            DSLInstruction::CopyInput(CopyInputData{
                input_offset: input_identity_offset.try_into().unwrap(),
                compute_offset: result_offset.try_into().unwrap(),
                bytes: 32 * 4,
            }),
        );
        result_offset += 32 * 4;
    }

    // compute the multiscalar multiplication for each group
    let mut scalars_offset = scalars_offset;
    let mut tables_offset = tables_offset;
    let mut result_offset = HEADER_SIZE;
    for group_size in proof_groups.iter() {
        for iter in (0..64).rev() {
            instructions.push(
                DSLInstruction::MultiscalarMul(MultiscalarMulData{
                    start: iter as u8,
                    end: iter + 1 as u8,
                    num_inputs: (*group_size).try_into().unwrap(),
                    scalars_offset: scalars_offset.try_into().unwrap(),
                    tables_offset: tables_offset.try_into().unwrap(),
                    result_offset: result_offset.try_into().unwrap(),
                })
            );
        }
        scalars_offset += group_size * 32;
        tables_offset += group_size * table_size;
        result_offset += 32 * 4;
    }

    dsl_instructions_to_bytes(&instructions)
}

#[cfg(not(target_arch = "bpf"))]
pub fn elligator_to_curve_instructions() -> Vec<u8> {
    // compute buffer is laid out as
    // [
    //   ..header..,
    //   ..result_space..,
    //   ..scratch_space..,
    // ]
    let result_space_size = 32 * 4;
    let scratch_space = HEADER_SIZE + result_space_size;

    let mut instructions = vec![];

    let input_num = 0;
    let input_offset = HEADER_SIZE + input_num * 32;
    let scratch_space = scratch_space.try_into().unwrap();
    instructions.extend_from_slice(&[
        DSLInstruction::CopyInput(CopyInputData{
            input_offset: input_offset.try_into().unwrap(),
            compute_offset: scratch_space,
            bytes: 32,
        }),
        DSLInstruction::ElligatorInit(RunDecompressData{
            offset: scratch_space,
        }),
        DSLInstruction::Pow22501P1(RunDecompressData{
            offset: scratch_space + 32,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 64,
        }),
        DSLInstruction::ElligatorFini(RunDecompressData{
            offset: scratch_space,
        }),
    ]);

    dsl_instructions_to_bytes(&instructions)
}

#[cfg(not(target_arch = "bpf"))]
fn dsl_instructions_to_bytes(
    instructions: &[DSLInstruction]
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(INSTRUCTION_SIZE * instructions.len());
    for ix in instructions.iter() {
        let mut buf = [0; INSTRUCTION_SIZE];
        let ix_bytes = ix.try_to_vec().unwrap();
        // should fail if len > INSTRUCTION_SIZE...
        buf[..ix_bytes.len()].copy_from_slice(ix_bytes.as_slice());
        bytes.extend_from_slice(&buf);
    }

    bytes
}

