use {
    borsh::{BorshDeserialize, BorshSerialize},
    bytemuck::{Pod},
    num_derive::{FromPrimitive, ToPrimitive},
    num_traits::{FromPrimitive},
    solana_program::{
        program_error::ProgramError,
    },
};

#[cfg(not(target_arch = "bpf"))]
use {
    num_traits::{ToPrimitive},
    solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
    },
};

#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Curve25519Instruction {
    WriteBytes,
    InitializeInputBuffer,
    InitializeComputeBuffer,
    CrankCompute,
}

// TODO: move to state
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum Key {
    Uninitialized,
    InputBufferV1,
    ComputeBufferV1,
}

// ComputeHeader and InputHeader should be smaller than HEADER_SIZE
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct ComputeHeader {
    pub key: Key,
    pub instruction_num: u32,
}
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct InputHeader {
    pub key: Key,
}

pub const HEADER_SIZE: usize = 32;
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
}

// fits under the compute limits for deserialization + one iteration + serialization
pub const MAX_MULTISCALAR_POINTS: usize = 6;

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct CopyInputData { // 32 bytes at a time.. TODO: more flexible
    pub input_offset: u32,
    pub compute_offset: u32,
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

pub fn decode_instruction_data<T: Pod>(
    input: &[u8]
) -> Result<&T, ProgramError> {
    if input.len() < 2 {
        Err(ProgramError::InvalidInstructionData)
    } else {
        pod_from_bytes(&input[1..]).ok_or(ProgramError::InvalidArgument)
    }
}

pub fn decode_dsl_instruction_data<T: Pod>(
    input: &[u8],
) -> Result<&T, ProgramError> {
    if input.len() < 2 {
        Err(ProgramError::InvalidInstructionData)
    } else {
        pod_from_bytes(&input[1..1+std::mem::size_of::<T>()])
            .ok_or(ProgramError::InvalidArgument)
    }
}

/// Convert a slice into a `Pod` (zero copy)
pub fn pod_from_bytes<T: Pod>(bytes: &[u8]) -> Option<&T> {
    bytemuck::try_from_bytes(bytes).ok()
}


#[cfg(not(target_arch = "bpf"))]
pub fn encode_instruction<T: Pod>(
    accounts: Vec<AccountMeta>,
    instruction_type: Curve25519Instruction,
    instruction_data: &T,
) -> Instruction {
    let mut data = vec![ToPrimitive::to_u8(&instruction_type).unwrap()];
    data.extend_from_slice(bytemuck::bytes_of(instruction_data));
    Instruction {
        program_id: crate::ID,
        accounts,
        data,
    }
}

#[cfg(not(target_arch = "bpf"))]
pub fn write_bytes(
    compute_buffer: Pubkey,
    offset: u32,
    bytes: &[u8],
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(compute_buffer, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    let mut data = vec![ToPrimitive::to_u8(&Curve25519Instruction::WriteBytes).unwrap()];
    data.extend_from_slice(bytemuck::bytes_of(&offset));
    data.extend_from_slice(bytes);
    Instruction {
        program_id: crate::ID,
        accounts,
        data,
    }
}

#[cfg(not(target_arch = "bpf"))]
pub fn run_compute_routine(
    instruction_type: Curve25519Instruction,
    compute_buffer: Pubkey,
    offset: u32,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(compute_buffer, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    encode_instruction(
        accounts,
        instruction_type,
        &offset,
    )
}

#[cfg(not(target_arch = "bpf"))]
pub fn build_lookup_table(
    compute_buffer: Pubkey,
    // table_buffer: Pubkey,
    point_offset: u32,
    table_offset: u32,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(compute_buffer, false),
        // AccountMeta::new(compute_buffer, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    encode_instruction(
        accounts,
        Curve25519Instruction::BuildLookupTable,
        &[point_offset, table_offset],
    )
}

#[cfg(not(target_arch = "bpf"))]
pub fn multiscalar_mul(
    compute_buffer: Pubkey,
    start: u8,
    end: u8,
    num_inputs: u8,
    scalars_offset: u32,
    tables_offset: u32,
    result_offset: u32,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(compute_buffer, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    assert!(usize::from(num_inputs) <= MAX_MULTISCALAR_POINTS);

    encode_instruction(
        accounts,
        Curve25519Instruction::MultiscalarMul,
        &MultiscalarMulData {
            start: start,
            end: end,
            num_inputs: num_inputs,
            scalars_offset: scalars_offset.into(),
            tables_offset: tables_offset.into(),
            result_offset: result_offset.into(),
        },
    )
}

#[cfg(not(target_arch = "bpf"))]
pub fn prep_multiscalar_input(
    compute_buffer: Pubkey,
    bytes: &[u8],
    input_num: u8,
    state_offset: u32,  // should leave at least room for decompression (32 * 11)
) -> Vec<Instruction> {
    let table_offset: u32 =
        state_offset                       // decompression state
        + input_num as u32 * 32 * 4 * 8;   // LUT size 8, 4 field elements per
    vec![
        write_bytes(
            compute_buffer,
            0,
            &bytes,
        ),
        run_compute_routine(
            Curve25519Instruction::DecompressInit,
            compute_buffer,
            0,
        ),
        run_compute_routine(
            Curve25519Instruction::InvSqrtInit,
            compute_buffer,
            32,
        ),
        run_compute_routine(
            Curve25519Instruction::Pow22501P1,
            compute_buffer,
            64,
        ),
        run_compute_routine(
            Curve25519Instruction::Pow22501P2,
            compute_buffer,
            96,
        ),
        run_compute_routine(
            Curve25519Instruction::InvSqrtFini,
            compute_buffer,
            32,
        ),
        run_compute_routine(
            Curve25519Instruction::DecompressFini,
            compute_buffer,
            0,
        ),
        build_lookup_table(
            compute_buffer,
            32 * 7,
            table_offset,
        ),
    ]
}


#[cfg(not(target_arch = "bpf"))]
pub fn transer_proof_instructions() {
    // input buffer is laid out as
    // [ ..header.., ..proof_inputs.., ..proof_scalars.. ]

    // some duplicates
    let num_proof_inputs = 11;
    let num_proof_scalars = num_proof_inputs;
    let proof_groups = [3, 3, 5];

    assert_eq!(proof_groups.iter().sum(), num_proof_inputs);

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
    let scratch_space_size = 32 * 7; // space needed for decompression

    let scalars_offset = scratch_space + scratch_space_size;
    let tables_offset  = scalars_offset + 32 * num_proof_scalars;
    let table_size = 32 * 4 * 8;

    let mut instructions = vec![];

    // build the lookup tables
    for input_num in 0..num_proof_inputs {
        let input_offset = HEADER_SIZE + input_num * 32;
        let table_offset = tables_offset + input_num * table_size;
        instructions.extend_from_slice(&[
            DSLInstruction::CopyInput {
                input_offset,
                compute_offset: scratch_space,
            },
            DSLInstruction::DecompressInit {
                offset: scratch_space,
            },
            DSLInstruction::InvSqrtInit {
                offset: scratch_space + 32,
            },
            DSLInstruction::Pow22501P1 {
                offset: scratch_space + 64,
            },
            DSLInstruction::Pow22501P2 {
                offset: scratch_space + 96,
            },
            DSLInstruction::InvSqrtFini {
                offset: scratch_space + 32,
            },
            DSLInstruction::DecompressFini {
                offset: scratch_space,
            },
            DSLInstruction::BuildLookupTable {
                point_offset: scratch_space,
                table_offset,
            },
        ]);
    }

    // copy the scalars
    let input_scalars_offset =
        HEADER_SIZE + num_proof_inputs * 32;
    for scalar_num in 0..num_proof_scalars {
        let input_offset = input_scalars_offset + scalar_num * 32;
        let compute_offset = scalars_offset + scalar_num * 32;
        instructions.push(
            DSLInstruction::CopyInput {
                input_offset,
                compute_offset,
            },
        );
    }

    // compute the multiscalar multiplication for each group
    let mut scalars_offset = scalars_offset;
    let mut tables_offset = tables_offset;
    let mut result_offset = HEADER_SIZE;
    for group_size in proof_groups.iter() {
        for iter in (0..64).rev() {
            instructions.push(
                DSLInstruction::MultiscalarMul {
                    start: iter as u8,
                    end: iter + 1 as u8,
                    num_inputs: group_size,
                    scalars_offset,
                    tables_offset,
                    result_offset,
                }
            );
        }
        scalars_offset += group_size * 32;
        tables_offset += group_size * 32 * 4;
        result_offset += 32 * 4;
    }

    let mut bytes = Vec::with_capacity(INSTRUCTION_SIZE * instructions.len());
    for ix in instructions.iter() {
        let buf = [0; INSTRUCTION_SIZE ];
        let ix_bytes = bytemuck::bytes_of(&ix);
        buf[..ix_bytes.len()].copy_from_slice(ix_bytes);
        bytes.extend_with_slice(buf);
    }

    bytes
}

