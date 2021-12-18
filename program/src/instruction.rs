use {
    bytemuck::{Pod, Zeroable},
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
        sysvar,
    },
};


#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Curve25519Instruction {
    WriteBytes,

    InvSqrtInit,
    Pow22501P1,
    Pow22501P2,
    InvSqrtFini,

    DecompressInit,
    DecompressFini,

    BuildLookupTable,
}

pub fn decode_instruction_type(
    input: &[u8]
) -> Result<Curve25519Instruction, ProgramError> {
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
    let mut accounts = vec![
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
    let mut accounts = vec![
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
    table_buffer: Pubkey,
    point_offset: u32,
    table_offset: u32,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(compute_buffer, false),
        AccountMeta::new(table_buffer, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    encode_instruction(
        accounts,
        Curve25519Instruction::BuildLookupTable,
        &[point_offset, table_offset],
    )
}
