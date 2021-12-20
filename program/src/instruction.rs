use {
    bytemuck::{Pod, Zeroable},
    crate::scalar,
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
    std::convert::TryInto,
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
    MultiscalarMul,
}

// fits under the compute limits for deserialization + one iteration + serialization
pub const MAX_MULTISCALAR_POINTS: usize = 6;

/// The standard `u32` can cause alignment issues when placed in a `Pod`, define a replacement that
/// is usable in all `Pod`s
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodU32([u8; 4]);
impl From<u32> for PodU32 {
    fn from(n: u32) -> Self {
        Self(n.to_le_bytes())
    }
}
impl From<PodU32> for u32 {
    fn from(pod: PodU32) -> Self {
        Self::from_le_bytes(pod.0)
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct MultiscalarMulData {
    // reversed
    pub start: u8,
    pub end: u8,

    pub num_inputs: u8,
    pub scalars_offset: PodU32,
    // Offsets to LUTs computed from points. Expected to be a packed array
    pub tables_offset: PodU32,

    // Result of previous computation and where this result will be stored
    pub result_offset: PodU32,
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
    // table_buffer: Pubkey,
    point_offset: u32,
    table_offset: u32,
) -> Instruction {
    let mut accounts = vec![
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
    let mut accounts = vec![
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
