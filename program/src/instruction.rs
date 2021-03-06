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

    DecompressEdwards(RunSplitComputeData), // 2 steps
    CompressEdwards(RunSplitComputeData), // 2 steps
    Elligator(RunSplitComputeData), // 2 steps
    MontgomeryElligator(RunSplitComputeData), // 3 steps
    MontgomeryToEdwards(MontgomeryToEdwardsData), // 2 steps
    MulByCofactor(BuildLookupTableData), // 1 step. writes to table_offset

    // CompressedRistretto with witness for inverse sqrt
    DecompressWithWitness(RunDecompressData),
    WriteEdwardsIdentity(RunDecompressData),
}

// fits under the compute limits for deserialization + one iteration + serialization
pub const MAX_MULTISCALAR_POINTS: usize = 11;

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
pub struct RunSplitComputeData {
    pub offset: u32,
    pub step: u8,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct MontgomeryToEdwardsData {
    pub offset: u32,
    pub sign_offset: u32,
    pub step: u8,
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
fn proof_point_size(with_witness: bool) -> usize {
    if with_witness { 32 * 2 } else { 32 }
}

#[cfg(not(target_arch = "bpf"))]
pub fn write_input_points(
    input_buffer: Pubkey,
    authority: Pubkey,
    points: &[[u8; 32]],
) -> Option<Vec<Instruction>> {
    return Some(vec![
        // write the points
        write_bytes(
            input_buffer,
            authority,
            HEADER_SIZE as u32,
            false,
            bytemuck::cast_slice::<[u8; 32], u8>(&points)
        ),
    ]);
}

#[cfg(not(target_arch = "bpf"))]
pub fn write_input_points_with_witness(
    input_buffer: Pubkey,
    authority: Pubkey,
    points: &[[u8; 32]],
) -> Option<Vec<Instruction>> {
    let points_with_witnesses = points.iter().map(
        |p| -> Option<[u8; 64]> {
            let mut res = [0u8; 64];
            res[..32].copy_from_slice(p);

            #[allow(non_snake_case)]
            let Iinv_sq = crate::ristretto::CompressedRistretto(*p)
                .decompress_init()?;

            use curve25519_dalek::field::FieldElement;
            let (ok, witness) = &FieldElement::from_bytes(
                &Iinv_sq.to_bytes(),
            ).invsqrt();

            if ok.unwrap_u8() != 1 { return None; }
            if &Iinv_sq * &crate::field::FieldElement::from_bytes(&witness.to_bytes()).square() != crate::field::FieldElement::one() {
                return None;
            }

            res[32..].copy_from_slice(&witness.to_bytes());

            Some(res)
        }).collect::<Option<Vec<_>>>()?;

    return Some(vec![
        // write the points
        write_bytes(
            input_buffer,
            authority,
            HEADER_SIZE as u32,
            false,
            bytemuck::cast_slice::<[u8; 64], u8>(&points_with_witnesses)
        ),
    ]);
}

#[cfg(not(target_arch = "bpf"))]
pub fn write_input_scalars(
    input_buffer: Pubkey,
    authority: Pubkey,
    scalars: &[crate::scalar::Scalar],
    with_witness: bool,
) -> Vec<Instruction> {
    let base = HEADER_SIZE + scalars.len() * proof_point_size(with_witness);
    return vec![
        // write the scalars
        write_bytes(
            input_buffer,
            authority,
            base.try_into().unwrap(),
            false,
            bytemuck::cast_slice::<[u8; 32], u8>(
                scalars.iter().map(|s| s.to_packed_radix_16()).collect::<Vec<_>>().as_slice()),
        ),
    ];
}

#[cfg(not(target_arch = "bpf"))]
pub fn finalize_buffer(
    buffer: Pubkey,
    authority: Pubkey,
) -> Vec<Instruction> {
    return vec![
        write_bytes(
            buffer,
            authority,
            HEADER_SIZE as u32,
            true,
            &[],
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
pub fn transfer_proof_instructions(
    proof_groups: Vec<usize>,
    with_witness: bool,
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

    let scalars_offset = scratch_space + scratch_space_size;
    let tables_offset  = scalars_offset + 32 * num_proof_scalars;
    let table_size = LookupTable::<ProjectiveNielsPoint>::TABLE_SIZE;

    let mut instructions = vec![];

    // build the lookup tables
    let mut input_offset = HEADER_SIZE;
    for input_num in 0..num_proof_inputs {
        let table_offset = tables_offset + input_num * table_size;
        let scratch_space = scratch_space.try_into().unwrap();
        if with_witness {
            instructions.extend_from_slice(
                &decompress_point_with_witness(input_offset, scratch_space, table_offset),
            );
        } else {
            instructions.extend_from_slice(
                &decompress_point(input_offset, scratch_space, table_offset),
            );
        }
        input_offset += proof_point_size(with_witness);
    }

    // copy the scalars
    let scalar_bytes = 32 * num_proof_scalars;
    instructions.push(
        DSLInstruction::CopyInput(CopyInputData{
            input_offset: input_offset.try_into().unwrap(),
            compute_offset: scalars_offset.try_into().unwrap(),
            bytes: scalar_bytes.try_into().unwrap(),
        }),
    );

    // write the identity inputs
    let mut result_offset = HEADER_SIZE;
    for _group_size in proof_groups.iter() {
        instructions.push(
            DSLInstruction::WriteEdwardsIdentity(RunDecompressData{
                offset: result_offset.try_into().unwrap(),
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

// CompressedRistretto -> Table<Ristretto>
#[cfg(not(target_arch = "bpf"))]
pub fn decompress_point(
    input_offset: usize,
    scratch_space: u32,
    table_offset: usize,
) -> [DSLInstruction; 8] {
    [
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
            offset: scratch_space + 32 * 2,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 32 * 3,
        }),
        DSLInstruction::InvSqrtFini(RunDecompressData{
            offset: scratch_space + 32,
        }),
        DSLInstruction::DecompressFini(RunDecompressData{
            offset: scratch_space,
        }),
        DSLInstruction::BuildLookupTable(BuildLookupTableData{
            point_offset: scratch_space + 32 * 8,
            table_offset: table_offset.try_into().unwrap(),
        }),
    ]
}

// CompressedRistretto, 2^225-1 witness -> Table<Ristretto>
// more input copying, less compute
#[cfg(not(target_arch = "bpf"))]
pub fn decompress_point_with_witness(
    input_offset: usize,
    scratch_space: u32,
    table_offset: usize,
) -> [DSLInstruction; 3] {
    [
        DSLInstruction::CopyInput(CopyInputData{
            input_offset: input_offset.try_into().unwrap(),
            compute_offset: scratch_space,
            bytes: 64,
        }),
        DSLInstruction::DecompressWithWitness(RunDecompressData{
            offset: scratch_space,
        }),
        DSLInstruction::BuildLookupTable(BuildLookupTableData{
            point_offset: scratch_space + 32 * 2,
            table_offset: table_offset.try_into().unwrap(),
        }),
    ]
}

#[cfg(not(target_arch = "bpf"))]
pub fn elligator_to_curve_instructions(
    input_offset: u32,
    scratch_space: u32,
) -> [DSLInstruction; 5] {
    [
        DSLInstruction::CopyInput(CopyInputData{
            input_offset: input_offset.try_into().unwrap(),
            compute_offset: scratch_space,
            bytes: 32,
        }),
        DSLInstruction::Elligator(RunSplitComputeData{
            offset: scratch_space,
            step: 0,
        }),
        DSLInstruction::Pow22501P1(RunDecompressData{
            offset: scratch_space + 32,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 64,
        }),
        DSLInstruction::Elligator(RunSplitComputeData{
            offset: scratch_space,
            step: 1,
        }),
    ]
}

#[cfg(not(target_arch = "bpf"))]
pub fn edwards_elligator_to_curve_instructions(
    input_offset: u32,
    scratch_space: u32,
) -> [DSLInstruction; 17] {
    [
        DSLInstruction::CopyInput(CopyInputData{
            input_offset: input_offset.try_into().unwrap(),
            compute_offset: scratch_space,
            bytes: 32,
        }),
        DSLInstruction::MontgomeryElligator(RunSplitComputeData{
            offset: scratch_space,
            step: 0,
        }),
        DSLInstruction::Pow22501P1(RunDecompressData{
            offset: scratch_space + 32,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 32 * 2,
        }),
        DSLInstruction::MontgomeryElligator(RunSplitComputeData{
            offset: scratch_space,
            step: 1,
        }),
        DSLInstruction::Pow22501P1(RunDecompressData{
            offset: scratch_space + 32 * 6,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 32 * 7,
        }),
        DSLInstruction::MontgomeryElligator(RunSplitComputeData{
            offset: scratch_space,
            step: 2,
        }),

        // largely independent now (sans sign bit)
        DSLInstruction::MontgomeryToEdwards(MontgomeryToEdwardsData{
            offset: scratch_space + 32 * 11,
            sign_offset: scratch_space + 31,
            step: 0,
        }),
        DSLInstruction::Pow22501P1(RunDecompressData{
            offset: scratch_space + 32 * 12,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 32 * 13,
        }),
        DSLInstruction::MontgomeryToEdwards(MontgomeryToEdwardsData{
            offset: scratch_space + 32 * 11,
            sign_offset: scratch_space + 31,
            step: 1,
        }),

        // independent again
        DSLInstruction::DecompressEdwards(RunSplitComputeData{
            offset: scratch_space + 32 * 17,
            step: 0,
        }),
        DSLInstruction::Pow22501P1(RunDecompressData{
            offset: scratch_space + 32 * 18,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 32 * 19,
        }),
        DSLInstruction::DecompressEdwards(RunSplitComputeData{
            offset: scratch_space + 32 * 17,
            step: 1,
        }),
        // in place
        DSLInstruction::MulByCofactor(BuildLookupTableData{
            point_offset: scratch_space + 32 * 23,
            table_offset: scratch_space + 32 * 23,
        }),
    ]
}

#[cfg(not(target_arch = "bpf"))]
pub fn decompress_edwards_instructions(
    input_offset: u32,
    scratch_space: u32,
) -> [DSLInstruction; 5] {
    [
        DSLInstruction::CopyInput(CopyInputData{
            input_offset: input_offset.try_into().unwrap(),
            compute_offset: scratch_space,
            bytes: 32,
        }),
        DSLInstruction::DecompressEdwards(RunSplitComputeData{
            offset: scratch_space,
            step: 0,
        }),
        DSLInstruction::Pow22501P1(RunDecompressData{
            offset: scratch_space + 32,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 64,
        }),
        DSLInstruction::DecompressEdwards(RunSplitComputeData{
            offset: scratch_space,
            step: 1,
        }),
    ]
}

#[cfg(not(target_arch = "bpf"))]
pub fn compress_edwards_instructions(
    input_offset: u32,
    scratch_space: u32,
) -> [DSLInstruction; 5] {
    [
        DSLInstruction::CopyInput(CopyInputData{
            input_offset: input_offset.try_into().unwrap(),
            compute_offset: scratch_space,
            bytes: 128,
        }),
        DSLInstruction::CompressEdwards(RunSplitComputeData{
            offset: scratch_space,
            step: 0,
        }),
        DSLInstruction::Pow22501P1(RunDecompressData{
            offset: scratch_space + 32 * 4,
        }),
        DSLInstruction::Pow22501P2(RunDecompressData{
            offset: scratch_space + 32 * 5,
        }),
        DSLInstruction::CompressEdwards(RunSplitComputeData{
            offset: scratch_space,
            step: 1,
        }),
    ]
}

#[cfg(not(target_arch = "bpf"))]
pub fn dsl_instructions_to_bytes(
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

