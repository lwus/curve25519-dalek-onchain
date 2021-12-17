use crate::{
    instruction::*,
    field::*,
};

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use std::convert::TryInto;

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    match decode_instruction_type(input)? {
        Curve25519Instruction::Pow22501P1 => {
            let element = FieldElement::from_bytes(&input[1..].try_into().map_err(|_| ProgramError::InvalidArgument)?);
            let res = element.pow22501();
            Ok(())
        }
    }
}
