mod entrypoint;
pub mod processor;
pub mod instruction;

// Internal macros. Must come first!
#[macro_use]
pub(crate) mod macros;

pub mod backend;
// pub mod constants;
pub mod edwards;
pub mod field;
pub mod ristretto;
pub mod scalar;
pub mod traits;
pub mod window;

solana_program::declare_id!("curveSS6UodDcBHTgerBXQxzW43kctcPe1dwT7yWaox");
