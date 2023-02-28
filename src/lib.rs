#![feature(vec_into_raw_parts)]
#![feature(get_many_mut)]

mod difficulty;
mod prove;
pub mod reader;
mod verify;
pub use crate::prove::*;
pub use crate::verify::*;
