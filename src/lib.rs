//#![feature(iterator_step_by)]
//#![feature(extern_prelude)]
extern crate base64;
extern crate byteorder;
extern crate itertools;
extern crate openssl;
extern crate rand;
extern crate block_buffer;

#[macro_use]
extern crate maplit;
extern crate digest;
extern crate fake_simd as simd;

extern crate hyper;

mod md4;
mod sha1;
mod convert;
mod util;
pub mod set1;
pub mod set2;
pub mod set3;
pub mod set4;


#[cfg(test)]
mod tests;

