#![feature(new_uninit)]

use blake3::Hasher;
use core::hash::Hasher as _;
use std::convert::TryInto;
use twox_hash::xxh3::{hash64, Hash64};

const LEN_U64: usize = std::mem::size_of::<u64>();
const H64_SEED: u64 = 18_185_519_866_219_491_001;

#[inline]
pub fn hash_data_secret(secret: &[u8], data: &[u8]) -> u64 {
  let mut h64 = Hash64::with_seed(H64_SEED);
  h64.write(data);
  h64.write(secret);
  h64.finish()
}

macro_rules! xor {
  ($out:expr, $x:expr) => {
    $out.iter_mut().zip($x.iter()).for_each(|(a, b)| *a ^= *b);
  };
}

pub fn encrypt(secret: &[u8], data: &[u8]) -> Box<[u8]> {
  let hash = hash64(data);

  let out_len = LEN_U64 + data.len();
  let mut out = unsafe { Box::<[u8]>::new_uninit_slice(out_len).assume_init() };
  let out_data = &mut out[LEN_U64..];

  Hasher::new()
    .update(&hash.to_le_bytes())
    .update(secret)
    .finalize_xof()
    .fill(out_data);

  xor!(out_data, data);

  let hash = hash_data_secret(out_data, secret) ^ hash;

  out[..LEN_U64].clone_from_slice(&hash.to_le_bytes());

  out
}

pub fn decrypt(secret: &[u8], data: &[u8]) -> Option<Box<[u8]>> {
  let ed = &data[LEN_U64..];
  let hash = u64::from_le_bytes(data[..LEN_U64].try_into().unwrap()) ^ hash_data_secret(ed, secret);
  let out_len = data.len() - LEN_U64;
  let mut out = unsafe { Box::<[u8]>::new_uninit_slice(out_len).assume_init() };

  Hasher::new()
    .update(&hash.to_le_bytes())
    .update(secret)
    .finalize_xof()
    .fill(&mut out);

  xor!(out, ed);

  if hash64(&out) != hash {
    None
  } else {
    Some(out)
  }
}
