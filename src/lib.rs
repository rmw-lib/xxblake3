use std::{
  alloc::{alloc_zeroed, Layout},
  convert::TryInto,
  hash::{BuildHasher, Hasher},
};

use xxhash_rust::xxh3::{xxh3_64, Xxh3Builder};

const LEN_U64: usize = std::mem::size_of::<u64>();
const HASHER: Xxh3Builder = Xxh3Builder::new();

fn box_new(len: usize) -> Box<[u8]> {
  if len == 0 {
    return <Box<[u8]>>::default();
  }
  let layout = Layout::array::<u8>(len).unwrap();
  let ptr = unsafe { alloc_zeroed(layout) };
  let slice_ptr = core::ptr::slice_from_raw_parts_mut(ptr, len);
  unsafe { Box::from_raw(slice_ptr) }
}

#[inline]
pub fn hash_data_secret(secret: &[u8], data: &[u8]) -> u64 {
  let mut h64 = HASHER.build_hasher();
  h64.write(data);
  h64.write(secret);
  h64.finish()
}

macro_rules! xor {
  ($out:expr, $x:expr) => {
    $out.iter_mut().zip($x.iter()).for_each(|(a, b)| *a ^= *b);
  };
}

pub fn encrypt(
  secret: impl AsRef<[u8]>,
  iv: impl AsRef<[u8]>,
  data: impl AsRef<[u8]>,
) -> Box<[u8]> {
  let data = data.as_ref();
  let secret = secret.as_ref();
  let hash = xxh3_64(data);

  let out_len = LEN_U64 + data.len();
  let mut out = box_new(out_len);
  let out_data = &mut out[LEN_U64..];

  blake3::Hasher::new()
    .update(&hash.to_le_bytes())
    .update(iv.as_ref())
    .update(secret)
    .finalize_xof()
    .fill(out_data);

  xor!(out_data, data);

  let hash = hash_data_secret(out_data, secret) ^ hash;

  out[..LEN_U64].clone_from_slice(&hash.to_le_bytes());

  out
}

pub fn decrypt(
  secret: impl AsRef<[u8]>,
  iv: impl AsRef<[u8]>,
  data: impl AsRef<[u8]>,
) -> Option<Box<[u8]>> {
  let data = data.as_ref();
  let secret = secret.as_ref();
  let ed = &data[LEN_U64..];
  let hash = u64::from_le_bytes(data[..LEN_U64].try_into().unwrap()) ^ hash_data_secret(ed, secret);
  let out_len = data.len() - LEN_U64;
  let mut out = box_new(out_len);

  blake3::Hasher::new()
    .update(&hash.to_le_bytes())
    .update(iv.as_ref())
    .update(secret)
    .finalize_xof()
    .fill(&mut out);

  xor!(out, ed);

  if xxh3_64(&out) != hash {
    None
  } else {
    Some(out)
  }
}
