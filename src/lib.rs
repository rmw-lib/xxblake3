use blake3::Hasher;
use std::convert::TryInto;
use xxhash_rust::xxh3::xxh3_64;
use xxhash_rust::xxh3::Xxh3Builder;

const LEN_U64: usize = std::mem::size_of::<u64>();
const HASHER: Xxh3Builder = Xxh3Builder::new();

#[inline]
pub fn hash_data_secret(secret: &[u8], data: &[u8]) -> u64 {
  let mut h64 = HASHER::build_hasher();
  h64.write(data);
  h64.write(secret);
  h64.finish()
}

macro_rules! xor {
  ($out:expr, $x:expr) => {
    $out.iter_mut().zip($x.iter()).for_each(|(a, b)| *a ^= *b);
  };
}

pub fn encrypt(secret: &[u8], iv: &[u8], data: &[u8]) -> Box<[u8]> {
  let hash = xxh3_64(data);

  let out_len = LEN_U64 + data.len();
  let mut out = Box::new([u8; out_len]);
  let out_data = &mut out[LEN_U64..];

  Hasher::new()
    .update(&hash.to_le_bytes())
    .update(iv)
    .update(secret)
    .finalize_xof()
    .fill(out_data);

  xor!(out_data, data);

  let hash = hash_data_secret(out_data, secret) ^ hash;

  out[..LEN_U64].clone_from_slice(&hash.to_le_bytes());

  out
}

pub fn decrypt(secret: &[u8], iv: &[u8], data: &[u8]) -> Option<Box<[u8]>> {
  let ed = &data[LEN_U64..];
  let hash = u64::from_le_bytes(data[..LEN_U64].try_into().unwrap()) ^ hash_data_secret(ed, secret);
  let out_len = data.len() - LEN_U64;
  let mut out = Box::new([u8; out_len]);

  Hasher::new()
    .update(&hash.to_le_bytes())
    .update(iv)
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
