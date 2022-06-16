<!-- 本文件由 ./readme.make.md 自动生成，请不要直接修改此文件 -->

# xxblake3

encryption and decryption based on xxh3 and blake3

see [tests/main.rs](https://docs.rs/crate/xxblake3/0.0.1/source/tests/main.rs) for usage

```rust
use xxblake3::{decrypt, encrypt};

#[test]
fn main() {
  let secret = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
  ];

  let data = "test msg".as_bytes();

  let mut encrypted = encrypt(&secret, data);

  println!("data len {}", data.len());
  println!("encrypted len {}", encrypted.len());

  assert_eq!(*data, *decrypt(&secret, &encrypted).unwrap());

  encrypted[9] = !encrypted[9];

  assert_eq!(None, decrypt(&secret, &encrypted));
}
```

impl code

```rust
#![feature(new_uninit)]

use blake3::Hasher;
use core::hash::Hasher as _;
use std::convert::TryInto;
use twox_hash::xxh3::{hash64, Hash64};

const LEN_U64: usize = std::mem::size_of::<u64>();
const H64_SEED: u64 = 1;

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
    let hash =
        u64::from_le_bytes(data[..LEN_U64].try_into().unwrap()) ^ hash_data_secret(ed, secret);
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
```

## step

加密流程 :

  1. 校验码 = xxh3::Hash64(原始内容) // seed = 0
  1. 流密码 = blake3(校验码+秘钥), 哈希输出长度=内容长度
  1. 加密内容 = 原始内容 异或 流密码
  1. 加密校验码 = xxh3::Hash64(加密内容+秘钥) 异或 校验码 // seed = 1
  1. 输出 = 加密校验码 + 加密内容

解密流程 :

  1. 校验码 = xxh3::Hash64(加密内容+秘钥) 异或 加密校验码 // seed = 1
  1. 流密码 = blake3(校验码+秘钥), 哈希输出长度=内容长度
  1. 解密内容 = 加密内容 异或 流密码
  1. 完整性效验 : 计算 xxh3::Hash64(解密内容) == 校验码 // seed = 0