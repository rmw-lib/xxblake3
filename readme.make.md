# xxblake3

encryption and decryption based on xxh3 and blake3

see [tests/main.rs](https://docs.rs/crate/xxblake3/0.0.1/source/tests/main.rs) for usage

```rust
#include ./tests/main.rs
```

impl code

```rust
#include ./src/lib.rs
```

## step

加密流程 :

  1. 校验码 = xxh3::Hash64(原始内容) // seed = 0
  1. 流密码 = blake3(校验码+秘钥), 哈希输出长度=内容长度
  1. 加密内容 = 原始内容 异或 流密码
  1. 加密校验码 = xxh3::Hash64(加密内容+秘钥) 异或 校验码 // seed = 181855_198662_19491001
  1. 输出 = 加密校验码 + 加密内容

解密流程 :

  1. 校验码 = xxh3::Hash64(加密内容+秘钥) 异或 加密校验码 // seed = 181855_198662_19491001
  1. 流密码 = blake3(校验码+秘钥), 哈希输出长度=内容长度
  1. 解密内容 = 加密内容 异或 流密码
  1. 完整性效验 : 计算 xxh3::Hash64(解密内容) == 校验码 // seed = 0
