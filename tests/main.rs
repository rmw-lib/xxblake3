use xxblake3::{decrypt, encrypt};

#[test]
fn main() {
  let secret = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
  ];

  let iv = 1u32.to_le_bytes();
  let data = "test msg".as_bytes();

  let mut encrypted = encrypt(&secret, &iv, data);

  println!("data len {}", data.len());
  println!("encrypted len {}", encrypted.len());

  assert_eq!(*data, *decrypt(&secret, &iv, &encrypted).unwrap());

  encrypted[9] = !encrypted[9];

  assert_eq!(None, decrypt(&secret, &iv, &encrypted));
}
