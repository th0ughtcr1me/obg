use rand::Rng;
use rand::prelude::*;
use chacha20::cipher::KeyIvInit;
use chacha20::cipher::StreamCipher;
use chacha20::ChaCha20;


pub fn mk(key: [u8;32], nonce: [u8;12]) -> ChaCha20 {
    ChaCha20::new(&key.into(), &nonce.into())
    // chacha20.apply_keystream(&mut password);
}
