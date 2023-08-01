/*!
CoDeCs Module

Performs Basic AES256-CBC Encryption and Decryption without HMAC: the
IV application in the first plaintext block is up to the user for
now...

# Example


```
use obg::aescbc::cdc::Aes256CbcCodec;
```
*/

#![allow(unused)]
pub use crate::aescbc::kd::pbkdf2_sha384_128bits;
pub use crate::aescbc::kd::pbkdf2_sha384_256bits;
pub use crate::aescbc::pad::Ansix923;
pub use crate::aescbc::pad::Padder128;
pub use crate::aescbc::pad::Padding;
pub use crate::aescbc::tp::{B128, B256};
pub use crate::errors::Error;
pub use crate::ioutils::{absolute_path, open_write, read_bytes};
use hex;
use rand::prelude::*;
use serde_yaml;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::Write;
use std::path::Path;

use aes::cipher::{
    // generic_array::{GenericArray, typenum::U8};
    generic_array::{ArrayLength, GenericArray},
    BlockDecrypt,
    BlockEncrypt,
    KeyInit,
};
use aes::Aes256;

pub enum BlockTransformationAction {
    Encryption,
    Decryption,
}

pub struct BlockTransformationContext {
    current: usize,
    total: usize,
    action: BlockTransformationAction,
}


impl BlockTransformationContext {
    pub fn new(current: usize, total: usize, action: BlockTransformationAction) -> BlockTransformationContext {
        BlockTransformationContext {
            current, total, action
        }
    }
}

pub trait EncryptionEngine {
    fn encrypt_block(&self, plaintext: &[u8], xor_block: &[u8]) -> Vec<u8>;
    fn decrypt_block(&self, ciphertext: &[u8], xor_block: &[u8]) -> Vec<u8>;
    fn encrypt_blocks(&self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt_blocks(&self, ciphertext: &[u8]) -> Vec<u8>;
    fn add_callback<F: Fn(BlockTransformationContext)+'static>(&self, callback: F);
    fn trigger_callbacks(&self, index: usize, count: usize, action: BlockTransformationAction);
}

pub fn xor_128(left: B128, right: B128) -> B128 {
    let mut result: B128 = [0; 16];
    for (i, (s, o)) in left.into_iter().zip(right.iter()).enumerate() {
        result[i] = s ^ o;
    }
    result
}

pub fn xor_256(left: B256, right: B256) -> B256 {
    let mut result: B256 = [0; 32];
    for (i, (s, o)) in left.into_iter().zip(right.iter()).enumerate() {
        result[i] = s ^ o;
    }
    result
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.into_iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Aes256Key {
    key: String,
    iv: String,
}
impl Aes256Key {
    pub fn skey(&self) -> B256 {
        let mut skey: B256 = [0x0; 32];
        skey.copy_from_slice(&self.key.as_bytes()[..32]);
        skey
    }
    pub fn siv(&self) -> B128 {
        let mut siv: B128 = [0x0; 16];
        siv.copy_from_slice(&self.iv.as_bytes()[..16]);
        siv
    }
    pub fn new(key: B256, iv: B128) -> Aes256Key {
        Aes256Key {
            key: hex::encode(key),
            iv: hex::encode(iv),
        }
    }
    pub fn derive(password: String, salt: String, cycles: u32, shuffle_iv: bool) -> Result<Aes256Key, Error> {
        let mut rng = rand::thread_rng();

        let password_file = Path::new(&password);
        let salt_file = Path::new(&salt);

        let password = if password_file.exists() {
            read_bytes(&password)?
        } else {
            password.as_str().as_bytes().to_vec()
        };
        let salt = if salt_file.exists() {
            read_bytes(&salt)?
        } else {
            salt.as_str().as_bytes().to_vec()
        };

        let key = pbkdf2_sha384_256bits(&password, &salt, cycles);
        let mut iv = pbkdf2_sha384_128bits(&salt, &password, cycles / 0xa);
        if shuffle_iv {
            iv.shuffle(&mut rng);
        }
        Ok(Aes256Key::new(key, iv))
    }
    pub fn load_from_file(filename: String) -> Result<Aes256Key, Error> {
        let location = absolute_path(&filename);
        let path = Path::new(&location);
        if path.exists() {
            let bytes = read_bytes(&location)?;
            let key: Aes256Key = serde_yaml::from_slice(&bytes)?;
            Ok(key)
        } else {
            Err(Error::FileSystemError(format!(
                "{} does not exist",
                location
            )))
        }
    }

    pub fn save_to_file(&self, filename: String) -> Result<(), Error> {
        let mut file = open_write(&filename).unwrap();
        let yaml = serde_yaml::to_string(self)?;
        Ok(file.write_all(yaml.as_bytes())?)
    }
}


#[derive(Debug, Clone)]
pub struct Aes256CbcCodec<F>
where
    T: Fn(BlockTransformationContext),
{
    cipher: Aes256,
    key: B256,
    iv: B128,
    padding: Padding,
    progress_callbacks: Vec<Box<F>>,
}

impl <T: Fn(BlockTransformationContext)> Aes256CbcCodec<T> {
    pub fn new(key: B256, iv: B128) -> Aes256CbcCodec<T> {
        let padding = Padding::Ansix923(Ansix923::new(0x00 as u8));
        Aes256CbcCodec::new_with_padding(key, iv, padding)
    }
    pub fn new_with_padding(key: B256, iv: B128, padding: Padding) -> Aes256CbcCodec<T> {
        let gkey = GenericArray::from(key);
        Aes256CbcCodec {
            cipher: Aes256::new(&gkey),
            key: key,
            iv: iv,
            padding: padding,
            progress_callbacks: Vec::new(),
        }
    }
    fn add_callback(&mut self, callback: T) {
        self.progress_callbacks.push(callback);
    }
    fn trigger_callbacks(&self, index: usize, count: usize, action: BlockTransformationAction) {
        let ctx = BlockTransformationContext::new(index, count, action);
        for callback in &self.progress_callbacks.iter() {
            let context = BlockTransformationContext::new(index, count, action);
            (&mut *callback.borrow())(ctx.clone());
        }
    }
    pub fn encrypt_first_block(&self, input_block: &[u8]) -> Vec<u8> {
        self.encrypt_block(input_block, &self.iv)
    }
}

impl<T> EncryptionEngine for Aes256CbcCodec<T> {
    fn encrypt_block(&self, plaintext: &[u8], xor_block: &[u8]) -> Vec<u8> {
        // XXX: validate blocks' size to 16 bytes and return Result<Vec<u8>, Error>
        let mut input_block = xor(&plaintext, &xor_block);
        let mut output_block = GenericArray::from_mut_slice(input_block.as_mut_slice());
        self.cipher.encrypt_block(&mut output_block);
        output_block.as_slice().to_vec()
    }
    fn encrypt_blocks(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        // split plaintext into 16 blocks
        // let padded = pad128bits_ansi_x923(&plaintext.to_vec());
        // let plaintext = padded.as_slice();
        let chunks: Vec<Vec<u8>> = plaintext.chunks(16).map(|c| c.to_vec()).collect();
        let count = chunks.len();

        for (index, block) in chunks.iter().enumerate() {
            let xor_block = if index == 0 {
                &self.iv
            } else {
                result[index - 1].as_slice()
            };
            let last_block_pos = count - 1;
            let block = &if index == last_block_pos {
                // ensure padding in the last block to avoid side-effects
                self.padding.pad(&block).to_vec()
            } else {
                block.to_vec()
            };
            result.push(self.encrypt_block(block, xor_block));
            self.trigger_callbacks(index, count, BlockTransformationAction::Encryption);
        }
        result.iter().flatten().map(|b| b.clone()).collect()
    }
    fn decrypt_blocks(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        // split ciphertext into 16 blocks
        let chunks: Vec<Vec<u8>> = ciphertext.chunks(16).map(|c| c.to_vec()).collect();
        let count = chunks.len();

        for (index, block) in chunks.iter().enumerate() {
            let xor_block = if index == 0 {
                &self.iv
            } else {
                chunks[index - 1].as_slice()
            };
            let last_block_pos = count - 1;
            let block = self.decrypt_block(block, xor_block);
            result.push(if index == last_block_pos {
                // ensure padding in the last block to avoid side-effects
                self.padding.unpad(&block)
            } else {
                block
            });
            self.trigger_callbacks(index, count, BlockTransformationAction::Decryption);
        }
        result.iter().flatten().map(|b| b.clone()).collect()
    }
    fn decrypt_block(&self, ciphertext: &[u8], xor_block: &[u8]) -> Vec<u8> {
        // XXX: validate block size 16 bytes and return Result<Vec<u8>, Error>
        let mut ciphertext = ciphertext.to_vec();
        let mut plaintext = GenericArray::from_mut_slice(ciphertext.as_mut_slice());
        self.cipher.decrypt_block(&mut plaintext);
        xor(&plaintext.as_slice(), &xor_block).to_vec()
    }
}

#[cfg(test)]
mod aes256cbc_tests {
    use crate::aescbc::cdc::{xor_128, xor_256, Aes256CbcCodec, EncryptionEngine, B128, B256};
    use crate::aescbc::kd::pbkdf2_sha384_128bits;
    use crate::aescbc::kd::pbkdf2_sha384_256bits;
    use crate::ioutils::read_bytes;
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
    use aes::Aes256;
    use k9::assert_equal;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct Block {
        pub plaintext: B128,
        pub input: B128,
        pub output: B128,
        pub ciphertext: B128,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Aes256CBCTestCase {
        pub key: B256,
        pub iv: B128,
        pub blocks: Vec<Block>,
    }

    impl Aes256CBCTestCase {
        pub fn block_at(&self, index: usize) -> Block {
            self.blocks.get(index).unwrap().clone()
        }
    }

    pub fn nist_cbc_aes256_encryption_test_input() -> Aes256CBCTestCase {
        /// https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
        /// p.28 - # F.2.5 CBC-AES256.Encrypt Vectors
        let encryption_blocks = [
            Block {
                plaintext: [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a,
                ],
                input: [
                    0x6b, 0xc0, 0xbc, 0xe1, 0x2a, 0x45, 0x99, 0x91, 0xe1, 0x34, 0x74, 0x1a, 0x7f,
                    0x9e, 0x19, 0x25,
                ],
                output: [
                    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f,
                    0x7b, 0xfb, 0xd6,
                ],
                ciphertext: [
                    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f,
                    0x7b, 0xfb, 0xd6,
                ],
            },
            Block {
                plaintext: [
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
                    0xaf, 0x8e, 0x51,
                ],
                input: [
                    0x5b, 0xa1, 0xc6, 0x53, 0xc8, 0xe6, 0x5d, 0x26, 0xe9, 0x29, 0xc4, 0x57, 0x1a,
                    0xd4, 0x75, 0x87,
                ],
                output: [
                    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6,
                    0x70, 0x2c, 0x7d,
                ],
                ciphertext: [
                    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6,
                    0x70, 0x2c, 0x7d,
                ],
            },
            Block {
                plaintext: [
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
                    0x0a, 0x52, 0xef,
                ],
                input: [
                    0xac, 0x34, 0x52, 0xd0, 0xdd, 0x87, 0x64, 0x9c, 0x82, 0x64, 0xb6, 0x62, 0xdc,
                    0x7a, 0x7e, 0x92,
                ],
                output: [
                    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04,
                    0x23, 0x14, 0x61,
                ],
                ciphertext: [
                    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04,
                    0x23, 0x14, 0x61,
                ],
            },
            Block {
                plaintext: [
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6,
                    0x6c, 0x37, 0x10,
                ],
                input: [
                    0xcf, 0x6d, 0x17, 0x2c, 0x76, 0x96, 0x21, 0xd8, 0x08, 0x1b, 0xa3, 0x18, 0xe2,
                    0x4f, 0x23, 0x71,
                ],
                output: [
                    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c,
                    0x6a, 0x9d, 0x1b,
                ],
                ciphertext: [
                    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c,
                    0x6a, 0x9d, 0x1b,
                ],
            },
        ];
        return Aes256CBCTestCase {
            key: [
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
                0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
                0x09, 0x14, 0xdf, 0xf4,
            ],
            iv: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            blocks: encryption_blocks.to_vec(),
        };
    }
    pub fn nist_cbc_aes256_decryption_test_input() -> Aes256CBCTestCase {
        /// https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
        /// p.29 - # F.2.6 CBC-AES256.Decrypt Vectors
        let decryption_blocks = [
            Block {
                ciphertext: [
                    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f,
                    0x7b, 0xfb, 0xd6,
                ],
                input: [
                    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f,
                    0x7b, 0xfb, 0xd6,
                ],
                output: [
                    0x6b, 0xc0, 0xbc, 0xe1, 0x2a, 0x45, 0x99, 0x91, 0xe1, 0x34, 0x74, 0x1a, 0x7f,
                    0x9e, 0x19, 0x25,
                ],
                plaintext: [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a,
                ],
            },
            Block {
                ciphertext: [
                    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6,
                    0x70, 0x2c, 0x7d,
                ],
                input: [
                    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6,
                    0x70, 0x2c, 0x7d,
                ],
                output: [
                    0x5b, 0xa1, 0xc6, 0x53, 0xc8, 0xe6, 0x5d, 0x26, 0xe9, 0x29, 0xc4, 0x57, 0x1a,
                    0xd4, 0x75, 0x87,
                ],
                plaintext: [
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
                    0xaf, 0x8e, 0x51,
                ],
            },
            Block {
                ciphertext: [
                    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04,
                    0x23, 0x14, 0x61,
                ],
                input: [
                    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04,
                    0x23, 0x14, 0x61,
                ],
                output: [
                    0xac, 0x34, 0x52, 0xd0, 0xdd, 0x87, 0x64, 0x9c, 0x82, 0x64, 0xb6, 0x62, 0xdc,
                    0x7a, 0x7e, 0x92,
                ],
                plaintext: [
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
                    0x0a, 0x52, 0xef,
                ],
            },
            Block {
                ciphertext: [
                    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c,
                    0x6a, 0x9d, 0x1b,
                ],
                input: [
                    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c,
                    0x6a, 0x9d, 0x1b,
                ],
                output: [
                    0xcf, 0x6d, 0x17, 0x2c, 0x76, 0x96, 0x21, 0xd8, 0x08, 0x1b, 0xa3, 0x18, 0xe2,
                    0x4f, 0x23, 0x71,
                ],
                plaintext: [
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6,
                    0x6c, 0x37, 0x10,
                ],
            },
        ];
        return Aes256CBCTestCase {
            key: [
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
                0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
                0x09, 0x14, 0xdf, 0xf4,
            ],
            iv: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            blocks: decryption_blocks.to_vec(),
        };
    }

    #[test]
    pub fn test_confirm_cbc_aes256_nist_spec_encrypt_single_block() {
        // Given the CBC-AES256 encryption input provided by NIST's Special Publication 800-38A 2001 Edition (p.28)
        let encryption_input = nist_cbc_aes256_encryption_test_input();

        // When I initialize the low-level implementation of the aes crate
        let key = GenericArray::from(encryption_input.key);
        let iv = encryption_input.iv.clone();
        let cipher = Aes256::new(&key);

        // And I take the block #1 of NIST's input, plaintext and IV
        let block1 = encryption_input.block_at(0);
        let block1_plaintext = block1.plaintext.clone();

        // And I XOR the block's plaintext with the IV
        let xor_input = xor_128(block1_plaintext, iv);

        // Then it should match the input
        assert_equal!(xor_input, block1.input);

        let mut block1_plaintext = GenericArray::from(block1.plaintext);
        let mut block1_input = GenericArray::from(block1.input);

        // And I clone the original block input
        let block1_input_copy = block1_input.clone();

        // When I encrypt the Block #1's input in-place
        cipher.encrypt_block(&mut block1_input);

        // Then it should match the Block #1's ciphertext
        assert_equal!(
            block1_input,
            GenericArray::from(encryption_input.blocks[0].ciphertext)
        );

        // And it should also match the Block #1's output
        assert_equal!(
            block1_input,
            GenericArray::from(encryption_input.blocks[0].output)
        );

        // When I then decrypt the block in-place
        cipher.decrypt_block(&mut block1_input);

        // Then it should match the Block #1's input
        assert_equal!(
            block1_input,
            GenericArray::from(encryption_input.blocks[0].input)
        );

        // And it should match the cloned input
        assert_equal!(block1_input, block1_input_copy);
    }

    #[test]
    pub fn test_confirm_cbc_aes256_nist_spec_decrypt_single_block() {
        // Given the CBC-AES256 decryption input provided by NIST's Special Publication 800-38A 2001 Edition (p.28)
        let decryption_input = nist_cbc_aes256_decryption_test_input();

        // When I initialize the low-level implementation of the aes crate
        let key = GenericArray::from(decryption_input.key);
        let iv = decryption_input.iv.clone();
        let cipher = Aes256::new(&key);

        // And I take the block #1 of NIST's input, plaintext and IV
        let block1 = decryption_input.block_at(0);
        let block1_output = block1.output.clone();
        let block1_ciphertext = block1.ciphertext.clone();

        // And I XOR the block's output with the IV
        let xor_output = xor_128(block1_output, iv);

        // Then it should match the plaintext
        assert_equal!(xor_output, block1.plaintext);

        let mut block1_plaintext = GenericArray::from(block1.plaintext);
        let mut block1_input = GenericArray::from(block1.input);

        // And I clone the original block input
        let block1_input_copy = block1_input.clone();

        // When I decrypt the Block #1's input in-place
        cipher.decrypt_block(&mut block1_input);

        // Then it should match the Block #1's output
        assert_equal!(
            block1_input,
            GenericArray::from(decryption_input.blocks[0].output)
        );

        // And it should match the Block #1's plaintext XOR IV
        assert_equal!(
            block1_input,
            GenericArray::from(xor_128(decryption_input.blocks[0].plaintext, iv))
        );

        // When I then encrypt the block in-place
        cipher.encrypt_block(&mut block1_input);

        // Then it should match the Block #1's input
        assert_equal!(
            block1_input,
            GenericArray::from(decryption_input.blocks[0].input)
        );

        // And it should match the cloned input
        assert_equal!(block1_input, block1_input_copy);
    }

    #[test]
    pub fn test_codec_encrypt_first_block() {
        // Given the CBC-AES256 encryption input provided by NIST's Special Publication 800-38A 2001 Edition (p.28)
        let encryption_input = nist_cbc_aes256_encryption_test_input();

        // And I initialize the Aes256CbcCodec with the key and iv
        let cdc = Aes256CbcCodec::new(encryption_input.key, encryption_input.iv);

        // And I take the block #1 of NIST's input data
        let block1 = encryption_input.block_at(0);

        // When I encrypt the first Block #1's plaintext
        let encrypted_ptf = cdc.encrypt_first_block(&block1.plaintext);

        // And I encrypt the first Block #1's input with the IV as XOR block
        let encrypted_ptx = cdc.encrypt_block(&block1.plaintext, &cdc.iv);

        // Then the plaintext encrypted as "first block" should match the Block #1's ciphertext
        assert_equal!(encrypted_ptf, block1.ciphertext.to_vec());

        // And the plaintext encrypted with the IV as "XOR block" should match the Block #1's ciphertext
        assert_equal!(encrypted_ptx, block1.ciphertext.to_vec());

        // And the plaintext encrypted as "first block" should match the Block #1's output
        assert_equal!(encrypted_ptf, block1.output.to_vec());

        // And the plaintext encrypted with the IV as "XOR block" should match the Block #1's output
        assert_equal!(encrypted_ptx, block1.output.to_vec());

        // When I then decrypt ciphertext with the IV as "XOR block"
        let decrypted_ct = cdc.decrypt_block(&block1.ciphertext, &cdc.iv);

        // Then it should match the Block #1's plaintext
        assert_equal!(decrypted_ct, block1.plaintext);

        // Then it should match the Block #1's plaintext XOR IV
        assert_equal!(decrypted_ct, xor_128(block1.input, cdc.iv));
    }

    #[test]
    pub fn test_codec_decrypt_first_block() {
        // Given the CBC-AES256 decryption input provided by NIST's Special Publication 800-38A 2001 Edition (p.28)
        let decryption_input = nist_cbc_aes256_decryption_test_input();

        // And I initialize the Aes256CbcCodec with the key and iv
        let cdc = Aes256CbcCodec::new(decryption_input.key, decryption_input.iv);

        // And I take the block #1 of NIST's input data
        let block1 = decryption_input.block_at(0);

        // When I decrypt the first Block #1's input with the IV as XOR block
        let decrypted_ptx = cdc.decrypt_block(&block1.ciphertext, &decryption_input.iv);

        // And I decrypt the first Block #1's input with an zero-filled slice as XOR block
        let empty_mask = [0u8; 16];
        let decrypted_ptz = cdc.decrypt_block(&block1.ciphertext, &empty_mask);

        // Then the plaintext decrypted with the IV as "XOR block" should match the Block #1's ciphertext
        assert_equal!(decrypted_ptx, block1.plaintext.to_vec());

        // And the plaintext decrypted with the empty mark as "XOR block" should match the Block #1's output
        assert_equal!(decrypted_ptz, block1.output.to_vec());

        // When I then encrypt plaintext with the IV as "XOR block"
        let encrypted_pt = cdc.encrypt_block(&block1.plaintext, &decryption_input.iv);

        // Then it should match the Block #1's ciphertext
        assert_equal!(encrypted_pt, block1.ciphertext);

        // And it should match the Block #1's ciphertext
        assert_equal!(encrypted_pt, block1.ciphertext);
    }

    #[test]
    pub fn test_codec_aes256_cbc_transcript_nist_spec_encrypt_four_blocks() {
        // Given the CBC-AES256 encryption input provided by NIST's Special Publication 800-38A 2001 Edition (p.28)
        let encryption_input = nist_cbc_aes256_encryption_test_input();

        // And I initialize the Aes256CbcCodec with the key and iv
        let cdc = Aes256CbcCodec::new(encryption_input.key, encryption_input.iv);

        // And I combine all 4 blocks of plaintext and ciphertext into a single block
        let expected_plaintext: Vec<u8> = encryption_input
            .blocks
            .iter()
            .map(|b| b.plaintext)
            .flatten()
            .collect();
        let expected_ciphertext: Vec<u8> = encryption_input
            .blocks
            .iter()
            .map(|b| b.ciphertext)
            .flatten()
            .collect();

        // When I encrypt the combined plaintext
        let ciphertext = cdc.encrypt_blocks(&expected_plaintext);
        // Then the result should match the combined ciphertext
        assert_equal!(ciphertext, expected_ciphertext);

        // When I decrypt the ciphertext
        let plaintext = cdc.decrypt_blocks(&ciphertext);
        // Then the result should match the combined plaintext
        assert_equal!(plaintext, expected_plaintext);
    }

    #[test]
    pub fn test_codec_aes256_cbc_transcript_arbitraryly_sized_buffer() {
        // Background: I have a key and IV
        let key = [71u8; 32];
        let iv = [84u8; 16];

        // Background: There is a buffer whose length has a remainder with modulus 16
        let plaintext = read_bytes("tests/plaintext.jpg").unwrap();
        let plaintext_length = plaintext.len();

        // Given I initialize a Aes256CbcCodec with a key and IV
        let cdc = Aes256CbcCodec::new(key, iv);

        // When I encrypt the combined plaintext
        let ciphertext = cdc.encrypt_blocks(&plaintext);

        // And subsequently decrypt that ciphertext
        let decrypted = cdc.decrypt_blocks(&ciphertext);

        // Then the result should match the original plaintext
        assert_equal!(decrypted.len() - plaintext_length, 0);
        assert_equal!(decrypted.len(), plaintext_length);
        assert_equal!(plaintext, decrypted);
    }
    #[test]
    pub fn test_codec_aes256_cbc_encrypt_pbkdf2_key_and_iv() {
        // Background: I have a key and IV
        let key = pbkdf2_sha384_256bits(b"cypher where is tank?", b"soul society", 83);
        let iv = pbkdf2_sha384_128bits(b"84 + 4(vier(six-he/saw him/vejo ele/vejo him/vejo rim(kidney - human organ that processes fear))((fear / four + fe' ar + avatar))) == X == ascii code 88", b"GO = 'George Orwell' = 4 in japanese. O shit we're back on fear...", 88); // XXX rs

        // Background: There is a buffer whose length has a remainder with modulus 16
        let plaintext = read_bytes("tests/plaintext.jpg").unwrap();
        let plaintext_length = plaintext.len();

        // Given I initialize a Aes256CbcCodec with a key and IV
        let cdc = Aes256CbcCodec<T>::new(key, iv);

        // When I encrypt the combined plaintext
        let ciphertext = cdc.encrypt_blocks(&plaintext);

        // And subsequently decrypt that ciphertext
        let decrypted = cdc.decrypt_blocks(&ciphertext);

        // Then the result should match the original plaintext
        assert_equal!(decrypted.len() - plaintext_length, 0);
        assert_equal!(decrypted.len(), plaintext_length);
        assert_equal!(plaintext, decrypted);
    }
}
