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

pub use crate::aescbc::kd::pbkdf2_sha384_128bits;
pub use crate::aescbc::kd::pbkdf2_sha384_256bits;
pub use crate::aescbc::kd::pbkdf2_sha384;
pub use crate::aescbc::kd::pbkdf2_sha512;
pub use crate::aescbc::kd::pbkdf2_sha512_256bits;
pub use crate::aescbc::kd::pbkdf2_sha256;
pub use crate::aescbc::kd::DerivationScheme;
pub use crate::aescbc::pad::Ansix923;
pub use crate::aescbc::pad::Padder128;
pub use crate::aescbc::pad::Padding;
pub use crate::aescbc::tp::{B128, B256};
pub use crate::errors::Error;
pub use crate::hashis::gcrc128;
pub use crate::hashis::gcrc256;
pub use crate::ioutils::{absolute_path, open_write, read_bytes, read_bytes_high_water_mark};
use hex;
use rand::prelude::*;

use aes::cipher::{
    // generic_array::{GenericArray, ArrayLength, typenum::U8};
    generic_array::GenericArray,
    BlockDecrypt,
    BlockEncrypt,
    KeyInit,
};
use aes::Aes256;
use std::io::Write;
use std::path::Path;

pub trait EncryptionEngine {
    fn encrypt_block(&self, plaintext: &[u8], xor_block: &[u8]) -> Vec<u8>;
    fn decrypt_block(&self, ciphertext: &[u8], xor_block: &[u8]) -> Vec<u8>;
    fn encrypt_blocks(&self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt_blocks(&self, ciphertext: &[u8]) -> Vec<u8>;
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Aes256Key {
    pub version: String,
    pub cycles: Option<u64>,
    pub key: String,
    pub iv: String,
    pub blob: String,
    name: Option<String>,
}

// MaGic PreFix
pub const AESMGPF: [u8; 8] = [0x1f, 0x8b, 0x08, 0x08, 0x61, 0x58, 0x37, 0x65];
pub const VRSBUF: [u8; 12] = [
    0x00, 0x00, 0x00, 0b00000011, // 3.
    0x00, 0x00, 0x00, 0b00000000, // 0.
    0x00, 0x00, 0x00, 0b00000001, // 1
];
pub const BLOBMINL: u64 = 237;
pub const MK1: [u8; 8] = [0x01, 0x05, 0x16, 0x10, 0x50, 0x11, 0x0a, 0x12];
pub const MK0: [u8; 4] = [0x26, 0x7b, 0xfe, 0x0e];

fn getcurrentversion() -> String {
    format!("obg-v{}", env!("CARGO_PKG_VERSION"))
}

pub fn match_prefix(magicpfx: &[u8]) -> bool {
    magicpfx.to_vec() == AESMGPF.to_vec()
}
// signs https://github.com/openbsd/src/blob/1835b44f319c9f17642bb957cc6602d2762cc3ae/sys/sys/signal.h#L51-L99

impl Aes256Key {
    pub fn skey(&self) -> B256 {
        let mut skey: B256 = [0x0; 32];
        skey.copy_from_slice(&hex::decode(self.key.as_bytes()).expect(&format!("{} key appears to be an invalid hex", match &self.name {
            Some(name) => format!("{:?} ", name),
            None => format!("")
        }))[..32]);
        skey
    }
    pub fn siv(&self) -> B128 {
        let mut siv: B128 = [0x0; 16];
        siv.copy_from_slice(&hex::decode(self.iv.as_bytes()).expect(&format!("{} iv appears to be an invalid hex", match &self.name {
            Some(name) => format!("{:?} ", name),
            None => format!("")
        }))[..16]);
        siv
    }
    pub fn sblob(&self) -> Vec<u8> {
        match hex::decode(&self.blob) {
            Ok(blob) => blob.clone(),
            Err(e) => format!("{}", e).as_bytes().to_vec()
        }
    }

    pub fn with_name(&self, name: String) -> Result<Aes256Key, Error> {
        match &self.name {
            Some(name) => Err(Error::KeyError(format!("key already named: {}", name))),
            None => Ok(Aes256Key {
                name: Some(name),
                key: self.key.clone(),
                iv: self.iv.clone(),
                blob: self.blob.clone(),
                cycles: self.cycles.clone(),
                version: self.version.clone(),
            })
        }
    }
    pub fn new(key: B256, iv: B128, blob: &[u8], cycles: u64) -> Aes256Key {
        Aes256Key {
            name: None,
            key: hex::encode(key),
            iv: hex::encode(iv),
            blob: hex::encode(blob),
            cycles: Some(cycles),
            version: getcurrentversion(),
        }
    }
    pub fn derive_with_name(
        name: &str,
        passwords: Vec<String>,
        password_hwm: u64,
        salts: Vec<String>,
        salt_hwm: u64,
        cycles: u64,
        salt_derivation_scheme: DerivationScheme,
        shuffle_iv: bool,
        blob_length: Option<u64>,
    ) -> Result<Aes256Key, Error> {
        let name = match Path::new(name).file_name() {
            Some(filename) => format!("{}", filename.to_string_lossy()),
            None => name.to_string(),
        };


        Self::derive(
            passwords,
            password_hwm,
            salts,
            salt_hwm,
            cycles,
            salt_derivation_scheme,
            shuffle_iv,
            blob_length,
        )?.with_name(name.to_string())
    }
    pub fn derive(
        passwords: Vec<String>,
        password_hwm: u64,
        salts: Vec<String>,
        salt_hwm: u64,
        cycles: u64,
        salt_derivation_scheme: DerivationScheme,
        shuffle_iv: bool,
        blob_length: Option<u64>,
    ) -> Result<Aes256Key, Error> {
        let mut password = Vec::<u8>::new();
        for sec in passwords {
            password.extend(if Path::new(&sec).exists() {
                read_bytes_high_water_mark(&sec, password_hwm)?
            } else {
                sec.as_str().as_bytes().to_vec()
            });
        }

        let mut salt = Vec::<u8>::new();
        for st in salts {
            salt.extend(if Path::new(&st).exists() {
                read_bytes_high_water_mark(&st, salt_hwm)?
            } else {
                st.as_str().as_bytes().to_vec()
            });
        }
        let mut rng = thread_rng();
        let len = match blob_length {
            Some(bl) => if bl < BLOBMINL {
                return Err(Error::NonValidKey(format!("blob length too small: {} (min {})", bl, BLOBMINL)));
            } else {
                bl
            },
            None => {
                let mut mods: Vec<u64> = (BLOBMINL..1283).collect();
                mods.shuffle(&mut rng);
                mods[0]
            }
        };

        let mut key = [0xa; 32];
        key.copy_from_slice(&salt_derivation_scheme.derive(&salt, &password, cycles as u32));
        let mut blob = Vec::<u8>::new();
        blob.resize(len as usize, 0xa);
        let mut tmp = Vec::<u8>::new();
        tmp.extend(&gcrc256(&password));
        tmp.reverse();
        tmp.extend(&gcrc128(&salt));
        blob.extend(&gcrc256(&tmp[..37]));
        while blob.len() < len as usize + 16 {
            blob.extend(&gcrc256(&tmp[..37]));
            blob.reverse();
        }
        let mut iv = [0; 16];
        iv.copy_from_slice(&blob.drain(..16).collect::<Vec<u8>>());
        let blob = blob[..len as usize].to_vec();
        if shuffle_iv {
            iv.shuffle(&mut rng);
        }
        Ok(Aes256Key::new(key, iv, &blob, cycles))
    }
    pub fn load_from_file(
        filename: String,
        strict: bool,
        key_offset: Option<usize>,
        salt_offset: Option<usize>,
        blob_offset: Option<usize>,
        moo: bool,
    ) -> Result<Aes256Key, Error> {
        let mut bytes = read_bytes(&filename)?;
        if key_offset== None && salt_offset == None && blob_offset == None && moo == false {
            let mut lhs = bytes.len() - 16;
            let siv: Vec<u8> = bytes.drain(lhs..).collect();

            lhs -= 32;
            let skey: Vec<u8> = bytes.drain(lhs..).collect();

            lhs -= 8;
            let cycles =
                Some(match u64::from_str_radix(&hex::encode(bytes.drain(lhs..).collect::<Vec<u8>>()), 16) {
                    Ok(c) => c,
                    Err(e) => return Err(Error::NonValidKey(format!("invalid cycles: {}", e)))
                });

            lhs -= 4;
            let mk0: Vec<u8> = bytes.drain(lhs..).collect();
            if strict {assert_eq!(mk0, MK0);}

            lhs -= 8;

            let mk1: Vec<u8> = bytes.drain(lhs..).collect();
            if strict {assert_eq!(mk1, MK1);}

            lhs -= 12;

            let vrsbuf: Vec<u8> = bytes.drain(lhs..).collect();
            let version = format!(
                "obg-v{}.{}.{}",
                vrsbuf[3],
                vrsbuf[7],
                vrsbuf[11],
            );
            if strict {assert_eq!(vrsbuf, VRSBUF);}

            lhs -=  8;
            let len: usize =
                u64::from_str_radix(&hex::encode(bytes.drain(lhs..).collect::<Vec<u8>>()), 16)? as usize;

            let blob = if len > lhs {
                if strict {
                    return Err(Error::KeyError(format!("invalid blob length in binary key: {}", len)));
                } else {
                    bytes.clone()
                }
            } else {
                lhs -= len;
                bytes.drain(lhs..).collect::<Vec<u8>>().to_vec()
            };

            lhs = if lhs <=4 {
                if strict {
                    return Err(Error::KeyError(format!("invalid blob length in binary key: {}", len)));
                } else {
                    lhs
                }
            } else {
                match moo {
                    true => lhs / 2,
                    false => lhs,
                }
            } - 4;

            let ebytes = bytes.drain(lhs..).collect::<Vec<u8>>().to_vec();
            if strict {assert_eq!(ebytes, [0x00, 0x00, 0x00, 0x00]);}
            let aesmgpf =  bytes.drain(..8).collect::<Vec<u8>>().to_vec();
            if strict {assert_eq!(aesmgpf, AESMGPF.to_vec());}
            let fname = bytes.to_vec();

            return Ok(Aes256Key {
                key: hex::encode(skey),
                iv: hex::encode(siv),
                blob: hex::encode(blob),
                version: version,
                cycles: cycles,
                name: match String::from_utf8(fname) {
                    Ok(i) => Some(i),
                    Err(_) => None
                },
            })
        } else {
            let mut ml: usize = (bytes.len() / 3) - 84;
            ml = match key_offset {
                Some(o) => {
                    if o > ml {
                        o
                    } else {
                        ml
                    }
                }
                None => ml,
            };
            ml = match salt_offset {
                Some(o) => {
                    if o > ml {
                        o
                    } else {
                        ml
                    }
                }
                None => ml,
            };
            ml = match blob_offset {
                Some(o) => {
                    if o > ml {
                        o
                    } else {
                        ml
                    }
                }
                None => ml,
            };
            if match moo {
                true => bytes.len() / 2,
                false => bytes.len(),
            } < ml
            {
                return Err(Error::FileSystemError(format!(
                    "{} is too small for the set of constraints",
                    filename
                )));
            }

            let mut lhs = (match moo {
                true => bytes.len() / 2,
                false => bytes.len(),
            }) - 16
                - match salt_offset {
                    Some(o) => o,
                    None => 0,
                };

            let siv: Vec<u8> = bytes.drain(lhs..).collect();

            lhs = (match moo {
                true => lhs / 2,
                false => lhs,
            }) - 32
                - match key_offset {
                    Some(o) => o,
                    None => 0,
                };
            let skey: Vec<u8> = bytes.drain(lhs..).collect();

            let blob = bytes.drain(lhs..).collect::<Vec<u8>>().to_vec();

            return Ok(Aes256Key {
                key: hex::encode(skey),
                iv: hex::encode(siv),
                blob: hex::encode(blob),
                version: format!("confidential"),
                cycles: Some(74),
                name: None,
            });
        }
    }
    pub fn save_to_file(&self, filename: String) -> Result<(), Error> {
        let mut file = open_write(&filename)?;
        file.write_all(&AESMGPF.to_vec())?;
        file.write_all(
            match Path::new(&filename).file_name() {
                Some(filename) => format!("{}", filename.to_string_lossy()),
                None => filename.clone(),
            }
            .as_str()
            .as_bytes(),
        )?;
        file.write_all(&[0x00, 0x00, 0x00, 0x00])?;
        let blob = hex::decode(&self.blob)?;
        let len = blob.len();

        file.write_all(&blob)?;
        file.write_all(&hex::decode(&format!("{:016x}", len))?)?;

        file.write_all(&VRSBUF)?;
        file.write_all(&MK1)?;
        file.write_all(&MK0)?;
        file.write_all(&hex::decode(&format!(
            "{:016x}",
            match self.cycles {
                Some(c) => c,
                None => 0,
            }
        ))?)?;
        file.write_all(&self.skey())?;
        file.write_all(&self.siv())?;
        Ok(())
    }
    pub fn save_to_yaml_file(&self, filename: String) -> Result<(), Error> {
        let mut file = open_write(&filename)?;
        let yaml = serde_yaml::to_string(self)?;
        Ok(file.write_all(yaml.as_bytes())?)
    }
    pub fn load_from_yaml_file(filename: String) -> Result<Aes256Key, Error> {
        let bytes = read_bytes(&filename)?;
        let key: Aes256Key = serde_yaml::from_slice(&bytes)?;
        Ok(key)
    }
}

#[derive(Debug, Clone)]
pub struct Aes256CbcCodec {
    cipher: Aes256,
    key: B256,
    iv: B128,
    padding: Padding,
}

impl Aes256CbcCodec {
    pub fn new(key: B256, iv: B128) -> Aes256CbcCodec {
        let padding = Padding::Ansix923(Ansix923::new(0xff as u8));
        Aes256CbcCodec::new_with_padding(key, iv, padding)
    }
    pub fn new_with_padding(key: B256, iv: B128, padding: Padding) -> Aes256CbcCodec {
        let gkey = GenericArray::from(key);
        Aes256CbcCodec {
            cipher: Aes256::new(&gkey),
            key: key,
            iv: iv,
            padding: padding,
        }
    }
    pub fn new_with_key(key: Aes256Key) -> Aes256CbcCodec {
        let padding = Padding::Ansix923(Ansix923::new(0xff as u8));
        let gkey = key.skey();
        let giv = key.siv();
        Aes256CbcCodec {
            cipher: Aes256::new(&GenericArray::from(gkey)),
            key: gkey,
            iv: giv,
            padding: padding,
        }
    }
    pub fn encrypt_first_block(&self, input_block: &[u8]) -> Vec<u8> {
        self.encrypt_block(input_block, &self.iv)
    }
    pub fn cipher(&self) -> Aes256 {
        Aes256::new(&(self.key).into())
    }
}

impl EncryptionEngine for Aes256CbcCodec {
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
            let block = &if index == last_block_pos && block.len() < 16 {
                // ensure padding in the last block to avoid side-effects
                self.padding.pad(&block).to_vec()
            } else {
                block.to_vec()
            };
            result.push(self.encrypt_block(block, xor_block));
        }
        let opaque: Vec<u8> = result.iter().flatten().map(|b| b.clone()).collect();
        // let mut ciphertext = Vec::<u8>::new();
        // ciphertext.extend(self.magic_id());
        // ciphertext.extend(opaque);
        // ciphertext
        opaque
    }
    fn decrypt_blocks(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        // split ciphertext into 16 blocks
        let chunks: Vec<Vec<u8>> = ciphertext.chunks(16).map(|c| c.to_vec()).collect();
        let count = chunks.len();
        let last_block_pos = count - 1;

        for (index, block) in chunks.iter().enumerate() {
            let xor_block = if index == 0 {
                &self.iv
            } else {
                chunks[index - 1].as_slice()
            };
            let block = self.decrypt_block(block, xor_block);
            result.push(if index == last_block_pos {
                // ensure padding in the last block to avoid side-effects
                self.padding.unpad(&block)
            } else {
                block
            });
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
    use crate::aescbc::cdc::{xor_128, Aes256CbcCodec, Aes256Key, EncryptionEngine, B128, B256};
    use crate::aescbc::cdc::{AESMGPF, MK0, MK1};
    use crate::aescbc::kd::pbkdf2_sha384_128bits;
    use crate::aescbc::kd::pbkdf2_sha384_256bits;
    use crate::aescbc::kd::DerivationScheme;
    use crate::aescbc::kd::Pbkdf2HashingAlgo;
    use crate::hashis::CrcAlgo;
    use crate::ioutils::read_bytes;
    use crate::aescbc::VRSBUF;

    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
    use aes::Aes256;
    use k9::assert_equal;
    use serde::{Deserialize, Serialize};
    // use crate::errors::Error;
    use glob::glob;

    // use std::str::FromStr;

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

    fn cleanup(paths: &[&str]) {
        for path in paths {
            if let Ok(paths) = glob(&path) {
                for path in paths {
                    match path {
                        Ok(path) => {
                            std::fs::remove_file(path.clone()).unwrap_or(());
                            eprintln!("deleted {}", path.display());
                        },
                        Err(e) => {
                            eprintln!("\x1b[1;38;5;160mdeleted {}\x1b[0m", e);

                        }
                    }
                }
            }
        }
    }
    pub fn nist_cbc_aes256_encryption_test_input() -> Aes256CBCTestCase {
        // https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
        // p.28 - # F.2.5 CBC-AES256.Encrypt Vectors
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
        // https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
        // p.29 - # F.2.6 CBC-AES256.Decrypt Vectors
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
    pub fn test_vrsbuf() {
        assert_equal!(VRSBUF.to_vec(), vec![
            0x00, 0x00, 0x00, 0b00000011, // 3.
            0x00, 0x00, 0x00, 0b00000000, // 0.
            0x00, 0x00, 0x00, 0b00000001, // 1
        ]);
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

        // And I XOR the block's output with the IV
        let xor_output = xor_128(block1_output, iv);

        // Then it should match the plaintext
        assert_equal!(xor_output, block1.plaintext);

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
    pub fn test_codec_aes256_cbc_encrypt_derive() {
        // Background: I have a Aes256Key
        let password = "cypher where is tank?".to_string();
        let salt = "soul society".to_string();
        let key = Aes256Key::derive(
            [password].to_vec(),
            u64::MAX,
            [salt].to_vec(),
            u64::MAX,
            0x35,
            DerivationScheme::Crc(CrcAlgo::GcRc256),
            false,
            None
        )
        .expect("it appears that the key cannot be derived in this instant");

        // Background: There is a buffer whose length has a remainder with modulus 16
        let plaintext = read_bytes("tests/plaintext.jpg").unwrap();
        let plaintext_length = plaintext.len();

        // Given I initialize a Aes256CbcCodec with a Aes256Key
        let cdc = Aes256CbcCodec::new_with_key(key);

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
    pub fn test_save_to_opaque_file() {
        // -> Result<(), Error>{
        cleanup(&["tests/*.kgz"]);
        let password = "arriviami".to_string();
        let salt = "capiti".to_string();
        let key = Aes256Key::derive(
            [password].to_vec(),
            u64::MAX,
            [salt].to_vec(),
            u64::MAX,
            0x35,
            DerivationScheme::Crc(CrcAlgo::GcRc256),
            false,
            None
        )
            .unwrap();
        let filename = format!("obg-key{}.kgz", rand::random::<u16>());
        let path = format!("tests/{}", &filename);
        key.save_to_file(path.clone()).unwrap();

        let mut kdatum = std::fs::read(&path).unwrap();

        let mut lhs = kdatum.len() - 16;
        let siv: Vec<u8> = kdatum.drain(lhs..).collect();
        assert_equal!(siv.to_vec(), key.siv().to_vec());

        lhs -= 32;
        let skey: Vec<u8> = kdatum.drain(lhs..).collect();
        assert_equal!(skey.to_vec(), key.skey().to_vec());

        lhs -= 8;
        let cycles =
            u64::from_str_radix(&hex::encode(kdatum.drain(lhs..).collect::<Vec<u8>>()), 16)
                .unwrap();
        assert_equal!(Some(cycles), key.cycles);

        lhs -= 4;
        let mk0: Vec<u8> = kdatum.drain(lhs..).collect();
        assert_equal!(mk0.to_vec(), MK0.to_vec());

        lhs -= 8;
        let mk1: Vec<u8> = kdatum.drain(lhs..).collect();
        assert_eq!(mk1.to_vec(), MK1.to_vec(),);

        lhs -= 12;
        let version: Vec<u8> = kdatum.drain(lhs..).collect();
        assert_equal!(
            version.to_vec(),
            vec![0x00, 0x00, 0x00, 0b00000011, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0b00000001]
        );

        lhs -= 8;
        let len: usize =
            u64::from_str_radix(&hex::encode(kdatum.drain(lhs..).collect::<Vec<u8>>()), 16)
                .unwrap() as usize;
        assert!(len >= 237 && len <= 1283);
        lhs -= len;
        assert_equal!(
            kdatum.drain(lhs..).collect::<Vec<u8>>().to_vec().len(),
            len
        );

        lhs -= 4;
        assert_equal!(
            kdatum.drain(lhs..).collect::<Vec<u8>>().to_vec(),
            vec![0x00, 0x00, 0x00, 0x00]
        );
        assert_equal!(kdatum.drain(..8).collect::<Vec<u8>>().to_vec(), AESMGPF);
        assert_equal!(kdatum.to_vec(), filename.as_bytes().to_vec());
        // Ok(())
    }
    #[test]
    pub fn test_opaque_save_open_blob_lennone() {
        // -> Result<(), Error>{
        cleanup(&["tests/*.kgz"]);
        let filename = format!("obg-key{}.kgz", rand::random::<u16>());
        let path = format!("tests/{}", &filename);

        let password = "arriviami".to_string();
        let salt = "capiti".to_string();
        let key = Aes256Key::derive_with_name(
            &filename,
            [password].to_vec(),
            u64::MAX,
            [salt].to_vec(),
            u64::MAX,
            0x35,
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512),
            false,
            None
        )
        .unwrap();
        key.save_to_file(path.clone()).unwrap();
        let ck = Aes256Key::load_from_file(path, true, None, None, None, false).unwrap();
        assert_equal!(ck.siv(), key.siv());
        assert_equal!(ck.skey(), key.skey());
        assert_equal!(ck.sblob().len(), key.sblob().len());
        assert_equal!(ck.sblob(), key.sblob());
        assert_equal!(key, ck);
    }
    #[test]
    pub fn test_opaque_save_open_bloblenset() {
        // -> Result<(), Error>{
        cleanup(&["tests/*.kgz"]);
        let filename = format!("obg-key{}.kgz", rand::random::<u16>());
        let path = format!("tests/{}", &filename);

        let password = "arriviami".to_string();
        let salt = "capiti".to_string();
        let key = Aes256Key::derive_with_name(
            &path,
            [password].to_vec(),
            u64::MAX,
            [salt].to_vec(),
            u64::MAX,
            0x35,
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512),
            false,
            Some(325)
        )
        .unwrap();
        key.save_to_file(path.clone()).unwrap();
        let ck = Aes256Key::load_from_file(path, true, None, None, None, false).unwrap();
        assert_equal!(ck.siv(), key.siv());
        assert_equal!(ck.skey(), key.skey());
        assert_equal!(ck.sblob().len(), key.sblob().len());
        assert_equal!(ck.sblob(), key.sblob());
        assert_equal!(key, ck);
    }
    #[test]
    pub fn test_opaque_save_open_bloblenbehindmin() {
        // -> Result<(), Error>{
        cleanup(&["tests/*.kgz"]);
        let filename = format!("obg-key{}.kgz", rand::random::<u16>());
        let path = format!("tests/{}", &filename);

        let password = "arriviami".to_string();
        let salt = "capiti".to_string();
        let result = Aes256Key::derive_with_name(
            &path,
            [password].to_vec(),
            u64::MAX,
            [salt].to_vec(),
            u64::MAX,
            0x35,
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512),
            false,
            Some(33)
        );

        assert_eq!(match result {
            Ok(hey) => {
                format!("notanerror: {:?}", hey)
            },
            Err(e) => {
                format!("{}", e)
            }
        }, format!("InvalidVersion: blob length too small: 33 (min 237)"));
    }
}
