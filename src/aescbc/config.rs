use crate::aescbc::tp::{B128, B256};
use crate::errors::Error;
use crate::serial::YamlFile;
// use crate::aescbc::tp::{b128_to_u64, b256_to_u128};

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AesCbcPaddingMethod {
    #[serde(rename = "padding_ansix923")]
    Ansix923,
}

impl YamlFile for AesCbcPaddingMethod {
    fn default() -> Result<AesCbcPaddingMethod, Error> {
        Ok(AesCbcPaddingMethod::Ansix923)
    }
}

impl fmt::Display for AesCbcPaddingMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "padding_{}",
            match self {
                AesCbcPaddingMethod::Ansix923 => "ansix923",
            }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AesCbcPaddingConfig {
    method: AesCbcPaddingMethod,
    padbyte: u8,
}
impl AesCbcPaddingConfig {
    pub fn new(padbyte: u8, method: AesCbcPaddingMethod) -> AesCbcPaddingConfig {
        AesCbcPaddingConfig { method, padbyte }
    }
}

impl YamlFile for AesCbcPaddingConfig {
    fn default() -> Result<AesCbcPaddingConfig, Error> {
        Ok(AesCbcPaddingConfig::new(
            0xff,
            AesCbcPaddingMethod::default()?,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Pbkdf2BlockLength {
    #[serde(rename = "128bits")]
    L128,
    #[serde(rename = "256bits")]
    L256,
}
impl fmt::Display for Pbkdf2BlockLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Pbkdf2BlockLength::L128 => "128bits",
                Pbkdf2BlockLength::L256 => "256bits",
            }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Pbkdf2HashingAlgo {
    #[serde(rename = "pbkdf2_sha3_256")]
    Sha3_256,
    #[serde(rename = "pbkdf2_sha3_384")]
    Sha3_384,
    #[serde(rename = "pbkdf2_sha3_512")]
    Sha3_512,
}

impl fmt::Display for Pbkdf2HashingAlgo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "pbkdf2_{}",
            match self {
                Pbkdf2HashingAlgo::Sha3_256 => "sha3_256",
                Pbkdf2HashingAlgo::Sha3_384 => "sha3_384",
                Pbkdf2HashingAlgo::Sha3_512 => "sha3_512",
            }
        )
    }
}

impl YamlFile for Pbkdf2HashingAlgo {
    fn default() -> Result<Pbkdf2HashingAlgo, Error> {
        Ok(Pbkdf2HashingAlgo::Sha3_384)
    }
}



impl Pbkdf2BlockLength {
    pub fn get(&self) -> usize {
        match self {
            Pbkdf2BlockLength::L128 => 128 / 8,
            Pbkdf2BlockLength::L256 => 256 / 8,
        }
    }
}

pub trait Pbkdf2Hasher<Block> {
    fn pbkdf2_hash(pw: &[u8], st: &[u8], it: u32) -> Block;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Pbkdf2Config {
    pub password: String,
    pub password_hashing: Pbkdf2HashingAlgo,
    pub salt: String,
    pub salt_hashing: Pbkdf2HashingAlgo,
    pub iterations: u32,
    pub length: Pbkdf2BlockLength,
}
impl YamlFile for Pbkdf2Config {
    fn default() -> Result<Pbkdf2Config, Error> {
        Ok(Pbkdf2Config {
            password: String::new(),
            password_hashing: Pbkdf2HashingAlgo::default()?,
            salt: String::new(),
            salt_hashing: Pbkdf2HashingAlgo::default()?,
            iterations: 1337,
            length: Pbkdf2BlockLength::L128,
        })
    }
}

// impl Pbkdf2Config {
//     pub fn for_key_from_file(password_file: &Path, salt_file: Path) -> Pbkdf2Config {
//         Pbkdf2Config {
//         }
//     }
// }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Aes256CbcConfig {
    // key: u128,
    // iv: u64,
    key: String,
    iv: String,
    padding: AesCbcPaddingConfig,
}

impl Aes256CbcConfig {
    pub fn new(padbyte: u8, key: B256, iv: B128) -> Aes256CbcConfig {
        let key = hex::encode(key);
        let iv = hex::encode(iv);
        Aes256CbcConfig {
            padding: AesCbcPaddingConfig::new(padbyte, AesCbcPaddingMethod::Ansix923),
            key,
            iv,
        }
    }

    pub fn get_key(&self) -> Result<B256, Error> {
        let mut result: B256 = [0u8; 32];
        let vc = hex::decode(self.key.clone())?;
        let keylen = vc.len();
        if keylen != 32 {
            return Err(Error::InvalidAes256KeySize(format!(
                "key length is {} instead of 32 for string {}",
                keylen,
                self.key.clone()
            )));
        }
        result.copy_from_slice(&vc[..32]);
        Ok(result)
    }

    pub fn get_iv(&self) -> Result<B128, Error> {
        let mut result: B128 = [0u8; 16];
        let hf = hex::decode(self.iv.clone())?;
        let ivlen = hf.len();
        if ivlen != 16 {
            return Err(Error::InvalidAesIvSize(format!(
                "iv length is {} instead of 16 for string {}",
                ivlen,
                self.iv.clone()
            )));
        }
        result.copy_from_slice(&hf[..16]);
        Ok(result)
    }

    // pub fn new_from_external_files(padbyte: u8, key_file: Path, iv_file: Path) -> Aes256CbcConfig {
    //     Aes256CbcConfig {

    //     }
    // }
}

#[cfg(test)]
mod aescbcconfig_tests {
    use crate::aescbc::config::Aes256CbcConfig;
    use crate::errors::Error;
    use k9::assert_equal;

    #[test]
    pub fn test_basic_serialization_deserialization() -> Result<(), Error> {
        let config = Aes256CbcConfig::new(37, [0x47; 32], [0x54; 16]);

        let serialized = serde_yaml::to_string(&config).unwrap();
        assert_equal!(serialized, "key: '4747474747474747474747474747474747474747474747474747474747474747'\niv: '54545454545454545454545454545454'\npadding:\n  method: padding_ansix923\n  padbyte: 37\n");

        let deserialized: Aes256CbcConfig = serde_yaml::from_str(&serialized).unwrap();
        assert_equal!(deserialized, config);
        assert_equal!(deserialized.get_key()?, [0x47; 32]);
        assert_equal!(deserialized.get_iv()?, [0x54; 16]);
        Ok(())
    }

    #[test]
    #[should_panic(
        expected = "key length is 27 instead of 32 for string acacacacacacacacacacacacacacacacacacacacacacacacacacac"
    )]
    pub fn test_deserialize_invalid_key_size() {
        let serialized = "key: 'acacacacacacacacacacacacacacacacacacacacacacacacacacac'\niv: 'aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae'\npadding:\n  method: padding_ansix923\n  padbyte: 165\n";
        let deserialized: Aes256CbcConfig = serde_yaml::from_str(&serialized).unwrap();
        deserialized.get_key().unwrap();
    }

    #[test]
    #[should_panic(expected = "odd length")]
    pub fn test_deserialize_invalid_iv_size_odd_length() {
        let serialized = "key: '4747474747474747474747474747474747474747474747474747474747474747'\niv: '4'\npadding:\n  method: padding_ansix923\n  padbyte: 42\n";
        let deserialized: Aes256CbcConfig = serde_yaml::from_str(&serialized).unwrap();
        deserialized.get_iv().unwrap();
    }

    #[test]
    #[should_panic(expected = "iv length is 1 instead of 16 for string 04")]
    pub fn test_deserialize_invalid_iv_size() {
        let serialized = "key: '4747474747474747474747474747474747474747474747474747474747474747'\niv: '04'\npadding:\n  method: padding_ansix923\n  padbyte: 42\n";
        let deserialized: Aes256CbcConfig = serde_yaml::from_str(&serialized).unwrap();
        deserialized.get_iv().unwrap();
    }
}
