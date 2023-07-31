use crate::aescbc::tp::{B128, B256};
use crate::errors::Error;
// use crate::aescbc::tp::{b128_to_u64, b256_to_u128};

use serde::{Deserialize, Serialize};
use std::fmt;

pub trait Config {
    fn default() -> Self;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AesCbcPaddingMethod {
    Ansix923,
}

impl Config for AesCbcPaddingMethod {
    fn default() -> AesCbcPaddingMethod {
        AesCbcPaddingMethod::Ansix923
    }
}
impl fmt::Display for AesCbcPaddingMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
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

impl Config for AesCbcPaddingConfig {
    fn default() -> AesCbcPaddingConfig {
        AesCbcPaddingConfig::new(0xff, AesCbcPaddingMethod::default())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Pbkdf2BlockLength {
    L128,
    L256,
}

impl Pbkdf2BlockLength {
    pub fn get(&self) -> usize {
        match self {
            Pbkdf2BlockLength::L128 => 128 / 8,
            Pbkdf2BlockLength::L256 => 256 / 8,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Pbkdf2Config {
    password: String,
    salt: String,
    iterations: u32,
    length: Pbkdf2BlockLength,
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
        assert_equal!(serialized, "key: '4747474747474747474747474747474747474747474747474747474747474747'\niv: '54545454545454545454545454545454'\npadding:\n  method: Ansix923\n  padbyte: 37\n");

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
        let serialized = "key: 'acacacacacacacacacacacacacacacacacacacacacacacacacacac'\niv: 'aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae'\npadding:\n  method: Ansix923\n  padbyte: 165\n";
        let deserialized: Aes256CbcConfig = serde_yaml::from_str(&serialized).unwrap();
        deserialized.get_key().unwrap();
    }

    #[test]
    #[should_panic(expected = "odd length")]
    pub fn test_deserialize_invalid_iv_size_odd_length() {
        let serialized = "key: '4747474747474747474747474747474747474747474747474747474747474747'\niv: '4'\npadding:\n  method: Ansix923\n  padbyte: 42\n";
        let deserialized: Aes256CbcConfig = serde_yaml::from_str(&serialized).unwrap();
        deserialized.get_iv().unwrap();
    }

    #[test]
    #[should_panic(expected = "iv length is 1 instead of 16 for string 04")]
    pub fn test_deserialize_invalid_iv_size() {
        let serialized = "key: '4747474747474747474747474747474747474747474747474747474747474747'\niv: '04'\npadding:\n  method: Ansix923\n  padbyte: 42\n";
        let deserialized: Aes256CbcConfig = serde_yaml::from_str(&serialized).unwrap();
        deserialized.get_iv().unwrap();
    }
}
