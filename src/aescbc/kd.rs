pub use crate::aescbc::config::Pbkdf2HashingAlgo;
use crate::aescbc::tp::B128;
use crate::aescbc::tp::B256;
use crate::errors::Error;
use crate::hashis::{gcrc128, gcrc256, CrcAlgo};
use crate::serial::YamlFile;
use clap::builder::PossibleValue;
use clap::ValueEnum;
use pbkdf2::pbkdf2_hmac;
use serde::{self, Deserialize, Serialize};
use sha3::Sha3_256 as Sha256;
use sha3::Sha3_384 as Sha384;
use sha3::Sha3_512 as Sha512;
use std::fmt;

pub fn pbkdf2_sha256(data: &[u8], st: &[u8], it: u32, length: usize) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(length);
    key.resize(length, 0x00);
    let mut key = key.as_mut_slice();
    pbkdf2_hmac::<Sha256>(data, st, it, &mut key);
    key.to_vec()
}

pub fn pbkdf2_sha256_128bits(data: &[u8], st: &[u8], it: u32) -> B128 {
    let mut result: B128 = [0x0; 16];
    let key = pbkdf2_sha256(data, st, it, 256);
    for chunk in key.chunks(16) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

pub fn pbkdf2_sha256_256bits(data: &[u8], st: &[u8], it: u32) -> B256 {
    let mut result: B256 = [0x0; 32];
    let key = pbkdf2_sha256(data, st, it, 256);
    for chunk in key.chunks(32) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

pub fn pbkdf2_sha384(data: &[u8], st: &[u8], it: u32, length: usize) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(length);
    key.resize(length, 0x00);
    let mut key = key.as_mut_slice();
    pbkdf2_hmac::<Sha384>(data, st, it, &mut key);
    key.to_vec()
}

pub fn pbkdf2_sha384_128bits(data: &[u8], st: &[u8], it: u32) -> B128 {
    let mut result: B128 = [0x0; 16];
    let key = pbkdf2_sha384(data, st, it, 256);
    for chunk in key.chunks(16) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

pub fn pbkdf2_sha384_256bits(data: &[u8], st: &[u8], it: u32) -> B256 {
    let mut result: B256 = [0x0; 32];
    let key = pbkdf2_sha384(data, st, it, 256);
    for chunk in key.chunks(32) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

pub fn pbkdf2_sha512(data: &[u8], st: &[u8], it: u32, length: usize) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(length);
    key.resize(length, 0x00);
    let mut key = key.as_mut_slice();
    pbkdf2_hmac::<Sha512>(data, st, it, &mut key);
    key.to_vec()
}

pub fn pbkdf2_sha512_128bits(data: &[u8], st: &[u8], it: u32) -> B128 {
    let mut result: B128 = [0x0; 16];
    let key = pbkdf2_sha512(data, st, it, 256);
    for chunk in key.chunks(16) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

pub fn pbkdf2_sha512_256bits(data: &[u8], st: &[u8], it: u32) -> B256 {
    let mut result: B256 = [0x0; 32];
    let key = pbkdf2_sha512(data, st, it, 256);
    for chunk in key.chunks(32) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum DerivationScheme {
    #[serde(rename = "pbkdf2")]
    Pbkdf2(Pbkdf2HashingAlgo),
    #[serde(rename = "crc")]
    Crc(CrcAlgo),
}
impl DerivationScheme {
    pub fn derive(&self, data: &[u8], st: &[u8], it: u32) -> Vec<u8> {
        match self {
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_256) => {
                pbkdf2_sha256(data, st, it, 32)
            }
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_384) => {
                pbkdf2_sha384(data, st, it, 32)
            }
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512) => {
                pbkdf2_sha512(data, st, it, 32)
            }
            DerivationScheme::Crc(CrcAlgo::GcRc128) => gcrc128(data).to_vec(),
            DerivationScheme::Crc(CrcAlgo::GcRc256) => gcrc256(data).to_vec(),
        }
    }
}
impl ValueEnum for DerivationScheme {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_256),
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_384),
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512),
            DerivationScheme::Crc(CrcAlgo::GcRc128),
            DerivationScheme::Crc(CrcAlgo::GcRc256),
        ]
    }
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_256) => {
                Some(PossibleValue::new("ds_pbkdf2_sha3_256"))
            }
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_384) => {
                Some(PossibleValue::new("ds_pbkdf2_sha3_384"))
            }
            DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512) => {
                Some(PossibleValue::new("ds_pbkdf2_sha3_512"))
            }
            DerivationScheme::Crc(CrcAlgo::GcRc128) => Some(PossibleValue::new("ds_crc_gcrc128")),
            DerivationScheme::Crc(CrcAlgo::GcRc256) => Some(PossibleValue::new("ds_crc_gcrc256")),
        }
    }
    fn from_str(input: &str, ignore_case: bool) -> Result<DerivationScheme, String> {
        let input = if ignore_case {
            input.to_lowercase()
        } else {
            input.to_string()
        };
        let input = input.trim();

        match input {
            "pbkdf2_sha3_256" => Ok(DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_256)),
            "pbkdf2_sha3_384" => Ok(DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_384)),
            "pbkdf2_sha3_512" => Ok(DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512)),
            "crc_gcrc128" => Ok(DerivationScheme::Crc(CrcAlgo::GcRc128)),
            "crc_gcrc256" => Ok(DerivationScheme::Crc(CrcAlgo::GcRc256)),
            otherwise => Err(otherwise.to_string()),
        }
    }
}
#[cfg(test)]
mod derivation_scheme_serialization_tests {
    use crate::aescbc::config::Pbkdf2HashingAlgo;
    use crate::aescbc::kd::DerivationScheme;
    use crate::errors::Error;
    use crate::hashis::CrcAlgo;

    use k9::assert_equal;

    #[test]
    pub fn test_pbkdf2_sha3_256() -> Result<(), Error> {
        let ds = DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_256);
        assert_equal!(serde_yaml::to_string(&ds)?, format!("pbkdf2_sha3_256\n"));
        Ok(())
    }
    #[test]
    pub fn test_pbkdf2_sha3_384() -> Result<(), Error> {
        let ds = DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_384);
        assert_equal!(serde_yaml::to_string(&ds)?, format!("pbkdf2_sha3_384\n"));
        Ok(())
    }
    #[test]
    pub fn test_pbkdf2_sha3_512() -> Result<(), Error> {
        let ds = DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512);
        assert_equal!(serde_yaml::to_string(&ds)?, format!("pbkdf2_sha3_512\n"));
        Ok(())
    }
    #[test]
    pub fn test_crc_gcrc128() -> Result<(), Error> {
        let ds = DerivationScheme::Crc(CrcAlgo::GcRc128);
        assert_equal!(serde_yaml::to_string(&ds)?, format!("crc_gcrc128\n"));
        Ok(())
    }
    #[test]
    pub fn test_crc_gcrc256() -> Result<(), Error> {
        let ds = DerivationScheme::Crc(CrcAlgo::GcRc256);
        assert_equal!(serde_yaml::to_string(&ds)?, format!("crc_gcrc256\n"));
        Ok(())
    }
}
// impl FromStr for DerivationScheme {
//     fn from_str(s: &str) -> Result<Self, std::err::Error> {

//     }
// }
impl YamlFile for DerivationScheme {
    fn default() -> Result<DerivationScheme, Error> {
        Ok(DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_512))
    }
}

impl fmt::Display for DerivationScheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ds_{}",
            match self {
                DerivationScheme::Crc(a) => format!("{}", a),
                DerivationScheme::Pbkdf2(a) => format!("{}", a),
            }
        )
    }
}

#[cfg(test)]
mod pbkdf2_sha256_tests {
    use crate::aescbc::kd::pbkdf2_sha256;
    use crate::aescbc::kd::pbkdf2_sha256_128bits;
    use crate::aescbc::kd::pbkdf2_sha256_256bits;
    use k9::assert_equal;

    #[test]
    pub fn test_pbkdf2_sha256() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha256(password, salt, iterations, 16);

        assert_equal!(dhmac.len(), 16);
        assert_equal!(
            dhmac,
            [84, 189, 114, 48, 88, 140, 144, 188, 30, 178, 172, 167, 173, 15, 72, 229,].to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha256_128bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha256_128bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 16);
        assert_equal!(
            dhmac.to_vec(),
            [75, 123, 63, 147, 158, 155, 204, 202, 159, 127, 253, 225, 5, 149, 70, 119,].to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha256_256bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        // XXX: https://www.one-tab.com/page/zT-wGbjAS_aXz6eV9_u9Ig
        let iterations = 0x53;

        let dhmac = pbkdf2_sha256_256bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 32);
        assert_equal!(
            dhmac.to_vec(),
            [
                91, 24, 54, 211, 113, 54, 159, 162, 131, 93, 207, 241, 44, 38, 220, 17, 16, 99, 9,
                64, 239, 173, 83, 104, 28, 34, 50, 16, 41, 179, 154, 102,
            ]
            .to_vec()
        );
    }
}

#[cfg(test)]
mod pbkdf2_sha384_tests {
    use crate::aescbc::kd::pbkdf2_sha384;
    use crate::aescbc::kd::pbkdf2_sha384_128bits;
    use crate::aescbc::kd::pbkdf2_sha384_256bits;
    use k9::assert_equal;

    #[test]
    pub fn test_pbkdf2_sha384() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha384(password, salt, iterations, 24);

        assert_equal!(dhmac.len(), 24);
        assert_equal!(
            dhmac,
            [
                93, 54, 175, 45, 68, 96, 125, 7, 49, 146, 221, 87, 219, 228, 6, 0, 128, 221, 20,
                87, 97, 169, 129, 27,
            ]
            .to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha384_128bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha384_128bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 16);
        assert_equal!(
            dhmac.to_vec(),
            [109, 164, 181, 139, 65, 152, 214, 206, 218, 47, 184, 138, 80, 55, 51, 119,].to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha384_256bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha384_256bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 32);
        assert_equal!(
            dhmac.to_vec(),
            [
                56, 255, 253, 85, 18, 209, 194, 89, 130, 57, 3, 250, 221, 102, 61, 59, 85, 91, 72,
                222, 83, 73, 20, 151, 88, 22, 187, 112, 141, 81, 14, 76,
            ]
            .to_vec()
        );
    }
}

#[cfg(test)]
mod pbkdf2_sha512_tests {
    use crate::aescbc::kd::pbkdf2_sha512;
    use crate::aescbc::kd::pbkdf2_sha512_128bits;
    use crate::aescbc::kd::pbkdf2_sha512_256bits;
    use k9::assert_equal;

    #[test]
    pub fn test_pbkdf2_sha512() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha512(password, salt, iterations, 24);

        assert_equal!(dhmac.len(), 24);
        assert_equal!(
            dhmac,
            [
                184, 99, 158, 94, 97, 151, 140, 231, 108, 96, 184, 54, 220, 203, 203, 67, 132, 16,
                88, 226, 230, 174, 32, 237,
            ]
            .to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha512_128bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha512_128bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 16);
        assert_equal!(
            dhmac.to_vec(),
            [156, 156, 3, 166, 110, 7, 99, 128, 90, 0, 187, 86, 215, 93, 116, 123,].to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha512_256bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha512_256bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 32);
        assert_equal!(
            dhmac.to_vec(),
            [
                47, 66, 192, 225, 237, 29, 47, 172, 203, 194, 0, 95, 190, 53, 191, 28, 179, 222,
                195, 71, 131, 26, 76, 44, 145, 194, 187, 9, 105, 104, 203, 103,
            ]
            .to_vec()
        );
    }
}
