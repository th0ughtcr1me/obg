use crate::aescbc::Aes256CbcCodec;
use crate::aescbc::Aes256Key;
use crate::aescbc::EncryptionEngine;
use crate::errors::Error;
use crate::ioutils::open_write;
use crate::sneaker;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

/// Represents the stages of encryption/decryption principally during I/O
pub enum IOStage {
    InitCodec,
    Read,
    Accept,
    Metadata,
    Transcode,
    Write,
}
impl From<IOStage> for String {
    fn from(stage: IOStage) -> String {
        String::from(match stage {
            IOStage::InitCodec => "InitCodec",
            IOStage::Read => "Read",
            IOStage::Accept => "Accept",
            IOStage::Metadata => "Metadata",
            IOStage::Transcode => "Transcode",
            IOStage::Write => "Write",
        })
    }
}
impl From<IOStage> for u8 {
    fn from(stage: IOStage) -> u8 {
        u8::from(match stage {
            IOStage::InitCodec => 0b000001,
            IOStage::Read => 0b000010,
            IOStage::Accept => 0b000100,
            IOStage::Metadata => 0b001000,
            IOStage::Transcode => 0b010000,
            IOStage::Write => 0b100000,
        })
    }
}

pub fn decrypt_file(key: Aes256Key, input_file: String, output_file: String) -> Result<(), Error> {
    let codec = Aes256CbcCodec::new(key.skey(), key.siv());
    let mut file = File::open(&input_file)?;
    let ciphertext: Vec<u8> = if sneaker::io::is_snuck(&mut file)? {
        let mut bytes: Vec<u8> = Vec::new();
        file.seek(SeekFrom::Start(sneaker::core::MAGIC_WIDTH as u64))?;
        file.read_to_end(&mut bytes)?;
        bytes
    } else {
        eprintln!(
            "{} does not appear to be encrypted with {} {}",
            input_file,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        std::process::exit(0x54);
    };

    let plaintext = codec.decrypt_blocks(&ciphertext);
    let mut file = open_write(&output_file)?;
    file.write_all(&plaintext)?;
    eprintln!("wrote {}", output_file);
    Ok(())
}

pub fn encrypt_file(key: Aes256Key, input_file: String, output_file: String) -> Result<(), Error> {
    let codec = Aes256CbcCodec::new(key.skey(), key.siv());
    let mut file = File::open(&input_file)?;
    if sneaker::io::is_snuck(&mut file)? {
        eprintln!("already encrypted: {}", input_file);
        std::process::exit(0x54);
    }
    file.rewind()?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;
    let ciphertext = codec.encrypt_blocks(&plaintext);
    let mut file = open_write(&output_file)?;
    file.write_all(&sneaker::core::magic_id())?;
    file.write_all(&ciphertext)?;
    eprintln!("wrote {}", output_file);
    Ok(())
}

#[cfg(test)]
mod pap_tests {
    use crate::aescbc::cdc::Aes256Key;
    use crate::emit::TempEmission;
    use crate::errors::Error;
    use crate::pap::{decrypt_file, encrypt_file};

    use k9::assert_equal;
    use std::fs::{read, File};
    use std::io::{Read, Write};

    pub fn random_bytes(breadth: usize) -> Result<Vec<u8>, Error> {
        let mut result = Vec::<u8>::new();
        result.resize(breadth, 0xa);
        let mut file = File::open("/dev/random")?;
        file.read_exact(&mut result)?;
        Ok(result)
    }
    pub fn seq_bytes(breadth: usize) -> Result<Vec<u8>, Error> {
        let mut result = Vec::<u8>::new();
        result.resize(breadth, 0xa);
        for x in 65..(65 + breadth) {
            result[x - 65] = x as u8;
        }
        Ok(result)
    }
    fn get_key() -> Aes256Key {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x65, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let blob = [
            0x07, 0x88, 0x1b, 0xdd, 0x2c, 0xd4, 0x32, 0xd6, 0x0f, 0x9f, 0x78, 0x7d, 0xc1, 0x64,
            0xae, 0x52, 0xd7, 0x21, 0x64, 0x40, 0x6a, 0x11, 0x4b, 0xaa, 0x20, 0x2c, 0xb8, 0x55,
            0x9b, 0x4f, 0x79, 0x96, 0x5e, 0x8b, 0xa7, 0xdf,
        ];
        Aes256Key::new(key, iv, &blob, 0)
    }
    #[test]
    pub fn test_e2e_sequential_bytes() -> Result<(), Error> {
        let emission = TempEmission::now();
        let (mut file, path) = emission.papobg_8473776564_file()?;
        let key = get_key();
        let path = format!("{}", path.display());
        let bytes = seq_bytes(64)?;
        file.write_all(&bytes)?;
        let enpath = format!("{}.en", path);
        let depath = format!("{}.de", path);
        encrypt_file(key.clone(), path, enpath.clone())?;
        decrypt_file(key.clone(), enpath.clone(), depath.clone())?;
        // let enbytes = read(enpath)?;
        let debytes = read(depath)?;
        assert_equal!(bytes, debytes);

        Ok(())
    }
    #[test]
    pub fn test_e2e_random_bytes() -> Result<(), Error> {
        let emission = TempEmission::now();
        let (mut file, path) = emission.papobg_8473776564_file()?;
        let key = get_key();
        let path = format!("{}", path.display());
        let bytes = random_bytes(64)?;
        file.write_all(&bytes)?;
        let enpath = format!("{}.en", path);
        let depath = format!("{}.de", path);
        encrypt_file(key.clone(), path, enpath.clone())?;
        decrypt_file(key.clone(), enpath.clone(), depath.clone())?;
        // let enbytes = read(enpath)?;
        let debytes = read(depath)?;
        assert_equal!(bytes, debytes);
        Ok(())
    }
}
