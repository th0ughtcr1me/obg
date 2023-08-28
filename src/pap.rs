use crate::aescbc::Aes256Key;
use crate::errors::Error;
use crate::aescbc::Aes256CbcCodec;
use crate::sneaker;
use crate::aescbc::EncryptionEngine;
use std::io::Write;
use std::io::Read;
use std::fs::File;

use crate::ioutils::open_write;


pub fn decrypt_file(key: Aes256Key, input_file: String, output_file: String) -> Result<(), Error> {
    let codec = Aes256CbcCodec::new(key.skey(), key.siv());
    let mut file = File::open(&input_file)?;
    let ciphertext: Vec<u8> = if sneaker::io::is_snuck(&mut file)? {
        let mut bytes: Vec<u8> = Vec::new();
        file.read_to_end(&mut bytes)?;
        bytes
    } else {
        eprintln!("{} does not appear to be encrypted with {} {}", input_file, env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
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
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;
    let ciphertext = codec.encrypt_blocks(&plaintext);
    let mut file = open_write(&output_file)?;
    file.write_all(&sneaker::core::magic_id())?;
    file.write_all(&ciphertext)?;
    eprintln!("wrote {}", output_file);
    Ok(())
}
