use clap_builder::Parser;
use hex;
use obg::aescbc::Aes256CbcCodec;
use obg::aescbc::EncryptionEngine;
use obg::clap::{Cli, Command, Decrypt, Encrypt};
use obg::clap::{KeyDeriver, KeyLoader};
use obg::errors::Error;
use obg::ioutils::absolute_path;
use obg::ioutils::open_write;
use obg::ioutils::read_bytes;
use std::io::Write;
// use url::{Url, Host, Position};

fn main() -> Result<(), Error> {
    let mate = Cli::parse();
    let _command = match mate.command {
        Command::Keygen(args) => {
            let key_file = absolute_path(&args.output_file);
            let key = args.derive_key(args.shuffle_iv)?;
            key.save_to_file(key_file.clone())?;
            eprintln!("saved {}", key_file);
        }
        Command::Encrypt(instruction) => match instruction {
            Encrypt::Text(args) => {
                let key = args.load_key()?;
                let codec = Aes256CbcCodec::new(key.skey(), key.siv());
                let plaintext = args.load_plaintext()?;
                let ciphertext = codec.encrypt_blocks(&plaintext);
                println!("{}", hex::encode(ciphertext));
            }
            Encrypt::File(args) => {
                let key = args.load_key()?;
                let codec = Aes256CbcCodec::new(key.skey(), key.siv());
                let plaintext = read_bytes(&args.input_file)?;
                let ciphertext = codec.encrypt_blocks(&plaintext);
                let mut file = open_write(&args.output_file)?;
                file.write_all(&ciphertext)?;
                eprintln!("wrote {}", args.output_file);
            }
        },
        Command::Decrypt(instruction) => match instruction {
            Decrypt::Text(args) => {
                let key = args.load_key()?;
                let codec = Aes256CbcCodec::new(key.skey(), key.siv());
                let ciphertext = args.load_ciphertext()?;
                let plaintext = codec.decrypt_blocks(&hex::decode(&ciphertext)?);
                println!("{}", String::from_utf8(plaintext)?);
            }
            Decrypt::File(args) => {
                let key = args.load_key()?;
                let codec = Aes256CbcCodec::new(key.skey(), key.siv());
                let ciphertext = read_bytes(&args.input_file)?;
                let plaintext = codec.decrypt_blocks(&ciphertext);
                let mut file = open_write(&args.output_file)?;
                file.write_all(&plaintext)?;
                eprintln!("wrote {}", args.output_file);
            }
        },
    };
    Ok(())
}
