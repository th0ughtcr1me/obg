use clap_builder::Parser;
use console;
use hex;

use obg::aescbc::Aes256CbcCodec;
use obg::aescbc::EncryptionEngine;
use obg::clap::{Cli, Command, Decrypt, Encrypt};
use obg::clap::{KeyDeriver, KeyLoader};
use obg::errors::Error;
use obg::ioutils::absolute_path;
use obg::ioutils::file_exists;
use obg::pap::{decrypt_file, encrypt_file};
use obg::sneaker::io::{is_snuck, xstack};
use std::fs::File;
// use url::{Url, Host, Position};

fn main() -> Result<(), Error> {
    std::panic::set_hook(Box::new(|panic_info| {
        if let Some(y) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!(
                "{} {}",
                console::style("Error:").color256(247),
                console::style(format!("{y}")).color256(253)
            );
        } else {
            eprintln!("{}{}", console::style("unknown error:").color256(160), console::style(&format!("{:#?}", panic_info)).color256(237));
        }
    }));

    let mate = Cli::parse();
    match mate.command {
        Command::Id(args) => {
            for reference in args.filenames.iter() {
                let path = absolute_path(reference);
                let mut file = File::open(&path)?;
                if xstack(&mut file)? {
                    eprintln!("\x1b[1;38;5;148mbgn\t\x1b[1;38;5;118mY\x1b[0m\t{}", &path);
                } else {
                    eprintln!("\x1b[1;38;5;148mbgn\t\x1b[1;38;5;160mN\x1b[0m\t{}", &path);
                }
                if is_snuck(&mut file)? {
                    eprintln!("\x1b[1;38;5;184mmgx\t\x1b[1;38;5;118mY\x1b[0m\t{}", &path);
                } else {
                    eprintln!("\x1b[1;38;5;184mmgx\t\x1b[1;38;5;160mN\x1b[0m\t{}", &path);
                }
            }
        }
        Command::Keygen(args) => {
            let key_file = absolute_path(&args.output_file);
            let key = args.derive_key(args.shuffle_iv)?;
            if file_exists(&key_file) && !args.force {
                eprintln!(
                    "{} already exists, you may pass `-f' to force overwrite",
                    key_file
                );
                std::process::exit(0xdc);
            }
            if args.yaml {
                key.save_to_yaml_file(key_file.clone())?;
            } else {
                key.save_to_file(key_file.clone())?;
            };
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
                encrypt_file(key, args.input_file, args.output_file)?
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
                decrypt_file(key, args.input_file, args.output_file)?
            }
        },
    };
    Ok(())
}
