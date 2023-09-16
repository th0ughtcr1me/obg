use clap_builder::Parser;
use hex;
use console;

use obg::aescbc::Aes256CbcCodec;
use obg::aescbc::EncryptionEngine;
use obg::clap::{Cli, Command, Decrypt, Encrypt};
use obg::clap::{KeyDeriver, KeyLoader};
use obg::errors::Error;
use obg::ioutils::absolute_path;
use obg::ioutils::file_exists;
use obg::pap::{decrypt_file, encrypt_file};
// use url::{Url, Host, Position};

fn main() -> Result<(), Error> {
    std::panic::set_hook(Box::new(|panic_info| {
    if let Some(y) = panic_info.payload().downcast_ref::<&str>() {
        eprintln!("{} {}", console::style("Error:").color256(247), console::style(format!("{y}")).color256(253));
    } else {
        eprintln!("{}", console::style("unknown error").red());
    }
    }));

    let mate = Cli::parse();
    match mate.command {
        Command::Keygen(args) => {
            let key_file = absolute_path(&args.output_file);
            let key = args.derive_key(args.shuffle_iv)?;
            if file_exists(&key_file) && !args.force {
                eprintln!("{} already exists, you may pass `-f' to force overwrite", key_file);
                std::process::exit(0xdc);
            }
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
