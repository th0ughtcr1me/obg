// use clap_builder::derive::*;
use crate::aescbc::Aes256Key;
use crate::errors::Error;
use clap::*;
use shellexpand;
use std::fs::File;
use std::io::{BufReader, Read};
// use std::path::Path;

pub fn absolute_path(src: &str) -> String {
    String::from(shellexpand::tilde(src))
}

pub fn read_file(filename: &str) -> Vec<u8> {
    let mut reader = BufReader::new(File::open(filename).unwrap());
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Encrypt {
    Text(EncryptTextParams),
    File(EncryptFileParams),
}
#[derive(Subcommand, Debug)]
pub enum Decrypt {
    Text(DecryptTextParams),
    File(DecryptFileParams),
}

pub trait KeyLoader {
    fn load_key(&self) -> Result<Aes256Key, Error>;
}

pub trait KeyDeriver {
    fn derive_key(&self) -> Result<Aes256Key, Error>;
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    #[arg(short, long, required(true))]
    pub output_file: String,
    #[arg(short, long, required(true), env = "OBG_PBDKF2_PASSWORD")]
    pub password: String,
    #[arg(short, long, required(true), env = "OBG_PBDKF2_SALT")]
    pub salt: String,
    #[arg(short, long, env = "OBG_PBDKF2_CYCLES", default_value_t = 1337)]
    pub cycles: u32,
}

impl KeyDeriver for KeygenArgs {
    fn derive_key(&self) -> Result<Aes256Key, Error> {
        Aes256Key::derive(self.password.clone(), self.salt.clone(), self.cycles)
    }
}

#[derive(Args, Debug)]
pub struct EncryptTextParams {
    #[arg(required(true))]
    pub plaintext: String,

    // #[arg(short, long, env = "OBG_PBDKF2_PASSWORD")]
    // pub password: String,

    // #[arg(short, long, env = "OBG_PBDKF2_SALT")]
    // pub salt: String,

    // #[arg(env = "OBG_PBDKF2_CYCLES", default_value_t = 1337)]
    // pub cycles: u32,
    #[arg(short, long)]
    pub key_file: String,
}
// impl KeyDeriver for EncryptTextParams {
//     fn derive_key(&self) -> Result<Aes256Key, Error> {
//         Aes256Key::derive(self.password.clone(), self.salt.clone(), self.cycles)
//     }
// }
impl KeyLoader for EncryptTextParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        Aes256Key::load_from_file(self.key_file.clone())
    }
}

#[derive(Args, Debug)]
pub struct EncryptFileParams {
    #[arg(short, long, required(true))]
    pub input_file: String,
    #[arg(short, long, required(true))]
    pub output_file: String,

    // #[arg(short, long, env = "OBG_PBDKF2_PASSWORD")]
    // pub password: String,

    // #[arg(short, long, env = "OBG_PBDKF2_SALT")]
    // pub salt: String,

    // #[arg(env = "OBG_PBDKF2_CYCLES", default_value_t = 1337)]
    // pub cycles: u32,
    #[arg(short, long)]
    pub key_file: String,
}
// impl KeyDeriver for EncryptFileParams {
//     fn derive_key(&self) -> Result<Aes256Key, Error> {
//         Aes256Key::derive(self.password.clone(), self.salt.clone(), self.cycles)
//     }
// }
impl KeyLoader for EncryptFileParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        Aes256Key::load_from_file(self.key_file.clone())
    }
}

#[derive(Args, Debug)]
pub struct DecryptTextParams {
    #[arg(required(true))]
    pub ciphertext: String,

    // #[arg(short, long, env = "OBG_PBDKF2_PASSWORD")]
    // pub password: String,

    // #[arg(short, long, env = "OBG_PBDKF2_SALT")]
    // pub salt: String,

    // #[arg(env = "OBG_PBDKF2_CYCLES", default_value_t = 1337)]
    // pub cycles: u32,
    #[arg(short, long)]
    pub key_file: String,
}
// impl KeyDeriver for DecryptTextParams {
//     fn derive_key(&self) -> Result<Aes256Key, Error> {
//         Aes256Key::derive(self.password.clone(), self.salt.clone(), self.cycles)
//     }
// }
impl KeyLoader for DecryptTextParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        Aes256Key::load_from_file(self.key_file.clone())
    }
}

#[derive(Args, Debug)]
pub struct DecryptFileParams {
    #[arg(short, long, required(true))]
    pub input_file: String,
    #[arg(short, long, required(true))]
    pub output_file: String,

    #[arg(short, long)]
    pub key_file: String,
    // #[arg(short, long, env = "OBG_PBDKF2_PASSWORD")]
    // pub password: String,

    // #[arg(short, long, env = "OBG_PBDKF2_SALT")]
    // pub salt: String,

    // #[arg(env = "OBG_PBDKF2_CYCLES", default_value_t = 1337)]
    // pub cycles: u32,
}
// impl KeyDeriver for DecryptFileParams {
//     fn derive_key(&self) -> Result<Aes256Key, Error> {
//         Aes256Key::derive(self.password.clone(), self.salt.clone(), self.cycles)
//     }
// }
impl KeyLoader for DecryptFileParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        Aes256Key::load_from_file(self.key_file.clone())
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command()]
    Keygen(KeygenArgs),
    #[command(subcommand)]
    Encrypt(Encrypt),
    #[command(subcommand)]
    Decrypt(Decrypt),
}
