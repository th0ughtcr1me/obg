// use clap_builder::derive::*;
use crate::aescbc::Aes256Key;
use crate::errors::Error;
// use atty::Stream;
use clap::*;
use shellexpand;
use std::fs::File;
use std::io::BufReader;
use std::io::{self, Read};
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
    fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error>;
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    #[arg(short, long, env = "OBG_KEY_FILE")]
    pub output_file: String,

    #[arg(
        short,
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_PASSWORD"
    )]
    pub password: Vec<String>,

    #[arg(
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_PASSWORD_HWM",
        default_value_t = 0x40000000,
    )]
    pub password_hwm: u64,

    #[arg(
        short,
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_SALT"
    )]
    pub salt: Vec<String>,

    #[arg(
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_SALT_HWM",
        default_value_t = 0x100000,
    )]
    pub salt_hwm: u64,

    #[arg(
        short,
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_CYCLES",
        default_value_t = 1337
    )]
    pub cycles: u32,

    #[arg(
        short = 'r',
        long = "randomize-iv",
        help = "performs random shuffling in the generated IV"
    )]
    pub shuffle_iv: bool,

    #[arg(short, long, help = "whether to ask password interactively")]
    pub interactive: bool,
}

impl KeyDeriver for KeygenArgs {
    fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error> {
        if self.password.len() == 0 {
            // let mut e = clap::error::Error::new(ErrorKind::MissingRequiredArgument);
            // e.insert(clap::error::ContextKind::Custom, clap::error::ContextValue::String("at least one password is required".to_string()));
            // return Err(e.into());
            panic!("at least one password is required");
        } else {
            for (index, sec) in self.password.iter().enumerate() {
                if sec.len() == 0 {
                    panic!("password at position {} is empty", index);
                }
            }
        }
        if self.salt.len() == 0 {
            panic!("at least one salt is required");
        } else {
            for (index, st) in self.salt.iter().enumerate() {
                if st.len() == 0 {
                    panic!("salt at position {} is empty", index);
                }
            }
        }


        Aes256Key::derive(
            self.password.clone(),
            self.salt.clone(),
            self.cycles,
            shuffle_iv,
        )
    }
}

#[derive(Args, Debug)]
#[group(multiple = false)]
pub struct KeyOptions {
    #[arg(short, long, required = false)] //, overrides_with_all(["password", "salt"]))]
    pub key_file: String,
    // #[arg(short, long, required=false)]
    // pub password: Vec<String>,
    // #[arg(short, long, required=false)]
    // pub salt: String,
    // #[arg(short, long, default_value_t = 1337)]
    // pub cycles: u32,
    #[arg(
        short = 'r',
        long = "rand-iv",
        help = "performs random shuffling in the generated IV"
    )]
    pub shuffle_iv: bool,
    #[arg(short, long, help = "whether to ask password interactively")]
    pub interactive: bool,
}
// impl KeyDeriver for KeyOptions {
//     fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error> {
//         if self.key_file.len() > 0 {
//             if !Path::new(&self.key_file).exists() {
//                 return Err(Error::InvalidCliArg(format!(
//                     "key-file {} does not exist",
//                     self.key_file
//                 )));
//             }
//             return Aes256Key::load_from_file(self.key_file.clone());
//         }
//         if self.password.len() == 0 {
//             return Err(Error::InvalidCliArg(format!(
//                 "--password is required when --key-file is not provided"
//             )));
//         }
//         if self.salt.len() == 0 {
//             return Err(Error::InvalidCliArg(format!(
//                 "--salt is required when --key-file is not provided"
//             )));
//         }
//         Aes256Key::derive(
//             self.password.clone(),
//             self.salt.clone(),
//             self.cycles,
//             shuffle_iv,
//         )
//     }
// }
impl KeyLoader for KeyOptions {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        match self.key_file.len() {
            0 => Err(Error::InvalidCliArg(format!(
                "--key-file is required when --password is not provided"
            ))),
            _ => Aes256Key::load_from_file(self.key_file.clone()),
        }
    }
}
// impl KeyDeriver for KeyOptions {
//     fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error> {
//         if let Some(key_file) = &self.key_file {
//             if key_file.len() > 0 {
//                 if !Path::new(&key_file).exists() {
//                     return Err(Error::InvalidCliArg(format!(
//                         "key-file {} does not exist",
//                         key_file
//                     )));
//                 }
//                 return Aes256Key::load_from_file(key_file.clone());
//             }
//         }
//         if self.password == None {
//             return Err(Error::InvalidCliArg(format!(
//                 "--password is required when --key-file is not provided"
//             )));
//         }
//         if self.salt == None {
//             return Err(Error::InvalidCliArg(format!(
//                 "--salt is required when --key-file is not provided"
//             )));
//         }
//         Aes256Key::derive(
//             self.password.clone().unwrap(),
//             self.salt.clone().unwrap(),
//             self.cycles,
//             shuffle_iv,
//         )
//     }
// }
// impl KeyLoader for KeyOptions {
//     fn load_key(&self) -> Result<Aes256Key, Error> {
//         match &self.key_file {
//             Some(key_file) => Aes256Key::load_from_file(key_file.clone()),
//             None => Err(Error::InvalidCliArg(format!(
//                 "--key-file is required when --password is not provided"
//             )))
//         }
//     }
// }

#[derive(Args, Debug)]
pub struct EncryptTextParams {
    pub plaintext: Option<String>,

    #[command(flatten)]
    pub key_opts: KeyOptions,
}
impl EncryptTextParams {
    pub fn load_plaintext(&self) -> Result<Vec<u8>, Error> {
        match &self.plaintext {
            None => {
                // if atty::is(Stream::Stdin) {
                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer)?;
                Ok(buffer.trim().as_bytes().to_vec())
                // } else {
                //     Err(Error::InvalidCliArg(format!(
                //         "the plaintext argument is required when not piped into STDIN"
                //     )))
                // }
            }
            Some(plaintext) => Ok(plaintext.as_bytes().to_vec()),
        }
    }
}
// impl KeyDeriver for EncryptTextParams {
//     fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error> {
//         self.key_opts.derive_key(shuffle_iv)
//     }
// }
impl KeyLoader for EncryptTextParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        self.key_opts.load_key()
    }
}

#[derive(Args, Debug)]
pub struct EncryptFileParams {
    pub input_file: String,
    pub output_file: String,

    #[command(flatten)]
    pub key_opts: KeyOptions,
}
// impl KeyDeriver for EncryptFileParams {
//     fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error> {
//         self.key_opts.derive_key(shuffle_iv)
//     }
// }
impl KeyLoader for EncryptFileParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        self.key_opts.load_key()
    }
}

#[derive(Args, Debug)]
pub struct DecryptTextParams {
    pub ciphertext: Option<String>,

    #[command(flatten)]
    pub key_opts: KeyOptions,
}
impl DecryptTextParams {
    pub fn load_ciphertext(&self) -> Result<Vec<u8>, Error> {
        match &self.ciphertext {
            None => {
                // if atty::is(Stream::Stdin) {
                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer)?;
                Ok(buffer.trim().as_bytes().to_vec())
                // } else {
                //     Err(Error::InvalidCliArg(format!(
                //         "the ciphertext argument is required when not piped into STDIN"
                //     )))
                // }
            }
            Some(ciphertext) => Ok(ciphertext.as_bytes().to_vec()),
        }
    }
}
// impl KeyDeriver for DecryptTextParams {
//     fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error> {
//         self.key_opts.derive_key(shuffle_iv)
//     }
// }
impl KeyLoader for DecryptTextParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        self.key_opts.load_key()
    }
}

#[derive(Args, Debug)]
pub struct DecryptFileParams {
    pub input_file: String,
    pub output_file: String,

    #[command(flatten)]
    pub key_opts: KeyOptions,
}
// impl KeyDeriver for DecryptFileParams {
//     fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error> {
//         self.key_opts.derive_key(shuffle_iv)
//     }
// }
impl KeyLoader for DecryptFileParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        self.key_opts.load_key()
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
