// use clap_builder::derive::*;
use crate::aescbc::Aes256Key;
use crate::aescbc::DerivationScheme;
use crate::errors::Error;
// use crate::hashis::CrcAlgo;
use crate::aescbc::config::Pbkdf2HashingAlgo;
// use atty::Stream;
use clap::*;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::io::{self, Read};
// use std::path::Path;

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
    #[arg(short = 'o', long)]
    pub output_file: String,

    #[arg(short, long, help = "save yaml key")]
    pub yaml: bool,

    #[arg(short, long)]
    pub force: bool,

    #[arg(
        short,
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_PASSWORD"
    )]
    pub password: Vec<String>,

    #[arg(
        short = 'P',
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_PASSWORD_HWM",
        default_value_t = 0x400
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
        short = 'S',
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_SALT_HWM",
        default_value_t = 0x400
    )]
    pub salt_hwm: u64,

    #[arg(short = 'D', long, env = "OBG_DS", default_value_t = DerivationScheme::Pbkdf2(Pbkdf2HashingAlgo::Sha3_384))]
    pub salt_derivation_scheme: DerivationScheme,

    #[arg(short, long)]
    pub quiet: bool,

    #[arg(
        short,
        long,
        requires_if("false", "interactive"),
        env = "OBG_PBDKF2_CYCLES",
        default_value_t = 54325
    )]
    pub cycles: u64,

    #[arg(
        short = 'r',
        long = "randomize-iv",
        help = "performs random shuffling in the generated IV"
    )]
    pub shuffle_iv: bool,

    #[arg(
        short = 'R',
        long = "random",
        help = "generates key and iv with (pseudo-)random data rather in lieu of derivation"
    )]
    pub random: bool,

    #[arg(short, long, help = "whether to ask password interactively")]
    pub interactive: bool,

    #[arg(short = 'l', long, env = "OBG_BL", help = "blob length")]
    pub blob_length: Option<u64>,
}

impl KeyDeriver for KeygenArgs {
    fn derive_key(&self, shuffle_iv: bool) -> Result<Aes256Key, Error> {
        let password = if self.random {
            let mut rng = rand::thread_rng();
            let mut arr = Vec::<u8>::new();
            arr.resize(self.password_hwm as usize, 0);

            if !self.quiet {
                let pb = ProgressBar::new(self.cycles as u64)
                    .with_message("Generating Password")
                    .with_style(
                        ProgressStyle::with_template("{msg} [{elapsed_precise}] {bar:71.220}")?
                            .progress_chars("★ ✩"),
                    );
                for r in 0..self.cycles {
                    pb.inc(r.into());
                    rng.fill(&mut arr[..]);
                }
                pb.finish();
            } else {
                for _ in 0..self.cycles {
                    rng.fill(&mut arr[..]);
                }
            }

            vec![hex::encode(arr)]
        } else {
            self.password.clone()
        };
        let salt = if self.random {
            let mut rng = rand::thread_rng();
            let mut arr = Vec::<u8>::new();
            arr.resize(self.salt_hwm as usize, 0);
            if !self.quiet {
                let pb = ProgressBar::new(self.cycles as u64)
                    .with_message("Factoring Salt")
                    .with_style(ProgressStyle::with_template(
                        "{msg}      [{elapsed_precise}] {bar:71.237}",
                    )?);
                for r in 0..self.cycles {
                    pb.inc(r.into());
                    rng.fill(&mut arr[..]);
                }
                pb.finish();
            } else {
                for _ in 0..self.cycles {
                    rng.fill(&mut arr[..]);
                }
            }
            vec![hex::encode(arr)]
        } else {
            self.salt.clone()
        };

        if password.len() == 0 {
            // let mut e = clap::error::Error::new(ErrorKind::MissingRequiredArgument);
            // e.insert(clap::error::ContextKind::Custom, clap::error::ContextValue::String("at least one password is required".to_string()));
            // return Err(e.into());
            panic!("provide password or pass the --random flag");
        } else {
            for (index, sec) in password.iter().enumerate() {
                if sec.len() == 0 {
                    panic!("password at position {} is empty", index);
                }
            }
        }
        if salt.len() == 0 {
            panic!("provide salt or pass the --random flag");
        } else {
            for (index, st) in salt.iter().enumerate() {
                if st.len() == 0 {
                    panic!("salt at position {} is empty", index);
                }
            }
        }
        if !self.quiet {
            let pb = ProgressBar::new(2)
                .with_message("More Computation")
                .with_style(ProgressStyle::with_template(
                    "{msg}    [{elapsed_precise}] {bar:71.255}",
                )?);
            pb.inc(1);
        }
        Aes256Key::derive_with_name(
            &self.output_file,
            password.clone(),
            self.password_hwm,
            salt.clone(),
            self.salt_hwm,
            self.cycles,
            self.salt_derivation_scheme.clone(),
            shuffle_iv,
            self.blob_length,
        )
    }
}

#[derive(Args, Debug)]
#[group(multiple = true)]
pub struct KeyOptions {
    #[arg(short, long, required = false, env = "OBG_KEY_FILE")]
    //, overrides_with_all(["password", "salt"]))]
    pub key_file: String,
    // #[arg(short, long, required=false)]
    // pub password: Vec<String>,
    // #[arg(short, long, required=false)]
    // pub salt: String,
    // #[arg(short, long, default_value_t = 1337)]
    // pub cycles: u64,
    #[arg(
        short = 'r',
        long = "rand-iv",
        help = "performs random shuffling in the generated IV"
    )]
    pub shuffle_iv: bool,
    #[arg(short, long, help = "whether to ask password interactively")]
    pub interactive: bool,

    #[arg(short, long, help = "validate key integrity")]
    pub strict: bool,

    #[arg(short = 'p', long, help = "load opaque key")]
    pub opaque: bool,

    #[arg(short = 'o', long, env = "OBG_KO", help = "key offset")]
    pub key_offset: Option<usize>,

    #[arg(short = 'O', long, env = "OBG_SO", help = "salt offset")]
    pub salt_offset: Option<usize>,

    #[arg(short = 'b', long, env = "OBG_BO", help = "blob offset")]
    pub blob_offset: Option<usize>,

    #[arg(short = 'l', long, env = "OBG_BL", help = "blob length")]
    pub blob_length: Option<u64>,

    #[arg(short = 'm', long = "mo", env = "OBG_MO", help = "middle-out offset")]
    pub mo_offset: bool,
}
impl KeyLoader for KeyOptions {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        match self.key_file.len() {
            0 => Err(Error::InvalidCliArg(format!(
                "--key-file is required when --password is not provided"
            ))),
            _ => match self.opaque {
                false => Ok(Aes256Key::load_from_yaml_file(
                    self.key_file.clone(),
                ).unwrap_or(Aes256Key::load_from_file(
                    self.key_file.clone(),
                    self.strict,
                    self.key_offset,
                    self.salt_offset,
                    self.blob_offset,
                    self.mo_offset,
                )?)),
                true => Aes256Key::load_from_file(
                    self.key_file.clone(),
                    self.strict,
                    self.key_offset,
                    self.salt_offset,
                    self.blob_offset,
                    self.mo_offset,
                ),
            }
        }
    }
}

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
impl KeyLoader for DecryptFileParams {
    fn load_key(&self) -> Result<Aes256Key, Error> {
        self.key_opts.load_key()
    }
}
#[derive(Args, Debug)]
pub struct IdOps {
    pub filenames: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "generates key")]
    Keygen(KeygenArgs),
    #[command(
        subcommand,
        about = "encrypts file or input plaintext using a pre-existing key generated via the keygen command"
    )]
    Encrypt(Encrypt),
    #[command(subcommand, about = "decrypts file or input ciphertext")]
    Decrypt(Decrypt),
    #[command(about = "ascertain file's encrypted")]
    Id(IdOps),
}
