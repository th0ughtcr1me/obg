use crate::errors::Error;
use crate::serial::YamlFile;
use crate::aescbc::config::Pbkdf2Config;
use serde::{Deserialize, Serialize};

/// The configuration for the Key.
///
/// It contains the cycles for key, salt and iv used in key derivation.
#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct Config {
    pub derivation: Pbkdf2Config,
    pub default_key_path: Option<String>,
}

impl YamlFile for Config {
    fn default() -> Result<Config, Error> {
        Ok(Config {
            derivation: Pbkdf2Config::default()?,
            default_key_path: None,
        })
    }
}
impl Config {
    /// Creates a new config based on a &Vec<u32>

    pub fn set_default_key_path(&mut self, path: String) -> bool {
        let current = self.default_key_path.clone();
        self.default_key_path = Some(path);
        self.default_key_path != current
    }
}
