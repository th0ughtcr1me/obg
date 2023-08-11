use crate::errors::Error;
use crate::serial::YamlFile;
// use crate::aescbc::config::Pbkdf2Config;
use crate::aescbc::kd::DerivationScheme;
use crate::ioutils::{absolute_path, resolved_path};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;


#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct PasswordConfig {
    pub derivation: DerivationScheme,
    source: Vec<String>, // vector of strings or files
    source_hwm: u64,     // source high water mark
}

impl PasswordConfig {
    pub fn set_derivation_scheme(&mut self, scheme: DerivationScheme) -> bool {
        let current = self.derivation.clone();
        self.derivation = scheme;
        self.derivation != current
    }
    pub fn set_source(&mut self, source: Vec<String>) -> bool {
        let current = self.source.clone();
        self.source = source;
        self.source != current
    }
    pub fn set_source_hwm(&mut self, high_water_mark: u64) -> Result<bool, Error> {
        if high_water_mark < 32 {
            return Err(Error::InvalidConfig(format!("the minimum high-water-mark is 32 bytes, got {} instead", high_water_mark)))
        }
        let current = self.source_hwm.clone();
        self.source_hwm = high_water_mark;
        Ok(self.source_hwm != current)
    }
}
impl YamlFile for PasswordConfig {
    fn default() -> Result<PasswordConfig, Error> {
        Ok(PasswordConfig {
            derivation: DerivationScheme::default()?,
            source: vec!["/dev/random".into()],
            source_hwm: 1024 * 1024,
        })
    }
}

#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct IVConfig {
    derivation: DerivationScheme,
    shuffle: bool,
    source: Vec<String>, // vector of strings or files
    source_hwm: u64,     // source high water mark
}

impl YamlFile for IVConfig {
    fn default() -> Result<IVConfig, Error> {
        Ok(IVConfig {
            derivation: DerivationScheme::default()?,
            shuffle: false,
            source: vec!["/dev/random".into()],
            source_hwm: 1024 * 1024 * 1024,
        })
    }
}

#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    password: PasswordConfig,
    iv: IVConfig,
    path: String,
}

impl GeoConfig {
    pub fn get_path(&mut self) -> String {
        absolute_path(&self.path)
    }
    pub fn set_path(&mut self, path: String) -> bool {
        let current = self.path.clone();
        self.path = path;
        self.path != current
    }
    pub fn set_password(&mut self, config: PasswordConfig) -> bool {
        let current = self.password.clone();
        self.password = config;
        self.password != current
    }
    pub fn set_iv(&mut self, config: IVConfig) -> bool {
        let current = self.iv.clone();
        self.iv = config;
        self.iv != current
    }
}

impl YamlFile for GeoConfig {
    fn default() -> Result<GeoConfig, Error> {
        Ok(GeoConfig {
            password: PasswordConfig::default()?,
            iv: IVConfig::default()?,
            path: absolute_path(".").into(),
        })
    }
}

#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct Config {
    default: GeoConfig,
    tree: Option<BTreeMap<String, GeoConfig>>,
}
impl Config {
    pub fn set_default(&mut self, config: GeoConfig) {
        self.default = config;
    }
    pub fn add_path(&mut self, path: &str, config: GeoConfig) {
        match &mut self.tree {
            None => {
                let mut tree = BTreeMap::new();
                tree.insert(resolved_path(path), config);
                self.tree = Some(tree);
            },
            Some(ref mut tree) => {
                tree.insert(resolved_path(path), config);
                self.tree = Some(tree.clone());
            }
        };
    }
    pub fn remove_path(&mut self, path: &str) {
        match &mut self.tree {
            None => {
                let mut tree = BTreeMap::new();
                tree.remove(path);
                self.tree = Some(tree);
            },
            Some(ref mut tree) => {
                tree.remove(path);
                self.tree = Some(tree.clone());
            }
        };
    }
}
impl YamlFile for Config {
    fn default() -> Result<Config, Error> {
        Ok(Config {
            default: GeoConfig::default()?,
            tree: Some(BTreeMap::new()),
        })
    }
}


#[cfg(test)]
mod config_tests {
    use crate::config::Config;
    use crate::errors::Error;
    use crate::serial::YamlFile;
    use k9::assert_equal;

    #[test]
    pub fn test_default_config_to_yaml() -> Result<(), Error> {
        assert_equal!(Config::default()?.to_yaml()?, "default:
  password:
    derivation: !Pbkdf2 Sha3_512
    source:
    - /dev/random
    source_hwm: 1048576
  iv:
    derivation: !Pbkdf2 Sha3_512
    shuffle: false
    source:
    - /dev/random
    source_hwm: 1073741824
  path: .
tree: {}
".to_string());
        Ok(())
    }

}
