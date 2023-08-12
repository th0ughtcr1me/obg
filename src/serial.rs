use crate::errors::Error;
use crate::errors::YamlFileError;
// use crate::errors::YamlFileError;
use crate::ioutils::{absolute_path, open_write};

use serde::de::DeserializeOwned;
use serde::Serialize;

use std::{
    fs::{self},
    io::Write,
};

pub trait YamlFile {
    fn from_yaml<'a>(data: String) -> Result<Self, Error>
    where
        Self: DeserializeOwned,
        Self: Clone,
        Self: PartialEq,
    {
        let cfg: Self = match serde_yaml::from_str(&data) {
            Ok(config) => config,
            Err(error) => {
                return Err(YamlFileError::with_message(format!(
                    "failed to deserialize yaml config: {}",
                    error
                ))
                .into())
            }
        };
        Ok(cfg)
    }
    fn to_yaml(&self) -> Result<String, Error>
    where
        Self: Serialize,
    {
        match serde_yaml::to_string(&self) {
            Ok(val) => Ok(val),
            Err(e) => Err(YamlFileError::with_message(format!(
                "failed to encode key to yaml: {}",
                e
            ))
            .into()),
        }
    }

    fn default() -> Result<Self, Error>
    where
        Self: DeserializeOwned;

    fn import(filename: &str) -> Result<Self, Error>
    where
        Self: DeserializeOwned,
        Self: Clone,
        Self: PartialEq,
    {
        let filename = absolute_path(filename);
        match fs::read_to_string(filename.as_str()) {
            Ok(yaml) => YamlFile::from_yaml(yaml),
            Err(error) => {
                return Err(YamlFileError::with_message(format!(
                    "faled to read file {}\n\t{}",
                    filename, error
                ))
                .into())
            }
        }
    }

    fn export(&self, filename: &str) -> Result<String, Error>
    where
        Self: Serialize,
    {
        let filename = absolute_path(filename);

        let yaml = match self.to_yaml() {
            Ok(val) => val,
            Err(error) => return Err(error),
        };
        let mut file = match open_write(filename.as_str()) {
            Ok(file) => file,
            Err(error) => {
                return Err(YamlFileError::with_message(format!(
                    "failed to create file {}\n\t{}",
                    filename, error
                ))
                .into())
            }
        };
        file.write(yaml.as_ref()).unwrap();
        Ok(filename)
    }
}
