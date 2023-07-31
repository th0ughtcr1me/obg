pub use crate::errors::Error;
use shellexpand;
pub use std::fs::{File, OpenOptions};
pub use std::io::{BufReader, Read, Write};

pub struct ReadFile {
    pub bytes: Vec<u8>,
    pub length: usize,
}

pub fn absolute_path(src: &str) -> String {
    String::from(shellexpand::tilde(src))
}

pub fn homedir() -> String {
    absolute_path("~")
}

pub fn read_file(filename: &str) -> Result<ReadFile, Error> {
    let mut reader = BufReader::new(File::open(filename)?);
    let mut bytes = Vec::new();
    let length = reader.read_to_end(&mut bytes)?;
    Ok(ReadFile { bytes, length })
}

pub fn read_bytes(filename: &str) -> Result<Vec<u8>, Error> {
    Ok(read_file(filename)?.bytes)
}

pub fn open_write(target: &str) -> Result<std::fs::File, Error> {
    let target = absolute_path(target);
    Ok(OpenOptions::new()
        .create(true)
        .write(true)
        .open(target.as_str())?)
}
