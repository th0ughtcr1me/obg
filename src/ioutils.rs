use crate::errors::Error;
use shellexpand;

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;
use std::os::unix::fs::OpenOptionsExt;

pub struct ReadFile {
    pub bytes: Vec<u8>,
    pub length: usize,
}

pub fn absolute_path(src: &str) -> String {
    String::from(match shellexpand::full(src) {
        Ok(v) => v,
        Err(_) => shellexpand::tilde(src),
    })
}

pub fn absolutely_current_path() -> Result<String, Error> {
    let path = std::env::current_dir()?;
    match path.to_str() {
        Some(path) => Ok(absolute_path(path)),
        None => Err(Error::FileSystemError(format!("invalid current path"))),
    }
}

pub fn resolved_path(src: &str) -> String {
    absolute_path(src).replace(&homedir(), "~")
}

pub fn homedir() -> String {
    absolute_path("~")
}

pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn get_or_create_parent_dir(path: &str) -> Result<String, Error> {
    // XXX: proceed implementation
    let abspath = absolute_path(path);
    let path = Path::new(&abspath);
    match path.parent() {
        Some(parent) => {
            std::fs::create_dir_all(parent)?;
            Ok(format!("{}", parent.display()))
        }
        None => Err(Error::FileSystemError(format!(
            "base path does not have an ancestor {}",
            path.display()
        ))),
    }
}
pub fn read_file(filename: &str) -> Result<ReadFile, Error> {
    let mut file = File::open(filename)?;
    let mut bytes = Vec::new();
    let length = file.read_to_end(&mut bytes)?;
    Ok(ReadFile { bytes, length })
}

pub fn read_bytes_high_water_mark(filename: &str, hwm: u64) -> Result<Vec<u8>, Error> {
    let file = File::open(filename)?;
    let mut handle = file.take(hwm);
    handle.set_limit(hwm);
    let mut bytes = Vec::new();
    handle.read_to_end(&mut bytes)?;
    Ok(bytes)
}
pub fn read_bytes(filename: &str) -> Result<Vec<u8>, Error> {
    let mut file = File::open(filename)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn open_write(target: &str) -> Result<std::fs::File, Error> {
    let abspath = absolute_path(target);
    get_or_create_parent_dir(&abspath)?;
    // let parent =
    Ok(OpenOptions::new().create(true).write(true).mode(0o600).open(target)?)
}
