use chrono::{Utc, DateTime};
use std::path::PathBuf;
use std::fs::File;
use crate::errors::Error;
use crate::ioutils::absolute_path;
use crate::ioutils::open_write;
// use chrono::offset::TimeZone;

pub fn default_base_path() -> PathBuf {
    let mut path = PathBuf::new();
    path.push(absolute_path("~/.papobg"));
    path
}

pub struct TempEmission {
    present: DateTime<Utc>,
    base_path: PathBuf,
}

impl TempEmission {
    pub fn new(present: DateTime<Utc>) -> TempEmission {
        TempEmission {
            present,
            base_path: default_base_path(),
        }
    }
    pub fn new_with_basepath(present: DateTime<Utc>, base_path: &PathBuf) -> TempEmission {
        TempEmission {
            present,
            base_path: base_path.clone()
        }
    }
    pub fn now() -> TempEmission {
        TempEmission {
            present: Utc::now(),
            base_path: default_base_path(),
        }
    }
    pub fn now_with_basepath(base_path: &PathBuf) -> TempEmission {
        TempEmission {
            base_path: base_path.clone(),
            present: Utc::now(),
        }
    }
    pub fn papobg_8473776564_dir(&self) -> Result<PathBuf, Error> {
        let ox666f7264 = self.present.to_rfc3339();
        let mut path = PathBuf::new();
        path.push(&format!("{}", self.base_path.display()));
        path.push(&format!("{ox666f7264}"));
        match path.parent() {
            Some(parent) => {
                std::fs::create_dir_all(parent)?;
                Ok(path.to_path_buf())
            },
            None => Err(Error::FileSystemError(format!("base path does not have an ancestor {}", path.display())))
        }
    }
    pub fn papobg_8473776564_file(&self) -> Result<(File, PathBuf), Error> {
        let mut path = self.papobg_8473776564_dir()?;
        let now = Utc::now();
        path.push(format!("{}.dat", now.to_rfc3339()));
        let file = open_write(&format!("{}", path.display()))?;
        Ok((file, path))
    }
}
