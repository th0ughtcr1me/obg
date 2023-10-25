use chacha20::cipher::KeyIvInit;
use chacha20::ChaCha20;
use crate::aescbc::cdc::Aes256Key;
use crate::aescbc::tp::{B96, B256};
use crate::errors::Error;
use crate::aescbc::kd::pbkdf2_sha512;
use crate::aescbc::kd::pbkdf2_sha384;

pub struct ChaCha20Key {
    key: B256,
    nonce: B96,
}

impl ChaCha20Key {
    pub fn from_aeskey(ak: &Aes256Key) -> Result<ChaCha20Key, Error> {
        let mut blob = Vec::<u8>::new();
        blob.extend(&ak.siv());
        blob.extend(&ak.skey());

        let p00 = pbkdf2_sha512(&blob, &ak.skey(), blob[blob.len()-1] as u32, 32);
        let mut key: B256 = [0; 32];
        key.copy_from_slice(&p00[p00.len()-32..]);
        let p10 = pbkdf2_sha384(&blob, &ak.siv(), blob[blob.len()-1] as u32, 12);
        let mut nonce: B96 = [0; 12];
        nonce.copy_from_slice(&p10[p10.len()-12..]);

        Ok(ChaCha20Key {
            key: key,
            nonce: nonce,
        })
    }
    pub fn engine(&self) -> ChaCha20 {
        ChaCha20::new(&self.key.into(), &self.nonce.into())
    }
}
