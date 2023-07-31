use crate::aescbc::tp::{B128, B256};

pub fn xor_128(left: B128, right: B128) -> B128 {
    let mut result: B128 = [0; 16];
    for (i, (s, o)) in left.into_iter().zip(right.iter()).enumerate() {
        result[i] = s ^ o;
    }
    result
}

pub fn xor_256(left: B256, right: B256) -> B256 {
    let mut result: B256 = [0; 32];
    for (i, (s, o)) in left.into_iter().zip(right.iter()).enumerate() {
        result[i] = s ^ o;
    }
    result
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.into_iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}
