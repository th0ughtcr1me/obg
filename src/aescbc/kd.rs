use crate::aescbc::tp::B128;
use crate::aescbc::tp::B256;
use pbkdf2::pbkdf2_hmac;
use sha3::Sha3_256 as Sha256;
use sha3::Sha3_384 as Sha384;

pub fn pbkdf2_sha256(pw: &[u8], st: &[u8], it: u32, length: usize) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(length);
    key.resize(length, 0x00);
    let mut key = key.as_mut_slice();
    pbkdf2_hmac::<Sha256>(pw, st, it, &mut key);
    key.to_vec()
}

pub fn pbkdf2_sha256_128bits(pw: &[u8], st: &[u8], it: u32) -> B128 {
    let mut result: B128 = [0x0; 16];
    let key = pbkdf2_sha256(pw, st, it, 256);
    for chunk in key.chunks(16) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

pub fn pbkdf2_sha256_256bits(pw: &[u8], st: &[u8], it: u32) -> B256 {
    let mut result: B256 = [0x0; 32];
    let key = pbkdf2_sha256(pw, st, it, 256);
    for chunk in key.chunks(32) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

pub fn pbkdf2_sha384(pw: &[u8], st: &[u8], it: u32, length: usize) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(length);
    key.resize(length, 0x00);
    let mut key = key.as_mut_slice();
    pbkdf2_hmac::<Sha384>(pw, st, it, &mut key);
    key.to_vec()
}

pub fn pbkdf2_sha384_128bits(pw: &[u8], st: &[u8], it: u32) -> B128 {
    let mut result: B128 = [0x0; 16];
    let key = pbkdf2_sha384(pw, st, it, 256);
    for chunk in key.chunks(16) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

pub fn pbkdf2_sha384_256bits(pw: &[u8], st: &[u8], it: u32) -> B256 {
    let mut result: B256 = [0x0; 32];
    let key = pbkdf2_sha384(pw, st, it, 256);
    for chunk in key.chunks(32) {
        for (pos, v) in chunk.iter().enumerate() {
            result[pos] = result[pos] ^ v;
        }
    }
    result
}

#[cfg(test)]
mod pbkdf2_sha256_tests {
    use crate::aescbc::kd::pbkdf2_sha256;
    use crate::aescbc::kd::pbkdf2_sha256_128bits;
    use crate::aescbc::kd::pbkdf2_sha256_256bits;
    use k9::assert_equal;

    #[test]
    pub fn test_pbkdf2_sha256() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha256(password, salt, iterations, 16);

        assert_equal!(dhmac.len(), 16);
        assert_equal!(
            dhmac,
            [84, 189, 114, 48, 88, 140, 144, 188, 30, 178, 172, 167, 173, 15, 72, 229,].to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha256_128bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha256_128bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 16);
        assert_equal!(
            dhmac.to_vec(),
            [75, 123, 63, 147, 158, 155, 204, 202, 159, 127, 253, 225, 5, 149, 70, 119,].to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha256_256bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        // XXX: https://www.one-tab.com/page/zT-wGbjAS_aXz6eV9_u9Ig
        let iterations = 0x53;

        let dhmac = pbkdf2_sha256_256bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 32);
        assert_equal!(
            dhmac.to_vec(),
            [
                91, 24, 54, 211, 113, 54, 159, 162, 131, 93, 207, 241, 44, 38, 220, 17, 16, 99, 9,
                64, 239, 173, 83, 104, 28, 34, 50, 16, 41, 179, 154, 102,
            ]
            .to_vec()
        );
    }
}

#[cfg(test)]
mod pbkdf2_sha384_tests {
    use crate::aescbc::kd::pbkdf2_sha384;
    use crate::aescbc::kd::pbkdf2_sha384_128bits;
    use crate::aescbc::kd::pbkdf2_sha384_256bits;
    use k9::assert_equal;

    #[test]
    pub fn test_pbkdf2_sha384() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha384(password, salt, iterations, 24);

        assert_equal!(dhmac.len(), 24);
        assert_equal!(
            dhmac,
            [
                93, 54, 175, 45, 68, 96, 125, 7, 49, 146, 221, 87, 219, 228, 6, 0, 128, 221, 20,
                87, 97, 169, 129, 27,
            ]
            .to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha384_128bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha384_128bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 16);
        assert_equal!(
            dhmac.to_vec(),
            [109, 164, 181, 139, 65, 152, 214, 206, 218, 47, 184, 138, 80, 55, 51, 119,].to_vec()
        );
    }
    #[test]
    pub fn test_pbkdf2_sha384_256bits() {
        let password =
            b"Cras quis luctus tellus. Curabitur consectetur eu neque nec auctor. Curabitur.";
        let salt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris sed finibus.";
        let iterations = 0x53;

        let dhmac = pbkdf2_sha384_256bits(password, salt, iterations);

        assert_equal!(dhmac.len(), 32);
        assert_equal!(
            dhmac.to_vec(),
            [
                56, 255, 253, 85, 18, 209, 194, 89, 130, 57, 3, 250, 221, 102, 61, 59, 85, 91, 72,
                222, 83, 73, 20, 151, 88, 22, 187, 112, 141, 81, 14, 76,
            ]
            .to_vec()
        );
    }
}