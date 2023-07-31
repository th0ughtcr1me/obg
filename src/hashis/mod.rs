use crc::{Crc, CRC_64_GO_ISO, CRC_64_WE};
use crc::{CRC_32_JAMCRC, CRC_32_XFER, CRC_64_MS};
use hex;

pub const GO_64: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);
pub const WE_64: Crc<u64> = Crc::<u64>::new(&CRC_64_WE);
pub const MS_64: Crc<u64> = Crc::<u64>::new(&CRC_64_MS);
pub const JC_32: Crc<u32> = Crc::<u32>::new(&CRC_32_JAMCRC);
pub const XF_32: Crc<u32> = Crc::<u32>::new(&CRC_32_XFER);

pub fn gcrc128(data: &[u8]) -> [u8; 16] {
    let mut result = [0xff; 16];
    let mut lhs = hex::decode(format!("{:x}", WE_64.checksum(&data.clone()))).unwrap();
    lhs.reverse();
    let rhs = hex::decode(format!("{:x}", GO_64.checksum(&data.clone()))).unwrap();
    result[..16 / 2].copy_from_slice(&lhs);
    result[16 / 2..].copy_from_slice(&rhs);
    result
}

#[cfg(test)]
mod gcrc128_tests {
    use crate::hashis::gcrc128;
    use k9::assert_equal;

    #[test]
    pub fn test_gcrc128() {
        let input = b"seemingly random bytes";
        assert_equal!(
            gcrc128(input).to_vec(),
            [185, 59, 126, 244, 2, 252, 171, 21, 102, 82, 177, 220, 251, 137, 169, 191,].to_vec()
        );
    }
}

pub fn gcrc256(data: &[u8]) -> [u8; 32] {
    let mut result = [0xff; 32];
    let mut lhs = gcrc128(&data.clone());
    lhs.reverse();
    let rhs00 = hex::decode(format!("{:x}", MS_64.checksum(&data.clone()))).unwrap();
    let rhs01 = hex::decode(format!("{:x}", JC_32.checksum(&data.clone()))).unwrap();
    let rhs10 = hex::decode(format!("{:x}", XF_32.checksum(&data.clone()))).unwrap();
    let mut rhs = gcrc128(&data.clone());
    let pos = 32 / 2 / 2;
    rhs[..pos].copy_from_slice(&rhs00);
    rhs[pos..pos + 4].copy_from_slice(&rhs01);
    rhs[pos + 4..pos + 8].copy_from_slice(&rhs10);
    result[..32 / 2].copy_from_slice(&lhs);
    result[32 / 2..].copy_from_slice(&rhs);
    result
}

#[cfg(test)]
mod gcrc256_tests {
    use crate::hashis::gcrc256;
    use k9::assert_equal;

    #[test]
    pub fn test_gcrc256() {
        let input = b"seemingly random bytes";
        let result = gcrc256(input).to_vec();
        assert_equal!(
            result.to_vec(),
            [
                191, 169, 137, 251, 220, 177, 82, 102, 21, 171, 252, 2, 244, 126, 59, 185, 179, 0,
                173, 151, 198, 10, 130, 193, 46, 161, 160, 24, 27, 76, 161, 3
            ]
            .to_vec()
        );
    }
}
