// use crate::errors::Error;

const DEFAULT_PAD_BYTE: u8 = 0x00;

use crate::aescbc::tp::B128;
pub trait Padder128 {
    fn pad(&self, msg: &[u8]) -> B128;
    fn unpad(&self, msg: &[u8]) -> Vec<u8>;
    fn padbyte(&self) -> u8;
}

#[derive(Debug, Clone)]
pub enum Padding {
    Ansix923(Ansix923),
}

impl Padder128 for Padding {
    fn pad(&self, msg: &[u8]) -> B128 {
        match self {
            Padding::Ansix923(engine) => engine.pad(msg),
        }
    }
    fn unpad(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Padding::Ansix923(engine) => engine.unpad(msg),
        }
    }
    fn padbyte(&self) -> u8 {
        match self {
            Padding::Ansix923(engine) => engine.padbyte(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct Ansix923 {
    rc: u8,
}

impl Ansix923 {
    pub fn new(padbyte: u8) -> Ansix923 {
        Ansix923 { rc: padbyte }
    }
}

impl Padder128 for Ansix923 {
    fn pad(&self, msg: &[u8]) -> B128 {
        let mut padded = [0xfe; 16];
        padded.fill(self.padbyte());
        let pos = msg.len();
        let remainder = pos % 16;
        let remaining = 0x10 - remainder;
        padded[..pos].clone_from_slice(&msg);
        if remaining == 0 {
            return padded;
        }
        padded[pos..].fill(self.padbyte());
        // ANSI X923
        padded[0x10 - 1] = remaining as u8;
        padded
    }
    fn unpad(&self, msg: &[u8]) -> Vec<u8> {
        let abs_len = msg.len();
        let padbyte = self.padbyte();
        let last_pos = abs_len - 1;
        let pad_len = msg[last_pos] as usize;

        if pad_len > 0xf {
            return msg.to_vec();
        }
        for pad_pos in (abs_len - pad_len)..(abs_len - 1) {
            let padchar = msg[pad_pos];
            if padchar != padbyte {
                // XXX: if feature[validation] return Error::UnpadError
                return msg.to_vec();
            }
        }
        let mut preamble: Vec<u8> = Vec::with_capacity(abs_len);
        preamble.resize(abs_len, 0xff);
        preamble.copy_from_slice(&msg);
        let cut_pos = abs_len - pad_len;
        let result = preamble[..cut_pos].to_vec();
        result
    }
    fn padbyte(&self) -> u8 {
        self.rc
    }
}

#[cfg(test)]
mod padder128_tests {
    use crate::aescbc::pad::{Ansix923, Padder128};
    use crate::aescbc::tp::B128;
    use k9::assert_equal;

    #[test]
    pub fn test_dummy_padding() {
        let msg = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde,
        ];
        let gsm = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xff,
            0xff, 0x04,
        ];
        let mut padded = [0xfe; 0x10];
        assert_equal!(padded, [0xfe; 0x10]);
        padded.fill(0xff as u8);
        assert_equal!(padded, [0xff; 0x10]);
        let pos = msg.len();
        assert_equal!(pos, 12);
        padded[..pos].clone_from_slice(&msg);
        padded[pos..].fill(0xff as u8);
        assert_equal!(
            padded,
            [
                0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xff,
                0xff, 0xff,
            ]
        );
        // ANSI X923
        let remainder = pos % 0x10;
        let remaining = 0x10 - remainder;
        assert_equal!(remainder, 12);
        assert_equal!(remaining, 0x4);
        padded[pos + remaining - 1] = remaining as u8;
        assert_equal!(padded, gsm);
    }

    #[test]
    pub fn test_dummy_unpadding() {
        let msg: B128 = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xff,
            0xff, 0x04,
        ];
        assert_equal!(
            msg,
            [
                0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xff,
                0xff, 0x04,
            ]
        );
        let abs_len = msg.len();
        assert_equal!(abs_len, 0x10);
        let last_pos = abs_len - 1;
        assert_equal!(last_pos, 15);
        let mut preamble: Vec<u8> = Vec::with_capacity(abs_len);
        preamble.resize(abs_len, 0xff);
        preamble.copy_from_slice(&msg);
        assert_equal!(preamble, msg);

        let pad_len = preamble[last_pos] as usize;
        assert_equal!(pad_len, 0x4);

        let cut_pos = abs_len - pad_len;
        assert_equal!(cut_pos, 12);

        let result = preamble[..cut_pos].to_vec();
        assert_equal!(
            result,
            [0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde].to_vec()
        );
    }

    #[test]
    pub fn test_only_padding() {
        // Given a padder with 0xff as padbyte
        let padder = Ansix923::new(0xff as u8);

        // And a block with remainder of modulus 0x10 = 0x4
        let block12 = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde,
        ];

        // When I pad that block
        let result = padder.pad(&block12);

        // Then the result is padded with 0xff and terminates with the size of the remainder
        let expected_block: B128 = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xff,
            0xff, 0x04,
        ];
        assert_equal!(result, expected_block);
    }

    #[test]
    pub fn test_only_unpadding() {
        // Given a padder with 0xff as padbyte
        let padder = Ansix923::new(0xff as u8);

        // And a padded block
        let pad_block: B128 = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xff,
            0xff, 0x04,
        ];

        // When I unpad that block
        let result = padder.unpad(&pad_block);

        // Then the result is padded with 0xff and terminates with the size of the remainder
        let expected_block = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde,
        ];
        assert_equal!(result, expected_block);
    }

    #[test]
    pub fn test_invalid_unpadding_ansi_x923_tail_size_too_long() {
        // Given a padder with 0xff as padbyte
        let padder = Ansix923::new(0xff as u8);

        // And a seemingly padded block whose tail value is larger than that of a 128bits block
        let pad_block: B128 = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xff,
            0xff, 0xf0,
        ];

        // When I try to unpad that block
        let result = padder.unpad(&pad_block);

        // Then the seemingly padded block is left untouched
        let expected_block = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xff,
            0xff, 0xf0,
        ];
        assert_equal!(result, expected_block);
    }

    #[test]
    pub fn test_invalid_unpadding_ansi_x923_padbyte_mismatch() {
        // Given a padder with 0xff as padbyte
        let padder = Ansix923::new(0xff as u8);

        // And a seemingly padded block containing a character that does not match the padbyte
        let pad_block: B128 = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xf5,
            0xff, 0x04,
        ];

        // When I try to unpad that block
        let result = padder.unpad(&pad_block);

        // Then the seemingly padded block is left untouched
        let expected_block = [
            0x1c, 0xeb, 0x00, 0xda, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xde, 0xff, 0xf5,
            0xff, 0x04,
        ];
        assert_equal!(result, expected_block);
    }
}
