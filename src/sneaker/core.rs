pub const MAGIC_WIDTH: usize = 33;

pub fn magic_id() -> Vec<u8> {
    [
        0x00, 0x00, 0x02, 0x00, 0x01, 0x05, 0x02, 0x00, 0xc4, 0x47, 0x37, 0x31, 0x52, 0x4f, 0x00,
        0x57, 0x4d, 0x00, 0x55, 0x41, 0x00, 0x45, 0x55, 0x00, 0x44, 0x34, 0x56, 0x31, 0x13, 0x2b,
        0x7c, 0x21, 0x2b, // 2b or not 2b ~?~
    ]
        .to_vec()
}

#[cfg(test)]
mod sneaker_tests {

    use crate::sneaker::core;

    use k9::assert_equal;

    #[test]
    pub fn test_core() {
        let result = core::magic_id();

        assert_equal!(
            result.len(),
            core::MAGIC_WIDTH
        );
        assert_equal!(
            result[5],
            0x05
        );
        assert_equal!(
            result[4],
            0x01
        );

    }
}
