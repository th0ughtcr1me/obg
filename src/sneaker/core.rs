pub const STACK_WIDTH: usize = 4;
pub const MAGIC_WIDTH: usize = 33;


pub fn stack() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x02, 0x00,
    ]
}

pub fn magic_id() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x02, 0x00, 0x00, 0x02, 0x02, 0x00, 0xc4, 0x47, 0x37, 0x31, 0x52, 0x4f, 0x00,
        0x57, 0x4d, 0x00, 0x55, 0x41, 0x00, 0x45, 0x55, 0x00, 0x44, 0x34, 0x56, 0x31, 0x13, 0x2b,
        0x7c, 0x21, 0x2b, // 2b or not 2b ~?~
    ]
}



#[cfg(test)]
mod sneaker_tests {

    use crate::sneaker::core;

    use k9::assert_equal;

    #[test]
    pub fn test_core() {
        let zid = core::magic_id();
        let pfx = core::stack();

        assert_equal!(zid.len(), core::MAGIC_WIDTH);
        assert_equal!(zid[5], 0x02);
        assert_equal!(zid[4], 0x00);

        assert_equal!(pfx.len(), 4);
        assert_equal!(pfx, vec![0x00, 0x00, 0x02, 0x00]);
    }
}
