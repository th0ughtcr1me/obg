pub mod core {
    pub const MAGIC_WIDTH: usize = 33;

    pub fn magic_id() -> Vec<u8> {
        [
            0x00, 0x00, 0x02, 0x00, 0x00, 0x42, 0x02, 0x00, 0xc4, 0x47, 0x37, 0x31, 0x52, 0x4f, 0x00,
            0x57, 0x4d, 0x00, 0x55, 0x41, 0x00, 0x45, 0x55, 0x00, 0x44, 0x34, 0x56, 0x31, 0x13, 0x2b,
            0x7c, 0x21, 0x2b, // 2b or not 2b ~?~
        ]
            .to_vec()
    }
}

pub mod io {
    use crate::sneaker::core;
    use crate::errors::Error;
    use std::io::{Read, Seek};

    pub fn is_snuck<S: Read + Seek>(source: &mut S) -> Result<bool, Error> {
        let mut start: Vec<u8> = Vec::new();
        start.resize(core::MAGIC_WIDTH, 0x37);
        source.rewind()?;
        source.read_exact(&mut start)?;
        Ok(start == core::magic_id())
    }
}

#[cfg(test)]
mod sneaker_tests {
    use std::io::Cursor;
    use crate::sneaker::core;
    use crate::sneaker::io;
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
            0x42
        );
        assert_equal!(
            result[4],
            0x00
        );

    }
    #[test]
    pub fn test_io() {
        let mut inner: Vec<u8> = Vec::new();
        inner.extend_from_slice(&core::magic_id());
        inner.resize(72, 0x47);
        let mut buf = Cursor::new(inner);

        let result = io::is_snuck(&mut buf).unwrap();

        assert_equal!(
            result,
            true
        );
    }
}
