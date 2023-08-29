pub mod core;
pub mod io;

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
