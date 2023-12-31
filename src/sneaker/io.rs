use crate::errors::Error;
use crate::sneaker::core;
use std::io::{Read, Seek};

pub fn xstack<S: Read + Seek>(source: &mut S) -> Result<bool, Error> {
    let mut start: Vec<u8> = Vec::new();
    start.resize(core::STACK_WIDTH, 0x4);
    source.rewind()?;
    source.read_exact(&mut start)?;
    Ok(start == core::stack())
}

pub fn is_snuck<S: Read + Seek>(source: &mut S) -> Result<bool, Error> {
    let mut start: Vec<u8> = Vec::new();
    start.resize(core::MAGIC_WIDTH, 0x37);
    source.rewind()?;
    source.read_exact(&mut start)?;
    Ok(start == core::magic_id())
}

#[cfg(test)]
mod sneaker_tests {
    use crate::sneaker::core;
    use crate::sneaker::io;
    use k9::assert_equal;
    use std::io::Cursor;

    #[test]
    pub fn test_io_stack() {
        let mut inner: Vec<u8> = Vec::new();
        inner.extend_from_slice(&core::stack());
        inner.resize(71, 0x48);
        let mut buf = Cursor::new(inner);

        let result = io::xstack(&mut buf).unwrap();

        assert_equal!(result, true);
    }
    #[test]
    pub fn test_io_is_snuck() {
        let mut inner: Vec<u8> = Vec::new();
        inner.extend_from_slice(&core::magic_id());
        inner.resize(72, 0x47);
        let mut buf = Cursor::new(inner);

        let result = io::is_snuck(&mut buf).unwrap();

        assert_equal!(result, true);
    }
}
