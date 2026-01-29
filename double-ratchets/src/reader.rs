use crate::errors::RatchetError;

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&[u8], RatchetError> {
        if self.pos + n > self.data.len() {
            return Err(RatchetError::DeserializationFailed);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], RatchetError> {
        self.read_bytes(N)?
            .try_into()
            .map_err(|_| RatchetError::DeserializationFailed)
    }

    pub fn read_u8(&mut self) -> Result<u8, RatchetError> {
        Ok(self.read_bytes(1)?[0])
    }

    pub fn read_u32(&mut self) -> Result<u32, RatchetError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    pub fn read_option(&mut self) -> Result<Option<[u8; 32]>, RatchetError> {
        match self.read_u8()? {
            0x00 => Ok(None),
            0x01 => Ok(Some(self.read_array()?)),
            _ => Err(RatchetError::DeserializationFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bytes() {
        let data = [1, 2, 3, 4, 5];
        let mut reader = Reader::new(&data);

        assert_eq!(reader.read_bytes(2).unwrap(), &[1, 2]);
        assert_eq!(reader.read_bytes(3).unwrap(), &[3, 4, 5]);
    }

    #[test]
    fn test_read_bytes_overflow() {
        let data = [1, 2, 3];
        let mut reader = Reader::new(&data);

        assert!(matches!(
            reader.read_bytes(4),
            Err(RatchetError::DeserializationFailed)
        ));
    }

    #[test]
    fn test_read_array() {
        let data = [1, 2, 3, 4];
        let mut reader = Reader::new(&data);

        let arr: [u8; 4] = reader.read_array().unwrap();
        assert_eq!(arr, [1, 2, 3, 4]);
    }

    #[test]
    fn test_read_u8() {
        let data = [0x42, 0xFF];
        let mut reader = Reader::new(&data);

        assert_eq!(reader.read_u8().unwrap(), 0x42);
        assert_eq!(reader.read_u8().unwrap(), 0xFF);
    }

    #[test]
    fn test_read_u32() {
        let data = [0x00, 0x01, 0x02, 0x03];
        let mut reader = Reader::new(&data);

        assert_eq!(reader.read_u32().unwrap(), 0x00010203);
    }

    #[test]
    fn test_read_option_none() {
        let data = [0x00];
        let mut reader = Reader::new(&data);

        assert_eq!(reader.read_option().unwrap(), None);
    }

    #[test]
    fn test_read_option_some() {
        let mut data = vec![0x01];
        data.extend_from_slice(&[0x42; 32]);
        let mut reader = Reader::new(&data);

        assert_eq!(reader.read_option().unwrap(), Some([0x42; 32]));
    }

    #[test]
    fn test_read_option_invalid_flag() {
        let data = [0x02];
        let mut reader = Reader::new(&data);

        assert!(matches!(
            reader.read_option(),
            Err(RatchetError::DeserializationFailed)
        ));
    }

    #[test]
    fn test_sequential_reads() {
        let mut data = vec![0x01];  // version
        data.extend_from_slice(&[0xAA; 32]);  // 32-byte array
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]);  // u32 = 16

        let mut reader = Reader::new(&data);

        assert_eq!(reader.read_u8().unwrap(), 0x01);
        assert_eq!(reader.read_array::<32>().unwrap(), [0xAA; 32]);
        assert_eq!(reader.read_u32().unwrap(), 16);
    }
}
