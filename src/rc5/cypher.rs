use std::cmp::max;
use std::convert::TryInto;
#[derive(Debug)]
pub enum Rc5Error {
    InvalidKeyLen,
    BufferOutOfBounds,
}

#[derive(Debug)]
pub enum Rc5Version {
    Rc5_32_12_16,
    Rc5_32_16_16,
}

pub struct Rc5 {
    /// The expanded secret key table.
    secret_key_table: Vec<u32>,

    /// The word size in bits.
    word_size: u32,

    /// The number of rounds
    num_rounds: usize,

    /// The key length
    key_len: usize,

    /// Magic Constants determined by the size of W.
    magic_constant_p: u32,
    magic_constant_q: u32,

    /// Number of bytes in each word.
    bytes_per_word: usize,
}

impl Rc5 {
    pub fn new(key: &[u8], version: Rc5Version) -> Result<Self, Rc5Error> {
        let (num_rounds, word_size, key_len, magic_constant_p, magic_constant_q) = match version {
            Rc5Version::Rc5_32_12_16 => (12, 32, 16, 0xB7E15163, 0x9E3779B9),
            Rc5Version::Rc5_32_16_16 => (16, 32, 16, 0xB7E15163, 0x9E3779B9),
        };

        if key.len() != key_len {
            return Err(Rc5Error::InvalidKeyLen);
        }

        let bytes_per_word = (word_size / 8) as usize;
        let mut rc5 = Self {
            secret_key_table: vec![],
            word_size,
            num_rounds,
            key_len,
            magic_constant_p,
            magic_constant_q,
            bytes_per_word,
        };
        rc5.expand_key(key);

        Ok(rc5)
    }

    fn expand_key(&mut self, key: &[u8]) {
        let num_blocks = max(self.key_len as usize, 1) / self.bytes_per_word;

        let mut l: Vec<u32> = vec![0; self.key_len - 1];
        for (i, b) in key.iter().enumerate().rev() {
            l[i / self.bytes_per_word] =
                (l[i / self.bytes_per_word].checked_shl(8).unwrap_or(0)).wrapping_add(*b as u32);
        }

        let num_words = ((self.num_rounds + 1) * 2) as usize;
        let mut secret_key_table = vec![0; num_words];

        secret_key_table[0] = self.magic_constant_p;
        for i in 1..num_words {
            secret_key_table[i] = secret_key_table[i - 1].wrapping_add(self.magic_constant_q);
        }

        // Mix the secret key.
        let mut i = 0;
        let mut j = 0;

        let mut a: u32 = 0;
        let mut b: u32 = 0;

        for _ in 0..max(num_words, num_blocks) * 3 {
            secret_key_table[i] =
                self.rotate_left(secret_key_table[i].wrapping_add(a.wrapping_add(b)), 3);
            a = secret_key_table[i];

            let a_b = a.wrapping_add(b);
            l[j] = self.rotate_left(l[j].wrapping_add(a_b), a_b);
            b = l[j];

            i = (i + 1) % num_words;
            j = (j + 1) % num_blocks;
        }

        self.secret_key_table = secret_key_table;
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, Rc5Error> {
        let words = self.le_bytes_to_words(&plaintext)?;
        let mut a = words[0].wrapping_add(self.secret_key_table[0]);
        let mut b = words[1].wrapping_add(self.secret_key_table[1]);

        for i in 1..=self.num_rounds {
            a = self
                .rotate_left(a ^ b, b)
                .wrapping_add(self.secret_key_table[2 * i]);
            b = self
                .rotate_left(b ^ a, a)
                .wrapping_add(self.secret_key_table[2 * i + 1]);
        }

        Ok(self.words_to_le_bytes(&[a, b]))
    }

    fn rotate_left(&self, x: u32, y: u32) -> u32 {
        x.wrapping_shl((y & (self.word_size - 1)) as u32)
            | x.wrapping_shr((self.word_size - (y & (self.word_size - 1))) as u32)
    }

    fn rotate_right(&self, x: u32, y: u32) -> u32 {
        x.wrapping_shr((y & (self.word_size - 1)) as u32)
            | x.wrapping_shl((self.word_size - (y & (self.word_size - 1))) as u32)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Rc5Error> {
        let words = self.le_bytes_to_words(&ciphertext)?;
        let mut b = words[1];
        let mut a = words[0];

        for i in (1..=self.num_rounds).rev() {
            b = self.rotate_right(b.wrapping_sub(self.secret_key_table[2 * i + 1]), a) ^ a;
            a = self.rotate_right(a.wrapping_sub(self.secret_key_table[2 * i]), b) ^ b;
        }
        b = b.wrapping_sub(self.secret_key_table[1]);
        a = a.wrapping_sub(self.secret_key_table[0]);

        Ok(self.words_to_le_bytes(&[a, b]))
    }

    fn le_bytes_to_words(&self, block: &[u8]) -> Result<[u32; 2], Rc5Error> {
        if block.len() < self.bytes_per_word {
            return Err(Rc5Error::BufferOutOfBounds);
        }

        let mut word_buf = [0u32; 2];
        word_buf[0] = u32::from_le_bytes(block[..self.bytes_per_word].try_into().unwrap());
        word_buf[1] = u32::from_le_bytes(block[self.bytes_per_word..].try_into().unwrap());
        Ok(word_buf)
    }

    fn words_to_le_bytes(&self, words: &[u32; 2]) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&words[0].to_le_bytes());
        bytes.extend_from_slice(&words[1].to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];

        let rc5 = Rc5::new(&key, Rc5Version::Rc5_32_12_16).unwrap();
        let res = rc5.encrypt(pt.clone()).unwrap();

        assert_eq!(ct, res);
    }
    #[test]
    fn encode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let rc5 = Rc5::new(&key, Rc5Version::Rc5_32_12_16).unwrap();
        let res = rc5.encrypt(pt.clone()).unwrap();

    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
    	let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let rc5 = Rc5::new(&key, Rc5Version::Rc5_32_12_16).unwrap();
        let res = rc5.decrypt(&ct).unwrap();
    	assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
    	let ct  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let rc5 = Rc5::new(&key, Rc5Version::Rc5_32_12_16).unwrap();
        let res = rc5.decrypt(&ct).unwrap();
    	assert!(&pt[..] == &res[..]);
    }
}
