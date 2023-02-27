use std::{ops::{Shl, Add, Sub, Shr, BitAnd, BitXor, BitOr}, u8};

pub type LargestType = u128;

#[derive(Copy, Clone, PartialEq)]
enum WordType {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
}

impl WordType {
    fn new(word_size: LargestType, value: LargestType) -> Self {
        match word_size {
            8 => WordType::U8(value as u8),
            16 => WordType::U16(value as u16),
            32 => WordType::U32(value as u32),
            64 => WordType::U64(value as u64),
            128 => WordType::U128(value as u128),
            _ => panic!("{} word size is not supported", word_size),
        }
    }

    fn max_val(&self) -> LargestType {
        match self {
            WordType::U8(_) => u8::MAX as LargestType,
            WordType::U16(_) => u16::MAX as LargestType,
            WordType::U32(_) => u32::MAX as LargestType,
            WordType::U64(_) => u64::MAX as LargestType,
            WordType::U128(_) => u128::MAX as LargestType,
        }
    }

    /// Extracts a tuple with (num_bits_per_word, value)
    pub fn extract(&self) -> (LargestType, LargestType) {
        let (word_size, value) = match *self {
            WordType::U8(value) => (8, value as LargestType),
            WordType::U16(value) => (16, value as LargestType),
            WordType::U32(value) => (32, value as LargestType),
            WordType::U64(value) => (64, value as LargestType),
            WordType::U128(value) => (128, value as LargestType),
        };

        (word_size, value)
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        match self {
            WordType::U8(value) => value.to_le_bytes().to_vec(),
            WordType::U16(value) => value.to_le_bytes().to_vec(),
            WordType::U32(value) => value.to_le_bytes().to_vec(),
            WordType::U64(value) => value.to_le_bytes().to_vec(),
            WordType::U128(value) => value.to_le_bytes().to_vec(),
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
pub struct Word {
    data: WordType,
}

#[derive(Clone, Copy)]
pub struct WordBuilder {
    word_size: LargestType, // word size in bits. constraint of the word types to be generated
}

impl WordBuilder {
    pub fn new(word_size: LargestType) -> Self {
        Self { word_size }
    }
    
    pub fn build_word(&self, value: LargestType) -> Word {
        Word::new(self.word_size, value)
    }

    /// Creates a new word vector.
    pub fn new_word_vec(&self, num_words: usize) -> Vec<Word> {
        vec![self.build_word(0) ; num_words]
    }
}

impl Word {
    /// Creates a new word initialized to zero.
    fn new(word_size: LargestType, value: LargestType) -> Self {
        Self {
            data: WordType::new(word_size, value)
        }
    }

    fn check_types(&self, rhs: Word) {
        if std::mem::discriminant(&self.data) != 
            std::mem::discriminant(&rhs.data) {
                panic!("The types dimension should match in the operation");
        }
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        self.data.to_le_bytes()
    }
}

impl Shl<Word> for Word {
    type Output = Word;

    fn shl(self, rhs: Word) -> Self::Output {
        self.check_types(rhs);

        let (word_size, self_value) = self.data.extract();
        let (_, rhs_value) = rhs.data.extract();

        let shift_amount = rhs_value % word_size;

        let left = self_value << shift_amount;
        let right = self_value >> ((word_size - shift_amount) % word_size);

        Word::new(word_size, left | right)
    }
}

impl Shl<u8> for Word {
    type Output = Word;

    fn shl(self, rhs: u8) -> Self::Output {
        let (word_size, self_value) = self.data.extract();
        
        let shift_amount = rhs as LargestType % word_size;

        let left = self_value << shift_amount;
        let right = self_value >> ((word_size - shift_amount) % word_size);

        Word::new(word_size, left | right)
    }
}

impl Shr<Word> for Word {
    type Output = Word;

    fn shr(self, rhs: Word) -> Self::Output {
        self.check_types(rhs);

        let (word_size, self_value) = self.data.extract();
        let (_, rhs_value) = rhs.data.extract();

        let shift_amount = rhs_value % word_size;

        let left = self_value >> shift_amount;
        let right = self_value << ((word_size - shift_amount) % word_size);

        Word::new(word_size, left | right)
    }
}

impl BitOr for Word {
	type Output = Word;

	fn bitor(self, rhs: Self) -> Self::Output {
        self.check_types(rhs);

        let (word_size, self_value) = self.data.extract();
        let (_, rhs_value) = rhs.data.extract();

        Word::new(word_size, self_value | rhs_value)
    }
}

impl BitAnd for Word {
	type Output = Word;

	fn bitand(self, rhs: Self) -> Self::Output {
        self.check_types(rhs);

        let (word_size, self_value) = self.data.extract();
        let (_, rhs_value) = rhs.data.extract();

        Word::new(word_size, self_value & rhs_value)
    }
}

impl BitXor for Word {
	type Output = Word;

	fn bitxor(self, rhs: Self) -> Self::Output {
        self.check_types(rhs);

        let (word_size, self_value) = self.data.extract();
        let (_, rhs_value) = rhs.data.extract();

        Word::new(word_size, self_value ^ rhs_value)
    }
}

impl Add for Word {
    type Output = Word;

    fn add(self, rhs: Self) -> Self::Output {
        self.check_types(rhs);

        let (word_size, self_value) = self.data.extract();
        let (_, rhs_value) = rhs.data.extract();

        let max_val = self.data.max_val() + 1;

        Word::new(word_size, (self_value + rhs_value) % max_val)
    }
}

impl Add<u8> for Word {
    type Output = Word;

    fn add(self, rhs: u8) -> Self::Output {
        let (word_size, self_value) = self.data.extract();

        let max_val = self.data.max_val() + 1;

        Word::new(word_size, (self_value + rhs as LargestType) % max_val)
    }
}

impl Sub for Word {
	type Output = Word;

	fn sub(self, rhs: Self) -> Self::Output {
        self.check_types(rhs);

        let (word_size, mut self_value) = self.data.extract();
        let (_, mut rhs_value) = rhs.data.extract();

        let max_val = self.data.max_val();

        self_value = self_value % ( max_val + 1 );
        rhs_value = rhs_value % ( max_val + 1 );

        let result: LargestType;
        if self_value > rhs_value {
            result = self_value - rhs_value;
        }
        else {
            result = max_val - rhs_value + self_value + 1;
        }

        Word::new(word_size, result)
    }
}

#[cfg(test)]
mod word_test {
    use super::*;

    #[test]
    fn arithmetic_test() {
        let wb = WordBuilder::new(16);

        assert!(wb.build_word(0x3002) == wb.build_word(0x3000) + 2_u8);
        assert!(wb.build_word(0x3039) == wb.build_word(0x3000) + wb.build_word(0x0039));
		assert!(wb.build_word(3) == wb.build_word(34) - wb.build_word(31));
		assert!(wb.build_word(0) == wb.build_word(0x00FF) & wb.build_word(0));
		assert!(wb.build_word(3) == wb.build_word(1) | wb.build_word(2));
		assert!(wb.build_word(0xFFFE) == wb.build_word(0xFFFF) ^ wb.build_word(0x0001));
    }

    #[test]
    fn rotate_test() {
        let wb = WordBuilder::new(16);

        assert!(wb.build_word(0x0022) == wb.build_word(0x0011) << wb.build_word(1));
        assert!(wb.build_word(16) == wb.build_word(1) << wb.build_word(4));
		assert!(wb.build_word(1) == wb.build_word(16) >> wb.build_word(4));

		let result = wb.build_word(0b1111111111111101) << 1_u8;
		assert!(result == wb.build_word(0b1111111111111011));

        let result = wb.build_word(0b1111111111111101) << wb.build_word(1);
		assert!(result == wb.build_word(0b1111111111111011));

		let result = wb.build_word(0b1111111111111011) >> wb.build_word(1);
		assert!(result == wb.build_word(0b1111111111111101));

		let result = wb.build_word(1) >> wb.build_word(0xFFFF);
		assert!(result == wb.build_word(0b10));

		let result = wb.build_word(0b1) << wb.build_word(16);
		assert!(result == wb.build_word(0b1));

        let result = wb.build_word(0x7000) << wb.build_word(0x0100);
		assert!(wb.build_word(0x7000) == result);

        let result = wb.build_word(0x7000) >> wb.build_word(0x0100);
		assert!(wb.build_word(0x7000) == result);

        let result = wb.build_word(0x7000) << wb.build_word(0x0008);
		assert!(wb.build_word(0x0070) == result);

        let result = wb.build_word(0x7000) >> wb.build_word(0x0008);
		assert!(wb.build_word(0x0070) == result);

	}
}
