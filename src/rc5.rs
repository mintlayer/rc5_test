
use std::ops::{Add, Sub, Shl, Shr, BitOr, BitAnd, BitXor};
use std::marker::PhantomData;

use num::{ToPrimitive, Unsigned};

use crate::utils;

pub trait WordType : Unsigned {}

macro_rules! implement_word_ops {
	($($uint_type: ty),*) => {
        $(
            impl WordType for $uint_type {}
        )*
    }
}

implement_word_ops!(u16, u32, u64, u128);

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct Word<T: WordType> {
	value : T,
}

impl<T: WordType + From<u8>> From<u8> for Word<T> {
    fn from(v: u8) -> Self {
        Self { value: T::from(v) }
    }
}

impl<T: WordType + Add<Output = T> + num::NumCast> Add for Word<T> {
	type Output = Word<T>;

	fn add(self, rhs: Self) -> Self::Output {
		let word_size = std::mem::size_of::<T>() * 8;
		let max_val = 2_u128.pow(word_size as u32);
		let self_value = num::cast::<T, u128>(self.value).unwrap();
		let rhs_value = num::cast::<T, u128>(rhs.value).unwrap();
		Self { 
			value: num::cast::<u128, T>(self_value.wrapping_add(rhs_value) % max_val).unwrap()
		}
    }
}

impl<T: WordType + Sub<Output = T> + num::NumCast> Sub for Word<T> {
	type Output = Word<T>;

	fn sub(self, rhs: Self) -> Self::Output {
		let word_size = std::mem::size_of::<T>() * 8;
		let max_val = 2_u128.pow(word_size as u32);
		let self_value = num::cast::<T, u128>(self.value).unwrap();
		let rhs_value = num::cast::<T, u128>(rhs.value).unwrap();
		Self {
			value: num::cast::<u128, T>(self_value.wrapping_sub(rhs_value) % max_val).unwrap()
		}
    }
}

impl<T: WordType + Shl<Output = T> + From<u8>> Shl<u8> for Word<T> {
	type Output = Word<T>;

	fn shl(self, rhs: u8) -> Self::Output {
		Self { value: self.value << T::from(rhs) }
	}
}

impl<T: WordType + Shr<Output = T> + From<u8>> Shr<u8> for Word<T> {
	type Output = Word<T>;

	fn shr(self, rhs: u8) -> Self::Output {
		Self { value: self.value >> T::from(rhs) }
	}
}

impl<T> Shl<Self> for Word<T>
	where T:
		WordType + 
		Shl<Output = T> + 
		Shr<Output = T> + 
		BitOr<Output = T> +
		Copy + 
		num::NumCast
{
	type Output = Word<T>;

	fn shl(self, rhs: Self) -> Self::Output {
		let word_size = std::mem::size_of::<T>() * 8;
		let word_size = num::cast::<usize, T>(word_size).unwrap() as T;

		let rhs = rhs.value % word_size;

		let left = self.value << rhs;
		let right = self.value >> ((word_size - rhs) % word_size);

		Self { value : left | right}
    }
}

impl<T> Shr for Word<T> 
	where T:
		WordType + 
		Shl<Output = T> + 
		Shr<Output = T> + 
		BitOr<Output = T> +
		Copy + 
		num::NumCast
{
	type Output = Word<T>;

	fn shr(self, rhs: Self) -> Self::Output {
		let word_size = std::mem::size_of::<T>() * 8;
		let word_size = num::cast::<usize, T>(word_size).unwrap() as T;

		let rhs = rhs.value % word_size;

		let left = self.value >> rhs;
		let right = self.value << ((word_size - rhs) % word_size);

		Self { value : left | right}
    }
}

impl<T: WordType + BitOr<Output = T>> BitOr for Word<T> {
	type Output = Word<T>;

	fn bitor(self, rhs: Self) -> Self::Output {
		Self { value : self.value | rhs.value }
    }
}

impl<T: WordType + BitAnd<Output = T>> BitAnd for Word<T> {
	type Output = Word<T>;

	fn bitand(self, rhs: Self) -> Self::Output {
		Self { value : self.value & rhs.value }
    }
}

impl<T: WordType + BitXor<Output = T>> BitXor for Word<T> {
	type Output = Word<T>;

	fn bitxor(self, rhs: Self) -> Self::Output {
		Self { value : self.value ^ rhs.value }
    }
}

pub struct RC5<T: WordType> {
	word_type: PhantomData<T>,
	num_rounds: u32,
	magic_constant_p: Word<T>,
	magic_constant_q: Word<T>,
}

impl<T> RC5<T> 
	where
		T: WordType + 
			Default + 
			Clone + 
			From<u8> +
			Sub<Output = T> +
			BitAnd<Output = T> +
			BitOr<Output = T> +
			BitXor<Output = T> +
			Shl<Output = T> +
			Shr<Output = T> +
			ToPrimitive +
			Copy +
			num::NumCast,
		Word<T>: Add<Output = Word<T>>,
	{
	pub fn new(num_rounds: u32, p: T, q: T) -> Self {
		Self {
			word_type: PhantomData,
			num_rounds: num_rounds,
			magic_constant_p: Word { value: p },
			magic_constant_q: Word { value: q },
		}
	}

	fn get_magic_constants(&self) -> (Word<T>, Word<T>) {
		// let (p16, q16) = (0xB7E1_u16, 0x9E37_u16);
		// ("B7E15163", "9E3779B9")
		// ("B7E151628AED2A6B", "9E3779B97F4A7C15")
		// ("B7E151628AED2A6ABF7158809CF4F3C7", "9E3779B97F4A7C15F39CC0605CEDC835")

		// BigNum::calc_magic_constants(16);

		// TODO: make this more flexible 
		todo!()
	}

	/// Converts Vec<u8> to Vec<Word<T>>
	pub fn parse(&self, input: &Vec<u8>) -> Vec<Word<T>> {
		let input_size = input.len();
		let num_bytes_per_word = std::mem::size_of::<T>();
		let num_words = utils::div_ceil(input_size, num_bytes_per_word);

		let mut ret = vec![ Word { value: T::default() } ; num_words];

		// TODO: there might be a more idiomatic way to do the next.
		let mut i = 0;
		let mut j = input_size;
		for byte in input.iter().rev() {
			j = j - 1;
			ret[j / num_bytes_per_word] = 
				ret[j / num_bytes_per_word] | 
				Word::from(*byte) << 8 * (i % num_bytes_per_word) as u8;
			i = i + 1;
		}

		ret
	}

	/// Converts Vec<Word<T>> to Vec<u8>
	pub fn serialize(&self, output: &Vec<Word<T>>) -> Vec<u8> {

		let num_bytes_per_word = std::mem::size_of::<T>();
		let num_bytes = output.len() * num_bytes_per_word;
		let mut ret = vec![0_u8 ; num_bytes];
		let mut i = 0_usize;
		let mut new_output = output.clone();

		for w in new_output.iter_mut() {
			for j in (0..num_bytes_per_word).rev() {
				let word = *w >> (8 * j as u8) & Word { value: num::cast::<u8, T>(0xFF_u8).unwrap() };
				ret[i] = num::cast::<T, u8>(word.value).unwrap() as u8;
				i = i + 1;
			}
		}

		ret
	}

	pub fn key_expansion(&self, secret_key: &Vec<u8>) -> Vec<Word<T>> {

		// Converting the Secret Key from Bytes to Words.
		let key_size = secret_key.len();

		let num_bytes_per_word = std::mem::size_of::<T>();
		let num_words = utils::div_ceil(key_size, num_bytes_per_word);

		let mut L = vec![ Word { value: T::default() } ; num_words];

		for i in (0..key_size).rev() {
			L[i / num_bytes_per_word] = (L[i / num_bytes_per_word] << 8_u8) + Word::from(secret_key[i]);
		}

		// Initializing the array S.
		let t = 2 * (self.num_rounds + 1) as usize;
		let mut S = vec![ Word { value: T::default() } ; t];

		S[0] = self.magic_constant_p;
		for i in 1..t {
			S[i] = S[i - 1] + self.magic_constant_q;
		}

		// Mixing in the Secret Key.
		let mut A = Word { value: T::default() };
		let mut B = Word { value: T::default() };
		
		let num_iterations = 3 * t;
		let mut i = 0_usize;
		let mut j = 0_usize;
		for _ in 0..num_iterations {
			S[i] = (S[i] + (A + B)) << Word::from(3_u8);
			A = S[i];

			L[j] = (L[j] + (A + B)) << (A + B);
			B = L[j];

			i = (i + 1) % t;
			j = (j + 1) % num_words;
		}

		S
	}

	pub fn encrypt(&self, key: &Vec<u8>, input_u8: &Vec<u8>) -> Vec<u8>{

		let S = self.key_expansion(key);

		let input = self.parse(input_u8);

		let mut A = input[0] + S[0];
		let mut B = input[1] + S[1];

		for i in 1..=self.num_rounds {
			A = ((A ^ B) << B) + S[ 2 * i as usize ];
			B = ((B ^ A) << A) + S[ 2 * i as usize + 1 ];
		}

		let mut output = Vec::new();
		output.push(A);
		output.push(B);
		
		return self.serialize(&output);
	}

	pub fn decrypt(&self, key: &Vec<u8>, input_u8: &Vec<u8>) -> Vec<u8> {
		let S = self.key_expansion(key);

		let input = self.parse(input_u8);

		let mut A = input[0];
		let mut B = input[1];

		for i in (1..=self.num_rounds).rev() {
			B = ((B - S[2*i as usize+1]) >> A) ^ A;
			A = ((A - S[2*i as usize]) >> B) ^ B;
		}

		let mut output = Vec::new();
		output.push(A - S[0]);
		output.push(B - S[1]);
		
		return self.serialize(&output);
	}

}

#[cfg(test)]
mod tests {

use super::*;

	#[test]
	fn serde_test() {
		let original = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
		let rc5 = RC5::new(12, 0xB7E15163_u32, 0x9E3779B9_u32);
		let parsed = rc5.parse(&original);
		let res = rc5.serialize(&parsed);
		assert_eq!(&original[..], &res[..] );
	}

	#[test]
	fn arithmetic_test() {
		assert_eq!(Word {value: 0xFFFF_u16}, Word{value: 0x01_u16} - Word{value: 0x02_u16});
		assert_eq!(Word {value: 0x2_u16}, Word{value: 0x01_u16} - Word{value: 0xFFFF_u16});
		assert_eq!(Word {value: 0x03_u16}, Word{value: 0x02_u16} | Word{value: 0x01_u16});
		assert_eq!(Word {value: 0xFE_u16}, Word{value: 0xFF_u16} ^ Word{value: 0x01_u16});
		assert_eq!(Word {value: 0x0001_u16}, Word{value: 0x0002_u16} + Word{value: 0xFFFF_u16});
		assert_eq!(Word {value: 0x01_u16}, Word{value: 0x23_u16} - Word{value: 0x22_u16});
	}

	#[test]
	fn shift_test() {
		let a = Word { value: 2125_u16 };
		let b = Word { value: 16_u16 };

		let _ = a >> b;

		let a = Word { value: 0x7000_u16 };
		let b = Word { value: 16_u16 };

		assert_eq!(Word{ value: 0x7000 }, a << b);
	}

	#[test]
	fn key_expansion_test() {
		let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
		let rc5 = RC5::new(0, 0xB7E1_u16, 0x9E37_u16) as RC5<u16>;
		rc5.key_expansion(&key);
	}

	#[test]
	fn word_test() {
		assert!(Word{ value : 12345_u16 } == (Word { value : 10045_u16 } + Word { value: 2300_u16 }));
		assert!(Word{ value : 3_u128 } == (Word { value : 34_u128 } - Word { value: 31_u128 }));
		assert!(Word{ value : 16_u64 } == (Word { value : 1_u64 } << Word { value: 4_u64 }));
		assert!(Word{ value : 1_u64 } == (Word { value : 16_u64 } >> Word { value: 4_u64 }));
		assert!(Word{ value : 0_u16 } == (Word { value : 65535_u16 } & Word { value: 0_u16 }));
		assert!(Word{ value : 3_u128 } == (Word { value : 1_u128 } | Word { value: 2_u128 }));
		assert!(Word{ value : 65534_u16 } == (Word { value : 65535_u16 } ^ Word { value: 1_u16 }));
	}

	#[test]
	fn rotate_test() {
		let result = Word { value: 0b00101101_u16 } << Word{value: 1u16};
		assert!(result == Word{value: 0b01011010_u16});

		let result = Word { value: 0b1111111111111101_u16 } << Word{value: 1u16};
		assert!(result == Word{value: 0b1111111111111011_u16});

		let result = Word { value: 0b1111111111111011_u16 } >> Word{value: 1u16};
		assert!(result == Word{value: 0b1111111111111101_u16});

		let result = Word { value: 0b1_u16 } >> Word{value: u16::MAX};
		assert!(result == Word{value: 0b10_u16});

		let result = Word { value: 0b1_u16 } << Word{value: 16u16};
		assert!(result == Word{value: 0b1_u16});
	}

}
