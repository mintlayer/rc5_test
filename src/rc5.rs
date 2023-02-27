use crate::utils;
use crate::word::{Word, WordBuilder, LargestType};

pub struct RC5 {
	word_size: usize, // number of bits per word
	num_rounds: u8, // number of encryption/decryption rounds
	key_size: u8, // number of bytes of the secret key
	word_builder: WordBuilder,
	magic_constant_p: Word,
	magic_constant_q: Word,
}

impl RC5 {
	pub fn new(word_size: usize, num_rounds: u8, key_size: u8) -> Self {

		let word_builder = WordBuilder::new(word_size as LargestType);
		let (p, q) = RC5::get_magic_constants(&word_builder,
			word_size);
		Self {
			word_size: word_size,
			num_rounds: num_rounds,
			key_size: key_size,
			word_builder: word_builder,
			magic_constant_p: p,
			magic_constant_q: q,
		}
	}

	fn get_magic_constants(word_builder: &WordBuilder,
		 word_size_in_bits: usize) -> (Word, Word) {
		// I acquired these values by manually running the test "calc_magic_consts_test()"
		// contained in 'utils.rs'.

		match word_size_in_bits {
			8 => (
				word_builder.build_word(0xB7),
				word_builder.build_word(0x9F),
			),
			16 => (
				word_builder.build_word(0xB7E1),
				word_builder.build_word(0x9E37),
			),
			32 => (
				word_builder.build_word(0xB7E15163),
				word_builder.build_word(0x9E3779B9),
			),
			64 => (
				word_builder.build_word(0xB7E151628AED2A6B),
				word_builder.build_word(0x9E3779B97F4A7C15),
			),
			128 => (
				word_builder.build_word(0xB7E151628AED2A6ABF7158809CF4F3C7),
				word_builder.build_word(0x9E3779B97F4A7C15F39CC0605CEDC835),
			),
			_ => panic!("Unsoported word size {}", word_size_in_bits),
		}
	}

	/// Converts Vec<u8> to Vec<Word<T>>
	fn parse(&self, input: &[u8]) -> Vec<Word> {
		assert!(self.word_size % 8 == 0);

		let input_size = input.len();
		let num_bytes_per_word = self.word_size / 8;
		let num_words = utils::div_ceil(input_size, num_bytes_per_word);

		let mut ret = self.word_builder.new_word_vec(num_words);

		for i in (0..input_size).rev() {
			if num_bytes_per_word > 1 {
				ret[i / num_bytes_per_word] = (ret[i / num_bytes_per_word] << 8_u8) + input[i];
			}
			else {
				ret[i / num_bytes_per_word] = self.word_builder.build_word(input[i] as LargestType);
			}
		}

		ret
	}

	/// Converts Vec<Word<T>> to Vec<u8>
	fn serialize(&self, output: &Vec<Word>) -> Vec<u8> {
		assert!(self.word_size % 8 == 0);

		let num_bytes_per_word = self.word_size / 8;
		let num_bytes = output.len() * num_bytes_per_word;
		let mut ret = vec![0_u8 ; num_bytes];
		let mut i = 0_usize;

		for w in output.iter() {

			for byte in w.to_le_bytes() {
				ret[i] = byte;
				i = i +1;
			}
		}

		ret
	}

	pub fn key_expansion(&self, key: &[u8]) -> Vec<Word> {

		// Converting the Secret Key from Bytes to Words.
		let key_size = key.len();

		let bytes_per_word = self.word_size / 8;
		let num_words = utils::div_ceil(key_size, bytes_per_word);

		let mut l = self.parse(key);

		// Initializing the array S.
		let t = 2 * (self.num_rounds + 1) as usize;
		let mut s = self.word_builder.new_word_vec(t);

		s[0] = self.magic_constant_p;
		for i in 1..t {
			s[i] = s[i - 1] + self.magic_constant_q;
		}

		// Mixing in the Secret Key.
		let mut a = self.word_builder.build_word(0);
		let mut b = self.word_builder.build_word(0);
		
		let num_iterations = 3 * std::cmp::max(t, num_words);
		let mut i = 0_usize;
		let mut j = 0_usize;
		for _ in 0..num_iterations {
			s[i] = (s[i] + (a + b)) << 3_u8;
			a = s[i];

			l[j] = (l[j] + (a + b)) << (a + b);
			b = l[j];

			i = (i + 1) % t;
			j = (j + 1) % num_words;
		}

		s
	}

	pub fn encrypt(&self, key: &[u8], input_u8: &[u8]) -> Vec<u8> {
		assert!(key.len() == self.key_size as usize);

		let s = self.key_expansion(key);

		let input = self.parse(input_u8);

		let mut a = input[0] + s[0];
		let mut b = input[1] + s[1];

		for i in 1..=self.num_rounds {
			a = ((a ^ b) << b) + s[ 2 * i as usize ];
			b = ((b ^ a) << a) + s[ 2 * i as usize + 1 ];
		}

		let mut output = Vec::new();
		output.push(a);
		output.push(b);
		
		return self.serialize(&output);
	}

	pub fn decrypt(&self, key: &[u8], input_u8: &[u8]) -> Vec<u8> {
		assert!(key.len() == self.key_size as usize);

		let s = self.key_expansion(key);

		let input = self.parse(input_u8);

		let mut a = input[0];
		let mut b = input[1];

		for i in (1..=self.num_rounds).rev() {
			b = ((b - s[ 2 * i as usize + 1 ]) >> a) ^ a;
			a = ((a - s[ 2 * i as usize ]) >> b) ^ b;
		}

		let mut output = Vec::new();
		output.push(a - s[0]);
		output.push(b - s[1]);
		
		return self.serialize(&output);
	}

}

#[cfg(test)]
mod tests {

use super::*;

	#[test]
	fn serde_test() {
		let rc5 = RC5::new(32, 12, 16);
		let original = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
		let parsed = rc5.parse(&original);
		let res = rc5.serialize(&parsed);
		assert_eq!(&original[..], &res[..] );
	}

	#[test]
	fn key_expansion_test() {
		// This test is aimed to debug the 'key_expansion' method.
		let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
		let rc5 = RC5::new(16, 16, 8);
		rc5.key_expansion(&key);
	}
}
