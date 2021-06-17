use std::convert::TryInto;

type WORD = u32; // Should be 32-bit = 4 bytes
const W: u32 = 32; // word size in bits
const R: u32 = 12; // number of rounds
const B: usize = 16; // number of bytes in key
const C: usize = 4; // number  words in key = ceil(8*b/w)
const T: usize = 26; // size of table S = 2*(r+1) words
const P: WORD = 0xb7e15163; // magic constants
const Q: WORD = 0x9e3779b9; // magic constants

pub struct RC5 {
    pub s: [WORD; T], // expanded key table
}

impl RC5 {
    pub fn new() -> Self {
        Self { s: [0; T] }
    }

    fn rotl(x: WORD, y: WORD) -> WORD {
        (x << (y & (W - 1))) | (x.wrapping_shr(W - (y & (W - 1))))
    }

    fn rotr(x: WORD, y: WORD) -> WORD {
        (x >> (y & (W - 1))) | (x.wrapping_shl(W - (y & (W - 1))))
    }

    pub fn encrypt(&mut self, pt: &[WORD; 2]) -> Vec<WORD> {
        let s = &mut self.s;
        let mut a = pt[0].wrapping_add(s[0]);
        let mut b = pt[1].wrapping_add(s[1]);
        for i in 1..=(R as usize) {
            a = Self::rotl(a ^ b, b).wrapping_add(s[2 * i]);
            b = Self::rotl(b ^ a, a).wrapping_add(s[2 * i + 1]);
        }
        vec![a, b]
    }

    pub fn decrypt(&mut self, ct: &[WORD; 2]) -> Vec<WORD> {
        let mut b = ct[1];
        let mut a = ct[0];

        let s = &mut self.s;
        for i in (1..=(R as usize)).rev() {
            b = Self::rotr(b.wrapping_sub(s[2 * i + 1]), a) ^ a;
            a = Self::rotr(a.wrapping_sub(s[2 * i]), b) ^ b;
        }
        vec![a.wrapping_sub(s[0]), b.wrapping_sub(s[1])]
    }

    pub fn setup(&mut self, key: &[u8]) {
        let u = (W / 8) as usize;
        let mut l: [WORD; C] = [0; C];
        l[C - 1] = 0;
        /* Initialize L, then S, then mix key into S */
        for i in (0..B).rev() {
            l[i / u] = (l[i / u] << 8) + key[i] as u32;
        }
        let s = &mut self.s;
        s[0] = P;
        for i in 1..T {
            s[i] = s[i - 1].wrapping_add(Q);
        }
        let mut a: WORD = 0;
        let mut b = 0;
        let mut i = 0;
        let mut j = 0;
        for _ in 0..3 * T {
            s[i] = Self::rotl(s[i].wrapping_add(a.wrapping_add(b)), 3);
            a = s[i];
            l[j] = Self::rotl(l[j].wrapping_add(a.wrapping_add(b)), a.wrapping_add(b));
            b = l[j];
            i = (i + 1) % T;
            j = (j + 1) % C;
        }
    }
}

pub trait Convert<T> {
    fn convert(self) -> T;
}

impl Convert<Vec<u32>> for Vec<u8> {
    fn convert(self) -> Vec<u32> {
        self.chunks(4)
            .map(|x| u32::from_ne_bytes(x.try_into().unwrap()))
            .collect()
    }
}

impl Convert<Vec<u8>> for Vec<u32> {
    fn convert(self) -> Vec<u8> {
        self.iter()
            .map(|&x| {
                let x: Vec<u8> = x.to_ne_bytes().into();
                x
            })
            .flatten()
            .collect()
    }
}

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
fn encode(key: Vec<u8>, pt: Vec<u8>) -> Vec<u8> {
    let mut rc5 = RC5::new();
    rc5.setup(key.as_slice());
    let pt = pt.convert().try_into().unwrap();
    rc5.encrypt(&pt).convert()
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let mut rc5 = RC5::new();
    rc5.setup(key.as_slice());
    let ct = ciphertext.convert().try_into().unwrap();
    rc5.decrypt(&ct).convert()
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
        let res = encode(key, pt);
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let res = encode(key, pt);
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let res = decode(key, ct);
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let res = decode(key, ct);
        assert!(&pt[..] == &res[..]);
    }
}
