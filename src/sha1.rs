// From https://github.com/Munksgaard/sha1
extern crate byteorder;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use std::num::Wrapping;

fn rotate_left(n: Wrapping<u32>, m: u32) -> Wrapping<u32> {
    Wrapping(n.0.rotate_left(m))
}

/// Returns the SHA-1 hash of the input
///
/// # Arguments
///
/// * `input` - A slice of bytes containing the input
///
/// # Example
///
// ```
// use sha1::sha1;
// let hash = sha1(b"The quick brown fox jumps over the lazy dog");
// ```
pub fn sha1(input: &[u8]) -> Vec<u8> {
    // Straightforward implementation of
    // https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode

    // Initialize variables
    let mut h0 = Wrapping(0x67_45_23_01);
    let mut h1 = Wrapping(0xEF_CD_AB_89);
    let mut h2 = Wrapping(0x98_BA_DC_FE);
    let mut h3 = Wrapping(0x10_32_54_76);
    let mut h4 = Wrapping(0xC3_D2_E1_F0);

    let ml = input.len() as u64 * 8;

    // Pre-processing

    let mut buf = input.to_vec();

    // append the bit '1' to the message e.g. by adding 0x80 if message length
    // is a multiple of 8 bits.
    buf.push(0x80);

    // append 0 ≤ k < 512 bits '0', such that the resulting message length in
    // bits is congruent to −64 ≡ 448 (mod 512)
    let to_fill = 512 - ((buf.len() * 8) % 512) - 64;

    for _ in 0..to_fill / 8 {
        buf.push(0);
    }

    // append ml, the original message length, as a 64-bit big-endian integer.
    // Thus, the total length is a multiple of 512 bits.
    let mlbytes = {
        let mut wtr: Vec<u8> = vec![];
        wtr.write_u64::<BigEndian>(ml).expect("Couldn't write ml");
        wtr
    };

    buf.extend_from_slice(&mlbytes);

    // Process the message in successive 512-bit chunks:
    for chunk in buf.chunks(512 / 8) {
        // break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        let mut w: Vec<Wrapping<u32>> = chunk
            .chunks(4)
            .map(|x| Wrapping(BigEndian::read_u32(x)))
            .collect();

        // Extend the sixteen 32-bit words into eighty 32-bit words
        for i in 16..80 {
            let x = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            w.push(x);
        }

        assert_eq!(w.len(), 80);

        // Initialize hash value for this chunk
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        // Main loop
        for (i, w_i) in w.iter().enumerate() {
            let (f, k) = if i <= 19 {
                ((b & c) | ((!b) & d), Wrapping(0x5A_82_79_99))
            } else if 20 <= i && i <= 39 {
                (b ^ c ^ d, Wrapping(0x6E_D9_EB_A1))
            } else if 40 <= i && i <= 59 {
                ((b & c) | (b & d) | (c & d), Wrapping(0x8F_1B_BC_DC))
            } else {
                (b ^ c ^ d, Wrapping(0xCA_62_C1_D6))
            };

            let tmp = rotate_left(a, 5) + f + e + k + w_i;

            e = d;
            d = c;
            c = rotate_left(b, 30);
            b = a;
            a = tmp;
        }

        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // Produce the final hash value (big-endian) as a 160-bit number
    let mut res: Vec<u8> = Vec::new();
    res.write_u32::<BigEndian>(h0.0).expect("Couldn't write h0");
    res.write_u32::<BigEndian>(h1.0).expect("Couldn't write h1");
    res.write_u32::<BigEndian>(h2.0).expect("Couldn't write h2");
    res.write_u32::<BigEndian>(h3.0).expect("Couldn't write h3");
    res.write_u32::<BigEndian>(h4.0).expect("Couldn't write h4");

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string() {
        let res = sha1(b"");
        let exp = [
            0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60,
            0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09,
        ];

        assert_eq!(exp, res.as_slice());
    }

    #[test]
    fn lazy_dog() {
        let res = sha1(b"The quick brown fox jumps over the lazy dog");
        let exp = [
            0x2F, 0xD4, 0xE1, 0xC6, 0x7A, 0x2D, 0x28, 0xFC, 0xED, 0x84, 0x9E, 0xE1, 0xBB, 0x76,
            0xE7, 0x39, 0x1B, 0x93, 0xEB, 0x12,
        ];

        assert_eq!(exp, res.as_slice());
    }

    #[test]
    fn lazy_cog() {
        let res = sha1(b"The quick brown fox jumps over the lazy cog");
        let exp = [
            0xDE, 0x9F, 0x2C, 0x7F, 0xD2, 0x5E, 0x1B, 0x3A, 0xFA, 0xD3, 0xE8, 0x5A, 0x0B, 0xD1,
            0x7D, 0x9B, 0x10, 0x0D, 0xB4, 0xB3,
        ];

        assert_eq!(exp, res.as_slice());
    }

}
