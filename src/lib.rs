extern crate itertools;
extern crate base64;

#[cfg(test)]
mod tests {
    mod set1 {
        use convert;
        use util;

        #[test]
        fn challenge1() {
            let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

            let bytes = convert::hex2bytes(&hex_str).expect("Couldn't parse constant as hex");
            let b64_str = convert::bytes2base64(&bytes);
            let expected_b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            assert_eq!(expected_b64_str, b64_str);
        }

        #[test]
        fn challenge2() {
            util::xor("1234".as_bytes(), "12345".as_bytes()).unwrap_err();

            assert_eq!(util::xor("".as_bytes(), "".as_bytes()).unwrap(), "".as_bytes());

            let xs = convert::hex2bytes("1c0111001f010100061a024b53535009181c").unwrap();
            let ys = convert::hex2bytes("686974207468652062756c6c277320657965").unwrap();

            let expected = convert::hex2bytes("746865206b696420646f6e277420706c6179").unwrap();
            assert_eq!(util::xor(&xs, &ys).unwrap(), expected);
        }
    }
}

pub mod util {

    pub fn xor(xs: &[u8], ys: &[u8]) -> Result<Vec<u8>, String> {
        if xs.len() != ys.len() {
            return Err(format!("xor: buf size mismatch: {} != {}", xs.len(), ys.len()))
        }
        Ok(xs.iter().zip(ys.iter()).map(|xy| {xy.0 ^ xy.1}).collect())
    }
}

pub mod convert {

    use itertools::Itertools;
    use base64;

    pub fn hex2bytes(hex_str: &str) -> Result<Vec<u8>, String> {
        // Get iterator of nibbles-or-errors
        hex_str.chars().map(hexchar2nibble).batching(|it| {
            match it.next() {
                None => None,
                Some(x) => match it.next() {
                    None => None,
                    Some(y) => Some((x, y)),
                }
            }}).map(hilo2byte).collect()
    }

    pub fn bytes2base64(bytes: &[u8]) -> String {
        base64::encode(bytes)
    }

    fn hilo2byte(hilo: (Result<u8,String>, Result<u8,String>)) -> Result<u8,String> {
        match hilo.0 {
            Err(s) => Err(s),
            Ok(hi) => match hilo.1 {
                Err(s) => Err(s),
                Ok(lo) => Ok(hi << 4 | lo),
            }
        }
    }

    fn hexchar2nibble(c: char) -> Result<u8, String> {
        match c.to_digit(16) {
            None => Err(format!("Can't parse hex digit: {}", c)),
            Some(n) => Ok(n as u8),
        }
    }
}
