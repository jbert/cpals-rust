extern crate itertools;

pub mod set1 {
    use convert;

    pub fn challenge1() {
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        let bytes = convert::hex2bytes(&hex_str).expect("Couldn't parse constant as hex");
        let b64_str = convert::bytes2base64(&bytes);
        println!("got b64 str: {}", b64_str);
    }
}

pub mod convert {

    use itertools::Itertools;

    pub fn hex2bytes(hex_str: &str) -> Result<Vec<u8>, String> {
        /*
        let mut bytes: Vec<u8> = Vec::new();
        let i = hex_str.chars();
        loop {
            let hi = i.next();
            if hi.is_none() {
                // We have our bytes
                return Ok(bytes)
            }
            let hi = hi.unwrap();

            let lo = i.next();
            if lo.is_none() {
                return Err("Odd length hex string");
            }
            let lo = lo.unwrap();

            let hi = char2nibble(hi);
            match hi {
            let byte = (char2nibble(hi) << 4) | char2nibble(lo);
            bytes.push(byte);
        }
        */
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

    pub fn bytes2base64(_bytes: &[u8]) -> String {
        String::from("hello")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
