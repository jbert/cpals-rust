extern crate itertools;
extern crate base64;
#[macro_use] extern crate maplit;

pub mod set1 {
    use convert;
    use util;
    use std::f64;

    pub fn challenge3() {
        let msg = convert::hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
//        let k = 65;
//        let buf = util::xor(k, &msg);
//        println!("buf is {:?}", buf);

        let ec = util::english_frequencies();

        let mut min_distance = f64::MAX;
        let mut min_dist_k = 0;
        for k in 0..255 {
            let buf = util::xor(k, &msg);
            let cc = util::CharCount::from_bytes(&buf);
            let distance = cc.char_freq().distance(&ec);
            if distance < min_distance {
                min_dist_k = k;
                min_distance = distance;
            }
//            println!("JB {} {}: {}", k, distance, convert::b2s(&buf));
        }
        //println!("{}: min distance from english is: {}", min_dist_k, min_distance);
        let plaintext = util::xor(min_dist_k, &msg);
        println!("S1 C3 msg is: {}", convert::b2s(&plaintext));
    }
}

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
            util::xor_buf("1234".as_bytes(), "12345".as_bytes()).unwrap_err();

            assert_eq!(util::xor_buf("".as_bytes(), "".as_bytes()).unwrap(), "".as_bytes());

            let xs = convert::hex2bytes("1c0111001f010100061a024b53535009181c").unwrap();
            let ys = convert::hex2bytes("686974207468652062756c6c277320657965").unwrap();

            let expected = convert::hex2bytes("746865206b696420646f6e277420706c6179").unwrap();
            assert_eq!(util::xor_buf(&xs, &ys).unwrap(), expected);
        }

        #[test]
        fn char_frequency() {
            struct TestCase {
                in_str: &'static[u8],
                reference: util::CharFreq,
                distance: f64
            }
            
            let test_cases = [
                TestCase{in_str: b"foo", reference: util::CharFreq(hashmap!{'f' => 1.0/3.0, 'o'=>2.0/3.0}), distance: 0.0},
                TestCase{in_str: b"a", reference: util::CharFreq(hashmap!{'b' => 1.0}), distance: 2.0},
                TestCase{in_str: b"ab", reference: util::CharFreq(hashmap!{'b' => 1.0}), distance: 1.0},
            ];

            for test_case in test_cases.iter() {
                let cc = util::CharCount::from_bytes(test_case.in_str);
                assert_eq!(test_case.distance, cc.char_freq().distance(&test_case.reference));
            }
        }

        #[test]
        fn char_count() {
            let test_cases = [
                ("foo", "foo", 0.0),
                ("foo", "oof", 0.0),
                ("foo", "foofoo", 0.0),
                ("foo", "foofoofoo", 0.0),
                ("a", "b", 2.0),
                ("aa", "bb", 2.0),
                ("a", "bc", 2.0),
            ];

            for test_case in test_cases.iter() {
                let (x, y, distance) = *test_case;
                let xc = util::CharCount::from_bytes(&convert::s2b(x));
                let yc = util::CharCount::from_bytes(&convert::s2b(y));
                assert_eq!(distance, xc.char_freq().distance(&yc.char_freq()));
            }
        }
    }
}

pub mod util {

    use std::collections::HashMap;
    use std::collections::HashSet;

    pub struct CharFreq(pub HashMap<char,f64>);

    impl CharFreq {

        pub fn freq(&self, c: char) -> f64 {
            match self.0.get(&c) {
                None => 0.0,
                Some(f) => *f,
            }
        }

        pub fn distance(&self, other: &CharFreq) -> f64 {
            let key_set: HashSet<&char> = self.0.keys().collect();
            let other_set: HashSet<&char> = other.0.keys().collect();

            let mut distance: f64 = 0.0;
            for c in key_set.union(&other_set) {
                let this = self.freq(**c);
                let that = other.freq(**c);
                let delta = (this-that).abs();
//                println!("JB - dist {} => {}", **c, delta);
                distance += delta;
            }
//            println!("JB - rawdist {}", distance);
            distance
        }
    }

    pub struct CharCount {
        total: usize,
        counts: HashMap<char,usize>,
    }

    impl CharCount {
        pub fn from_bytes(buf: &[u8]) -> CharCount {
            let mut cf = CharCount{total: 0, counts: HashMap::new()};
            cf.add_bytes(buf);
            cf
        }

        fn add_bytes(&mut self, buf: &[u8]) {
            for b in buf {
                self.add_byte(*b);
            }
        }

        fn add_byte(&mut self, b: u8) {
            self.add_char(b as char);
        }

        fn add_char(&mut self, c: char) {
            self.total += 1;
            let counter = self.counts.entry(c).or_insert(0);
            *counter += 1;
        }
        
        pub fn char_freq(&self) -> CharFreq {
            let m: HashMap<char, f64> = self.counts.iter().map(|(k, v)| {
                (*k, *v as f64 / self.total as f64)
            }).collect();
            CharFreq(m)
        }

    }

    // Ladies and gentlemen - your friend and mine - Etaoin Shrdlu
    pub fn english_frequencies() -> CharFreq {
        CharFreq(hashmap!(
            'a' => 8.167,
            'b' => 1.492,
            'c' => 2.782,
            'd' => 4.253,
            'e' => 12.702,
            'f' => 2.228,
            'g' => 2.015,
            'h' => 6.094,
            'i' => 6.966,
            'j' => 0.153,
            'k' => 0.772,
            'l' => 4.025,
            'm' => 2.406,
            'n' => 6.749,
            'o' => 7.507,
            'p' => 1.929,
            'q' => 0.095,
            'r' => 5.987,
            's' => 6.327,
            't' => 9.056,
            'u' => 2.758,
            'v' => 0.978,
            'w' => 2.360,
            'x' => 0.150,
            'y' => 1.974,
            'z' => 0.074,
            ))
    }

    pub fn xor(x: u8, ys: &[u8]) -> Vec<u8> {
        ys.iter().map(|y| { x ^ y }).collect()
    }

    pub fn xor_buf(xs: &[u8], ys: &[u8]) -> Result<Vec<u8>, String> {
        if xs.len() != ys.len() {
            return Err(format!("xor: buf size mismatch: {} != {}", xs.len(), ys.len()))
        }
        Ok(xs.iter().zip(ys.iter()).map(|xy| {xy.0 ^ xy.1}).collect())
    }
}

pub mod convert {

    use itertools::Itertools;
    use base64;

    pub fn b2s(buf: &[u8]) -> String {
        match String::from_utf8(buf.to_vec()) {
            Ok(s) => s,
            Err(err) => panic!("Can't decode bytes as utf8: {:?}: {}", buf, err),
        }
    }
    pub fn s2b(s: &str) -> Vec<u8> {
        s.bytes().collect()
    }

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
