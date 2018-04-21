extern crate itertools;
extern crate base64;
#[macro_use] extern crate maplit;

pub mod set1 {
    use convert;
    use util;

    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufRead;

    pub fn challenge4() {
        let data_file_name = "4.txt";
        let f = File::open(data_file_name).expect("File  not found");
        let reader = BufReader::new(f);

        let mut max_score_line_k = 0;
        let mut max_score = 0.0;
        let mut max_score_line = Vec::<u8>::new();

        for line_or_err in reader.lines() {
            let line = line_or_err.expect("Error reading line");
//            println!("JB read line: {}", line);
            let line = convert::hex2bytes(&line).unwrap();
            let (k, max_score_for_this_line) = break_single_byte_xor(&line);
//            let plain_text = util::xor(k, &line);
//            println!("JB {}: {}", max_score_for_this_line, convert::b2s(&plain_text));
            if max_score_for_this_line > max_score {
                max_score = max_score_for_this_line;
                max_score_line = line;
                max_score_line_k = k;
            }
        }

//        println!("JB max_score {} min_k {} min_line {}", max_score, max_score_line_k, convert::b2s(&max_score_line));
        let plain_text = util::xor(max_score_line_k, &max_score_line);
        println!("S1 C4 msg is: {}", convert::b2s(&plain_text));
    }

    pub fn challenge3() {
        let cipher_text = convert::hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

        let (min_dist_k, _) = break_single_byte_xor(&cipher_text);
        let plain_text = util::xor(min_dist_k, &cipher_text);
        println!("S1 C3 msg is: {}", convert::b2s(&plain_text));
    }

    fn break_single_byte_xor(cipher_text: &[u8]) -> (u8, f64) {
//        let ec = util::english_frequencies();

        let mut max_score = 0.0;
        let mut max_score_k = 0;
        for k in 0..255 {
            let buf = util::xor(k, cipher_text);
            let score = util::english_score(&buf);
            if score > max_score {
                max_score_k = k;
                max_score = score;
            }
            /*
            let distance = cc.distance(&ec);
            if distance < min_distance {
                min_dist_k = k;
                min_distance = distance;
            }
            */
//            println!("JB {} {}: {}", k, distance, convert::b2s(&buf));
        }
        return (max_score_k, max_score)
//        return (min_dist_k, min_distance)
    }
}

#[cfg(test)]
mod tests {
    mod set1 {
        use convert;
        use util;

        #[test]
        fn challenge3() {
            let plain_text = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
            let key = "ICE";
            let cipher_text = util::xor_encode(&convert::s2b(key), &convert::s2b(plain_text));
            let expected_cipher_text_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
            let expected_cipher_text = convert::hex2bytes(expected_cipher_text_hex).unwrap();
            assert_eq!(cipher_text, expected_cipher_text);
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
        fn challenge1() {
            let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

            let bytes = convert::hex2bytes(&hex_str).expect("Couldn't parse constant as hex");
            let b64_str = convert::bytes2base64(&bytes);
            let expected_b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            assert_eq!(expected_b64_str, b64_str);
        }

        #[test]
        fn order_freq() {
            let test_cases = [
                ("foo", "of"),
                ("aaabcde", "abcde"),       // equal freqencies match in lexo order
                ("Hello", "leho"),
            ];

            for test_case in test_cases.iter() {
                let (s, expected_order) = *test_case;
                let order = util::CharFreq::from_bytes(&s.bytes().collect::<Vec<_>>());
                let order = order.order().iter().collect::<String>();
                assert_eq!(order, expected_order);
            }
        }

        #[test]
        fn order_distance() {
            let test_cases = [
                ("12345", "12345", 0),
                ("12345", "21345", 1),
                ("12345", "32145", 2),
                ("12345", "42315", 3),

                ("12345", "21435", 2),
            ];

            for test_case in test_cases.iter() {
                let (x, y, expected_distance) = *test_case;
                let mut xs: Vec<char> = x.chars().collect();
                let mut ys: Vec<char> = y.chars().collect();
                let distance = util::order_distance(&mut xs, &mut ys);
                assert_eq!(distance, expected_distance);
            }
        }
    }
}

pub mod util {

    pub fn english_score(buf: &[u8]) -> f64 {
        let mut score = 0;
        let tier1 = "etaoin";
        let tier2 = "shrdlu";

        for b in buf {
            let c = *b as char;
            let c = c.to_lowercase().next().unwrap();       // We are only handling ascii
            if c.is_alphabetic() {
                score += 1;
                if let Some(_) = tier1.find(c) {
                    score += 2;
                }
                else if let Some(_) = tier2.find(c) {
                    score += 1;
                }
            }
            else if c == ' ' {
                score += 3;
            }
        }
        score as f64 / buf.len() as f64
    }

    use std::collections::HashMap;

    #[derive(Debug)]
    pub struct CharFreq(pub HashMap<char,f64>);

    impl CharFreq {

        pub fn freq(&self, c: char) -> f64 {
            match self.0.get(&c) {
                None => 0.0,
                Some(f) => *f,
            }
        }

        pub fn from_bytes(buf: &[u8]) -> CharFreq {
            let mut cf = CharFreq(HashMap::new());
            cf.add_bytes(buf);
            cf.normalise()
        }

        fn add_bytes(&mut self, buf: &[u8]) {
            for b in buf {
                self.add_byte(*b);
            }
        }

        fn add_byte(&mut self, b: u8) {
            self.add_char(b as char);
        }

        fn add_char(&mut self, mut c: char) {
            if ! ((c.is_alphabetic() && c.is_ascii()) || c == ' ') {
                return
            }
            c = c.to_lowercase().next().unwrap();       // We are only handling ascii
            let counter = self.0.entry(c).or_insert(0.0);
            *counter += 1.0;
        }

        pub fn order(&self) -> Vec<char> {
            let mut chars = self.0.keys().map(|c| *c).collect::<Vec<_>>();
            // Don't mind my NaN
            // HashMap starts in random order, so make deterministic by falling back
            // to comparing the chars if the frequecies are the same
            chars.sort_by(|a, b| self.freq(*b).partial_cmp(&self.freq(*a)).unwrap().then(a.cmp(b)));
            chars
        }

        pub fn distance(&self, other: &CharFreq) -> usize {
            let d = order_distance(&mut self.order(), &mut other.order());
//            println!("JB - distance ({}) between [{}] and [{}]", d, self.order().iter().collect::<String>(), other.order().iter().collect::<String>());
            d
        }

        pub fn normalise(&self) -> CharFreq {
            let total: f64 = self.0.values().sum();
            CharFreq(self.0.iter().map(|(k, v)| { (*k, *v / total) } ).collect())
        }
    }

    use std;

    pub fn order_distance<T: std::cmp::Eq>(xs: &mut Vec<T>, ys: &mut Vec<T>) -> usize {
        // Always have shortest first
        if xs.len() > ys.len() {
            return order_distance(ys, xs);
        }
        // If we run out of chars, penalise 
        if xs.len() == 0 {
//            return ys.len() * ys.len() * ys.len() * ys.len()
            return ys.len() * ys.len()
        }
        let x = xs.remove(0);
        let pos = ys.iter().position(|c| *c == x);
        let this_distance = match pos {
            Some(d) => {
                ys.swap(0, d);
                ys.remove(0);
                d
            }
            None => ys.len()
        };
        this_distance + order_distance(xs, ys)
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
            ' ' => 25.0,
//            '\0' => 0.0,  // Other
            )).normalise()
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

    pub fn xor_encode(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
        let keystream = key.iter().cycle();
        plain_text.iter().zip(keystream).map(|(c, k)| c ^ k).collect()
    }
}

pub mod convert {

    use itertools::Itertools;
    use base64;

    pub fn b2s(buf: &[u8]) -> String {
        match String::from_utf8(buf.to_vec()) {
            Ok(s) => s,
            Err(err) => format!("Can't decode bytes as utf8: {:?}: {}", buf, err),
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
