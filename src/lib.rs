#![feature(iterator_step_by)]
extern crate itertools;
extern crate base64;
extern crate openssl;
#[macro_use] extern crate maplit;

pub mod set2 {
    use util::*;
    use convert::*;
    use set1::*;

    pub fn challenge10() {
        let cipher_text= slurp_base64_file("7.txt");
        println!("JB - cipher length is {}", cipher_text.len());
        let iv = &s2b(&"\x00".repeat(16));
        let key = &s2b("YELLOW SUBMARINE");
        let plain_text = aes128_cbc_decode(&key, &iv, &cipher_text);
        for (i, byte) in plain_text[0..34].iter().enumerate() {
            println!("JB {:2} {:08b} {}", i, *byte, *byte as char);
        }
        println!("S1C10 msg is {}", &b2s(&plain_text));
        let recipher_text = aes128_cbc_encode(&key, &iv, &plain_text);
        println!("Re-encode matches? : {}", recipher_text == cipher_text);
    }

    pub fn aes128_cbc_decode(key: &[u8], iv: &[u8], cipher_text: &[u8]) -> Vec<u8> {
        let block_size = 16;
        assert!(key.len() == block_size, format!("AES128 requires {} byte key", block_size));
        assert!(iv.len() == block_size, format!("AES128 requires {} byte iv", block_size));

        // CBC consumes previous ciphertext blocks, prepended with the IV
        let mut last_cipher_block = iv.to_vec();
        let cipher_blocks = cipher_text.chunks(block_size);
        let plain_blocks = cipher_blocks.map(|cipher_block| {
//            println!("JB - about to decode key len {} block len {}", key.len(), last_cipher_block.len());
            println!("JB - decode last cipher block block {:x?}", last_cipher_block);
            println!("JB - decode this cipher block block {:x?}", cipher_block);
            let xor_input_block = aes128_crypt_block(false, &key, &cipher_block);
            let plain_block = xor_buf(&xor_input_block, &last_cipher_block).expect("Block size mismatch!?");
            last_cipher_block = cipher_block.clone().to_vec();
            plain_block
        });
        plain_blocks.collect::<Vec<_>>().concat()
    }


    pub fn aes128_cbc_encode(key: &[u8], iv: &[u8], plain_text: &[u8]) -> Vec<u8> {
        let block_size = 16;
        assert!(key.len() == block_size, format!("AES128 requires {} byte key", block_size));
        assert!(iv.len() == block_size, format!("AES128 requires {} byte iv", block_size));

        // CBC consumes previous ciphertext blocks, prepended with the IV
        let mut last_cipher_block = iv.to_vec();
        let plain_blocks = plain_text.chunks(block_size);
        let cipher_blocks = plain_blocks.map(|plain_block| {
            let ecb_input_block = &xor_buf(&plain_block, &last_cipher_block).expect("Block size mismatch!?");
            let cipher_block = aes128_crypt_block(true, &key, &ecb_input_block);
            last_cipher_block = cipher_block.clone();
            cipher_block
        });
        cipher_blocks.collect::<Vec<_>>().concat()
    }

}

pub mod set1 {
    use convert::*;
    use util::*;
    use openssl::symm;
    use std::collections::HashSet;

    pub fn challenge8() {
        let lines = slurp_hex_file_as_lines("8.txt");
        let block_size = 16;
        for (lineno, line) in lines.iter().enumerate() {
            let num_blocks = line.len() / block_size;
            let mut blocks = line.chunks(block_size);
            let distinct_blocks = blocks.collect::<HashSet<_>>();
            if distinct_blocks.len() != num_blocks {
                println!("s1 c8: Line {} has only {} distinct blocks, not {}", lineno, distinct_blocks.len(), num_blocks);
            }
        }
    }

    pub fn challenge7() {
        let key = s2b(&"YELLOW SUBMARINE");
        let cipher_text= slurp_base64_file("7.txt");

        /*
        let cipher = symm::Cipher::aes_128_ecb();
        let iv = s2b(&"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        match symm::decrypt(cipher, &key, Some(&iv), &cipher_text) {
            Err(error_stack)
                => println!("Failed to decrypt: {}", error_stack),
            Ok(plain_text)
                => println!("S1 C7 msg is {}", b2s(&plain_text)),
        }
        */
        println!("S1 C7 msg is {}", b2s(&aes128_ecb_decode(&key, &cipher_text)));
    }

    pub fn aes128_ecb_encode(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
        aes128_ecb_helper(key, plain_text).expect("Failed to encrypt")
    }

    fn aes128_ecb_helper(key: &[u8], plain_text: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = symm::Cipher::aes_128_ecb();
        let iv = s2b(&"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        match symm::encrypt(cipher, &key, Some(&iv), &plain_text) {
            Ok(buf) => Ok(buf),
            Err(stack) => Err(format!("{:?}", stack)),
        }
    }

    pub fn aes128_crypt_block(encode: bool, key: &[u8], in_text: &[u8]) -> Vec<u8> {
        aes128_crypt_block_helper(encode, key, in_text).expect("Failed to crypt")
    }

    pub fn aes128_crypt_block_helper(encode: bool, key: &[u8], in_text: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = symm::Cipher::aes_128_ecb();
        let block_size = cipher.block_size();
        assert_eq!(block_size, key.len(), "wrong size key");
        assert_eq!(block_size, in_text.len(), "wrong size input text");
        let iv = s2b(&"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        let mut crypter = symm::Crypter::new(
            cipher,
            match encode { true => symm::Mode::Encrypt, false => symm::Mode::Decrypt },
            key,
            Some(&iv)).unwrap();
        crypter.pad(false);

        let mut out_text = vec![0; block_size * 2];
        let mut count = 0;
        match crypter.update(&in_text, &mut out_text) {
            Ok(c) => count += c,
            Err(stack) => return Err(format!("{:?}", stack)),
        }
        match crypter.finalize(&mut out_text[count..]) {
            Ok(c) => count += c,
            Err(stack) => return Err(format!("{:?}", stack)),
        }
        assert_eq!(count, block_size, "We have one block output");
        out_text.truncate(count);

        Ok(out_text)
    }


    pub fn aes128_ecb_decode(key: &[u8], cipher_text: &[u8]) -> Vec<u8> {
        aes128_ecb_decode_helper(key, cipher_text).expect("Failed to decrypt")
    }
    pub fn aes128_ecb_decode_helper(key: &[u8], cipher_text: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = symm::Cipher::aes_128_ecb();
        let iv = s2b(&"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        match symm::decrypt(cipher, &key, Some(&iv), &cipher_text) {
            Ok(buf) => Ok(buf),
            Err(stack) => Err(format!("{:?}", stack)),
        }
    }

    pub fn challenge6() {
        let cipher_text = slurp_base64_file("6.txt");

        let max_keysize_to_try = 40;
        let num_keysizes_to_return = 5;
        let keysizes = guess_repeated_xor_keysize(max_keysize_to_try, num_keysizes_to_return, &cipher_text);

//        println!("keysizes {:?}", keysizes);
        
        let mut guesses = keysizes.iter().map(|&ks| break_repeated_xor(ks, &cipher_text))
            .collect::<Vec<_>>();
        guesses.sort_by(|&(score_a, _), &(score_b, _)| score_b.partial_cmp(&score_a).expect("Not a nan"));
//        println!("score {} guess\n{}\n", guesses[0].0, b2s(&guesses[0].1));
//        use below to turn 'keysize' -> key -> plaintext -> english_score and choose min
        /*
        let blocks = (0..keysize).map(|offset| cipher_text.iter().take(offset).step_by(keysize));
        let key = blocks.map(|block_it| {
            let buf = block_it.map(|r| *r).collect::<Vec<_>>();
            let (k, _) = break_single_byte_xor(&buf);
            k
        }).collect::<Vec<_>>();
        let plain_text = xor_decode(&key, &cipher_text);
        println!("key is:\n {:?}", key);
        */
        println!("S1 C6 msg is:\n{}", b2s(&guesses[0].1));
    }

    pub fn break_repeated_xor(keysize: usize, cipher_text: &[u8]) -> (f64, Vec<u8>) {
        // For each transposed block, find the best key byte for english
        let blocks = transpose_blocks(keysize, cipher_text);
        let key = blocks.iter().map(|block| {
//            println!("buf len is {}", block.len());
//            println!("beginning of buf is {:?}", &block[0..10]);
            let (k, _) = break_single_byte_xor(&block);
//            println!("key byte is {:?}", k);
            k
        }).collect::<Vec<_>>();

        // We now have a multibyte key.
        // Use it to find plaintext and english score
        let plain_text = xor_decode(&key, &cipher_text);
//        println!("key is: {}", b2s(&key));
        let score = english_score(true, &plain_text);
//        println!("JB BRX ks {} score {}", keysize, score);
        (score, plain_text)
    }

    fn transpose_blocks(blocksize: usize, buf: &[u8]) -> Vec<Vec<u8>> {
        // Transpose - get an iter to all the first bytes of the ciphertext block, all the 2nd etc
        // (using keysize as blocksize)
        (0..blocksize)
            .map(|offset| buf.iter().skip(offset).step_by(blocksize))
            .map(|block_iter| block_iter.map(|&r| r).collect::<Vec<_>>())
            .collect()
    }

    pub fn guess_repeated_xor_keysize(max_keysize_checked: usize, num_keysizes_to_return: usize, cipher_text: &[u8]) -> Vec<usize> {
        let mut hd_keysizes = (2..max_keysize_checked)
            .map(|keysize| {
                // Look at the distances between the first block and the next few
                let abuf = &cipher_text[0..keysize];
                let bbuf = &cipher_text[keysize..keysize*2];
                let cbuf = &cipher_text[keysize*2..keysize*3];
                let dbuf = &cipher_text[keysize*3..keysize*4];
                let hd = (hamming_distance(abuf, bbuf) + hamming_distance(bbuf, cbuf) + hamming_distance(cbuf, dbuf)) / 3;
                (keysize, hd as f64 / keysize as f64)
            }).collect::<Vec<_>>();
        hd_keysizes.sort_by(|&(_, hd_a), &(_, hd_b)| hd_a.partial_cmp(&hd_b).expect("Not a nan"));
        hd_keysizes.iter().take(num_keysizes_to_return).map(|&(ks, _)| ks).collect()
    }

    pub fn challenge4() {
        let lines = slurp_hex_file_as_lines("4.txt");

        let mut max_score_line_k = 0;
        let mut max_score = 0.0;
        let mut max_score_line = &Vec::<u8>::new();

        for line in lines.iter() {
            let (k, max_score_for_this_line) = break_single_byte_xor(&line);
//            let plain_text = xor(k, &line);
//            println!("JB {}: {}", max_score_for_this_line, b2s(&plain_text));
            if max_score_for_this_line > max_score {
                max_score = max_score_for_this_line;
                max_score_line = line;
                max_score_line_k = k;
            }
        }

//        println!("JB max_score {} min_k {} min_line {}", max_score, max_score_line_k, b2s(&max_score_line));
        let plain_text = xor(max_score_line_k, &max_score_line);
        println!("S1 C4 msg is: {}", b2s(&plain_text));
    }

    pub fn challenge3() {
        let cipher_text = hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

        let (min_dist_k, _) = break_single_byte_xor(&cipher_text);
        let plain_text = xor(min_dist_k, &cipher_text);
        println!("S1 C3 msg is: {}", b2s(&plain_text));
    }

    fn break_single_byte_xor(cipher_text: &[u8]) -> (u8, f64) {
//        let ec = english_frequencies();

        let mut max_score = 0.0;
        let mut max_score_k = 0;
        for k in 0..255 {
            let buf = xor(k, cipher_text);
            let score = english_score(true, &buf);
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
//            println!("JB {} {}: {}", k, distance, b2s(&buf));
        }
        return (max_score_k, max_score)
//        return (min_dist_k, min_distance)
    }
}

#[cfg(test)]
mod tests {
    mod set2 {
        use util::*;
        use convert::*;
        use set2::*;

        #[test]
        fn test_cbc_mode() {
            let test_cases = [
//                "\x00".repeat(16),
                "CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.",
                "yellow submarine",
            ];

            let key = s2b("YELLOW SUBMARINE");
            let iv = s2b(&"\x7f".repeat(16));

            for test_case in test_cases.iter() {
                let cipher_text = &aes128_cbc_encode(&key, &iv, &s2b(test_case));
                let re_plain_text = &aes128_cbc_decode(&key, &iv, &cipher_text);
                assert_eq!(&b2s(re_plain_text), test_case);
            }
        }

        #[test]
        fn challenge9() {
            let block_size = 20;
            let test_cases = [
                ("YELLOW SUBMARINE", "YELLOW SUBMARINE\x04\x04\x04\x04"),
                ("YELLOW SUBMARINE1234", "YELLOW SUBMARINE1234"),
                ("YELLOW SUBMARINE1234YELLOW SUBMARINE", "YELLOW SUBMARINE1234YELLOW SUBMARINE\x04\x04\x04\x04"),
                ("YELLOW SUBMARINE123", "YELLOW SUBMARINE123\x01"),
                ("YELLOW SUBMARINE12", "YELLOW SUBMARINE12\x02\x02"),
                ("YELLOW SUBMARINE1", "YELLOW SUBMARINE1\x03\x03\x03"),
            ];

            for test_case in test_cases.iter() {
                let (msg_str, expected_padded_msg_str) = *test_case;
                let msg = s2b(&msg_str);
                let expected_padded_msg = s2b(&expected_padded_msg_str);
                let padded_msg = pkcs7_pad(block_size, &msg);
                assert_eq!(padded_msg, expected_padded_msg);
            }
        }
    }

    mod set1 {
        use convert::*;
        use util::*;
        use set1::*;

        #[test]
        fn test_ecb() {
            let key = &s2b("yellow submarine");
            let plain_text = &s2b("cavorting badger");
            let cipher_text = &aes128_ecb_encode(&key, &plain_text);
            let re_plain_text = &aes128_ecb_decode(&key, &cipher_text);
            assert_eq!(plain_text, re_plain_text, "Get back the text we expect");
        }

        #[test]
        fn challenge6() {
            let s1 = "this is a test";
            let s2 = "wokka wokka!!!";
            assert_eq!(hamming_distance(&s2b(s1), &s2b(s2)), 37);
        }

        #[test]
        fn test_hamming_distance() {
            let test_cases = [
                ("000000", "000001", 1),
                ("000000", "000003", 2),
            ];

            for test_case in test_cases.iter() {
                let (x_hex, y_hex, expected_hd) = *test_case;
                let x = hex2bytes(&x_hex).expect("Test is wrong");
                let y = hex2bytes(&y_hex).expect("Test is wrong");
                assert_eq!(hamming_distance(&x, &y), expected_hd);
            }
        }

        #[test]
        fn challenge5() {
            let plain_text = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
            let key = "ICE";
            let cipher_text = xor_decode(&s2b(key), &s2b(plain_text));
            let expected_cipher_text_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
            let expected_cipher_text = hex2bytes(expected_cipher_text_hex).unwrap();
            assert_eq!(cipher_text, expected_cipher_text);
        }

        #[test]
        fn challenge2() {
            xor_buf("1234".as_bytes(), "12345".as_bytes()).unwrap_err();

            assert_eq!(xor_buf("".as_bytes(), "".as_bytes()).unwrap(), "".as_bytes());

            let xs = hex2bytes("1c0111001f010100061a024b53535009181c").unwrap();
            let ys = hex2bytes("686974207468652062756c6c277320657965").unwrap();

            let expected = hex2bytes("746865206b696420646f6e277420706c6179").unwrap();
            assert_eq!(xor_buf(&xs, &ys).unwrap(), expected);
        }

        #[test]
        fn challenge1() {
            let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

            let bytes = hex2bytes(&hex_str).expect("Couldn't parse constant as hex");
            let b64_str = bytes2base64(&bytes);
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
                let order = CharFreq::from_bytes(&s.bytes().collect::<Vec<_>>());
                let order = order.order().iter().collect::<String>();
                assert_eq!(order, expected_order);
            }
        }

        #[test]
        fn test_order_distance() {
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
                let distance = order_distance(&mut xs, &mut ys);
                assert_eq!(distance, expected_distance);
            }
        }

        #[test]
        fn test_xor_decode() {
            let test_cases = [
                ("00000000", "0102", "01020102"),
                ("00000000", "01", "01010101"),
                ("00000000", "010203", "01020301"),
                ("040504050405", "0405", "000000000000"),

                ("303132333435", "0102", "313333313537"),
            ];

            for test_case in test_cases.iter() {
                let (plain_text_hex, key_hex, expected_cipher_text_hex) = *test_case;
                let plain_text = hex2bytes(&plain_text_hex).expect("Test is wrong");
                let expected_cipher_text = hex2bytes(&expected_cipher_text_hex).expect("Test is wrong");
                let key = hex2bytes(&key_hex).expect("Test is wrong");
                let cipher_text = xor_decode(&key, &plain_text);
                assert_eq!(cipher_text, expected_cipher_text);
            }
        }

    }
}

pub mod util {

    use std::fs::File;
    use std::io::Read;
    use std::io::BufReader;
    use std::io::BufRead;
    use convert::*;

    pub fn pkcs7_pad(block_size: usize, buf: &[u8]) -> Vec<u8> {
        let mut padding_needed = block_size - buf.len() % block_size;
        if padding_needed == block_size {
            padding_needed = 0;
        }
        let padding_needed = padding_needed as u8;
        let mut v = buf.to_vec();
        v.extend((0..padding_needed).map(|_| padding_needed));
        v
    }


    pub fn slurp_base64_file(filename: &str) -> Vec<u8> {
        let mut contents = String::new();
        let mut f = File::open(filename).expect("Can't open file");
        f.read_to_string(&mut contents).expect("Can't read bytes");
        let contents = contents.replace("\n", "");
        let contents = base642bytes(&s2b(&contents)).expect("Data is not base64");
        contents
    }

    pub fn slurp_hex_file_as_lines(filename: &str) -> Vec<Vec<u8>> {
        let f = File::open(filename).expect("File  not found");
        let reader = BufReader::new(f);

        reader
            .lines()
            .map(|l| l.expect("Error reading line"))
            .map(|l| hex2bytes(&l).unwrap())
            .collect()
    }

    pub fn hamming_distance(xs: &[u8], ys: &[u8]) -> usize {
        xs.iter().zip(ys.iter()).map(|(x, y)| (x ^ y).count_ones() as usize).sum()
    }

    pub fn english_score_counting_method(buf: &[u8]) -> f64 {
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
    use std::f64;

    pub fn english_score_histo_order(buf: &[u8]) -> f64 {
        let ec = english_frequencies();
        let cc = CharFreq::from_bytes(&buf);
        let distance = cc.distance(&ec);
        if distance == 0 {
            f64::MAX
        } else {
            1.0 / distance as f64
        }
    }

    pub fn english_score(fast: bool, buf: &[u8]) -> f64 {
        if fast {
            english_score_counting_method(buf)
        } else {
            english_score_histo_order(buf)
        }
    }

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

    pub fn xor_decode(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
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

    pub fn base642bytes(b64str: &[u8]) -> Result<Vec<u8>, String> {
        base64::decode(b64str).map_err(|e| e.to_string())
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
