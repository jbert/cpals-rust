#![feature(iterator_step_by)]
#![feature(extern_prelude)]
extern crate itertools;
extern crate base64;
extern crate openssl;
extern crate rand;

#[macro_use] extern crate maplit;

pub mod set2 {
    use util::*;
    use convert::*;
    use set1::*;
    use rand::Rng;
    use std::collections::*;
    use std::iter;
    use itertools::Itertools;


    pub fn challenge13() {
        let key = get_random_bytes(16);
        let mut encode_profile_for_email = |email_address: &[u8]| {
            aes128_ecb_encode(&key, &s2b(&c13_profile_for(email_address)))
        };
        let decode_to_profile = |cipher_text: &[u8]| {
            let profile_str = aes128_ecb_decode(&key, &cipher_text);
            c13_parse_kv(&profile_str)
        };

        let email = &s2b("bob@example.com");
        println!("S2C13 - Profile for [{}] is [{}]", b2s(&email), c13_profile_for(email));
        let cipher_text = encode_profile_for_email(email);
        let profile = decode_to_profile(&cipher_text);
        println!("S2C13 - Role for decoded profile: {}", profile.expect("can get profile").role);

        let block_size = find_blocksize(&mut encode_profile_for_email);
        println!("S2C13 - Oracle block size is {}", block_size);
        let is_ecb = guess_cryptor_is_ecb(&mut encode_profile_for_email);
        println!("S2C13 - cryptor is ecb? : {}", is_ecb);

        // We want to encode this on a block boundary
        let target_text_str = &b2s(&pkcs7_pad(block_size, &s2b(&"admin")));

        // Loop with more and more padding in front of our target block
        // until we see a duplicate block.
        //
        // When we have enough padding in front of our target block to cause duplicated blocks
        // our target ciphertext is the block after the duplicates.
        let mut target_cipher_block : Vec<u8> = Vec::new();
        for padding in block_size - 1 .. block_size*3 {
            let mut padded_email_address = "_".repeat(padding);
            padded_email_address.push_str(&target_text_str);
            padded_email_address.push_str("@example.com");  // because why not
            let cipher_text = encode_profile_for_email(&s2b(&padded_email_address));

            let mut next_is_target = false;
            let mut last_block : Vec<u8> = Vec::new();
            for block in cipher_text.chunks(block_size) {
                if block.to_vec() == last_block {
                    next_is_target = true;
                    continue
                }
                if next_is_target {
                    target_cipher_block = block.to_vec();
                    break
                }
                last_block = block.to_vec();
            }
            if target_cipher_block.len() > 0 {
                println!("S2C13 - found target at offset {}", padding);
                break
            }
        }
        if target_cipher_block.len() <= 0 {
            panic!("Didn't find target cipher block")
        }

        // At some padding between 0..block_size the end block should
        // be 'user<pkcspadding>'. If so, replacing it with our
        // target cipher block should give us something which will decode
        // to our desired plaintext
        for padding in 0..block_size-1 {
            let mut padded_email_address = "_".repeat(padding);
            padded_email_address.push_str("@example.com");

            let mut cipher_text = encode_profile_for_email(&s2b(&padded_email_address));
//            cipher_text[cipher_text.len() - block_size..cipher_text.len()] = target_cipher_block;
            let cipher_text_len = cipher_text.len();
            cipher_text.splice(cipher_text_len - block_size .. cipher_text_len, target_cipher_block.clone());
            match decode_to_profile(&cipher_text) {
                Ok(profile) => if profile.role == "admin" {
                    println!("S2C13 - did it! got an admin role");
                    return
                },
                Err(_) => {
                    continue // We don't care about failed decodes, we'll probably get a few
                }
            }
        }
        panic!("S2C13 fail. Bad coder, no biscuit");
    }

    #[derive(Debug)]
    pub struct UserProfile {
        email: String,
        uid: String,
        role: String,
    }

    impl UserProfile {
        fn to_string(&self) -> String {
            format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
        }
        fn from_hm(hm: &HashMap<String,String>) -> UserProfile {
            UserProfile{
                email: hm.get(&"email".to_string()).expect("Must have email").clone(),
                uid: hm.get(&"uid".to_string()).expect("Must have email").clone(),
                role: hm.get(&"role".to_string()).expect("Must have email").clone(),
            }
        }
    }

    pub fn c13_profile_for(email_address: &[u8]) -> String {
        let email_address = &b2s(email_address);
        let email_address = email_address.replace("&","").replace("=","");
        UserProfile{email: email_address.to_string(), uid: "10".to_string(), role: "user".to_string()}.to_string()
    }

    pub fn c13_parse_kv(s: &[u8]) -> Result<UserProfile,String> {
        let hm = c13_parse_kv_to_hm(&s)?;
        Ok(UserProfile::from_hm(&hm))
    }

    pub fn c13_parse_kv_to_hm(buf: &[u8]) -> Result<HashMap<String,String>,String> {
        let s = &b2s(buf);
        s.split("&")
            .map(|sub_string| match sub_string.split("=").next_tuple() {
                Some(t) => Ok(t),
                None => Err("No equals sign".to_string()),
            }.map(|(k, v)| (k.to_string(), v.to_string())))
            .collect()
    }

    pub fn challenge12() {
        let key = get_random_bytes(16);
        let mut c12_cryptor = |pt: &[u8]| {
            c12_cryptor_helper(&key, pt)
        };

        let block_size = find_blocksize(&c12_cryptor);
        println!("S2C12 - cryptor block size is : {}", block_size);
        let is_ecb = guess_cryptor_is_ecb(&mut c12_cryptor);
        println!("S2C12 - cryptor is ecb? : {}", is_ecb);

//        let cipher_len = c12_cryptor(&[]).len();
//        println!("JB - cipher len is {}", cipher_len);

        let mut recovered_plain_text: Vec<u8> = Vec::new();
        let pad_char = 'A' as u8;

//        for _ in 0..cipher_len {
        loop {
//            println!("JB - {}: {}", recovered_plain_text.len(), b2s(&recovered_plain_text));

            // We encrypt a prefix which pads with known data to 1 byte less than a block
            let added_pad = block_size - ((recovered_plain_text.len()+1) % block_size);
            let pad: Vec<u8> = iter::repeat(pad_char).take(added_pad).collect();

            let cipher_text = c12_cryptor(&pad);

            let mut chosen_plain_text: Vec<u8> = pad.clone();
            chosen_plain_text.extend(recovered_plain_text.clone());
            assert_eq!(chosen_plain_text.len() % block_size, block_size - 1, "Padding worked");

            let last_block = chosen_plain_text.len() / block_size;
            let trick_plain_block = &chosen_plain_text[last_block*block_size..];
            let trick_cipher_block = &cipher_text[last_block*block_size..(last_block+1)*block_size];
//            println!("JB - trick_plain [{}]", b2s(&trick_plain_block));

            let next_byte = c12_find_next_byte(&c12_cryptor, &trick_plain_block, &trick_cipher_block);
            if !(next_byte == 0x0a || next_byte == 0xad || (next_byte >= 32 && next_byte < 127)) {
                break
            }
            recovered_plain_text.push(next_byte);
        }
        println!("S2C12 msg is {}", b2s(&recovered_plain_text));
    }

    fn c12_find_next_byte(cryptor: &Fn(&[u8]) -> Vec<u8>, plain_block: &[u8], trick_cipher_block: &[u8]) -> u8 {
        let block_size = trick_cipher_block.len();
        for guess in 0..=255 {
            let mut trial_plain_text = plain_block.to_vec();
            trial_plain_text.push(guess);
//            println!("JB - trial_plain [{}]", b2s(&trial_plain_text));
            let trial_cipher_text = cryptor(&trial_plain_text);
//            println!("JB - trial block is: {:?}", &trial_cipher_text[0..block_size]);
//            println!("JB - trick_cipher is: {:?}", &trick_cipher_block);
            if &trial_cipher_text[0..block_size] == trick_cipher_block {
                return guess
            }
        }
        panic!("Failed to find byte");
    }

    fn find_blocksize(cryptor: &Fn(&[u8]) -> Vec<u8>) -> usize {
        let mut last_cipher_text_size = 0;
        for plaintext_len in 0..1024 {
            let cipher_text = cryptor(&s2b(&"_".repeat(plaintext_len)));
            if last_cipher_text_size > 0 { // Not really necessary...can't we just encode 1 byte and assume PCKS-7?
                if last_cipher_text_size != cipher_text.len() {
                    return cipher_text.len() - last_cipher_text_size;
                }
            }
            last_cipher_text_size = cipher_text.len();
        }
        panic!("Couldn't find block size");
    }


    pub fn c12_cryptor_helper(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
        let block_size = 16;
        assert!(key.len() == block_size, format!("AES128 requires {} byte key", block_size));
        let suffix = str::replace("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK", "\n", "");
        let suffix = &base642bytes(&s2b(&suffix)).expect("Must be base64!");

        let mut plain_text = plain_text.to_vec();
        plain_text.extend_from_slice(suffix);
        aes128_ecb_encode(&key, &plain_text)
    }

    pub fn get_random_buf(lo: usize, hi: usize) -> Vec<u8> {
        let num = rand::thread_rng().gen_range(lo, hi);
        get_random_bytes(num)
    }

    pub fn get_random_bytes(n: usize) -> Vec<u8> {
//        let mut rng = rand::thread_rng();
//        (0..n).map(|_| rng.gen()).collect()
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    pub fn guess_cryptor_is_ecb(encryptor: &mut FnMut(&[u8]) -> Vec<u8>) -> bool {
        let block_size = 16;
        let repeated_plain_text = "a".repeat(block_size * 4);
        let cipher_text = encryptor(&s2b(&repeated_plain_text));

        has_repeated_blocks(block_size, &cipher_text)
    }

    fn has_repeated_blocks(block_size: usize, buf: &[u8]) -> bool {
        let num_blocks = buf.len() / block_size;
        let blocks = buf.chunks(block_size);
        let distinct_blocks = blocks.collect::<HashSet<_>>();
        distinct_blocks.len() != num_blocks
    }

    pub fn aes128_ecb_or_cbc_random_key(plain_text: &[u8]) -> (Vec<u8>, bool) {
        let block_size = 16;
        let key = get_random_bytes(block_size);

        let mut extended_plain_text = get_random_buf(5, 10);
        extended_plain_text.extend_from_slice(plain_text);
        extended_plain_text.extend(get_random_buf(5, 10));


        let use_ecb = rand::random();
        if use_ecb {
            (aes128_ecb_encode(&key, &extended_plain_text), use_ecb)
        } else {
            let iv = get_random_bytes(block_size);
            (aes128_cbc_encode(&key, &iv, &extended_plain_text), use_ecb)
        }
    }

    pub fn challenge10() {
        let cipher_text= slurp_base64_file("10.txt");
        let iv = &s2b(&"\x00".repeat(16));
        let key = &s2b("YELLOW SUBMARINE");
        let plain_text = aes128_cbc_decode(&key, &iv, &cipher_text);
//        for (i, byte) in plain_text[0..34].iter().enumerate() {
//            println!("JB {:2} {:08b} {}", i, *byte, *byte as char);
//        }
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
//            println!("JB - decode last cipher block block {:x?}", last_cipher_block);
//            println!("JB - decode this cipher block block {:x?}", cipher_block);
            let xor_input_block = aes128_crypt_block(false, &key, &cipher_block);
            let plain_block = xor_buf(&xor_input_block, &last_cipher_block).expect("Block size mismatch!?");
            last_cipher_block = cipher_block.clone().to_vec();
            plain_block
        });
        pkcs7_unpad(block_size, &plain_blocks.collect::<Vec<_>>().concat()).unwrap()
    }


    pub fn aes128_cbc_encode(key: &[u8], iv: &[u8], plain_text: &[u8]) -> Vec<u8> {
        let block_size = 16;
        assert!(key.len() == block_size, format!("AES128 requires {} byte key", block_size));
        assert!(iv.len() == block_size, format!("AES128 requires {} byte iv", block_size));

        // CBC consumes previous ciphertext blocks, prepended with the IV
        let mut last_cipher_block = iv.to_vec();
        let padded_plain_text = pkcs7_pad(block_size, plain_text);
        let plain_blocks = padded_plain_text.chunks(block_size);
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
        let block_size = 16;
        let padded_plain_text = pkcs7_pad(block_size, plain_text);
        aes128_ecb_helper(true, key, &padded_plain_text)
    }

    pub fn aes128_ecb_decode(key: &[u8], cipher_text: &[u8]) -> Vec<u8> {
        let block_size = 16;
        let padded_plain_text = aes128_ecb_helper(false, key, cipher_text);
        pkcs7_unpad(block_size, &padded_plain_text).unwrap()
    }

    fn aes128_ecb_helper(encode: bool, key: &[u8], in_text: &[u8]) -> Vec<u8> {
        let block_size = 16;
        in_text.chunks(block_size).map(|in_block| {
            aes128_crypt_block(encode, &key, &in_block)
        }).collect::<Vec<_>>().concat()
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
        use std::collections::*;

        fn hm_to_string(hm: &HashMap<&str, &str>) -> HashMap<String,String> {
            hm.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        }

        #[test]
        fn challenge13() {
            let test_cases = [
                ("foo=bar", Ok(hashmap!("foo" => "bar"))),
                ("foo=bar&baz=quux", Ok(hashmap!("foo" => "bar", "baz" => "quux"))),
                ("baz=quux&foo=bar", Ok(hashmap!("foo" => "bar", "baz" => "quux"))),
                ("baz=quux&baz=bar", Ok(hashmap!("baz" => "bar"))),
                ("bar", Err("No equals sign")),
                ("a=1&bar", Err("No equals sign")),
            ];

            for test_case in test_cases.iter() {
                let (s, ref expected_result) = *test_case;
                let expected_result = match expected_result {
                    Ok(hm) => Ok(hm_to_string(hm)),
                    Err(s) => Err(s.to_string()),
                };
                assert_eq!(&c13_parse_kv_to_hm(s), &expected_result);
            }
        }

        #[test]
        fn challenge11() {
            let attempts = 100;
            for _ in 0..attempts {
                let mut was_ecb = false;
                let guess = {
                    let mut cryptor = |plain_text: &[u8]| {
                        let (cipher_text, did_ecb) = aes128_ecb_or_cbc_random_key(plain_text);
                        was_ecb = did_ecb;
                        cipher_text
                    };
                    guess_cryptor_is_ecb(&mut cryptor)
                };
                assert_eq!(guess, was_ecb, "Guessed correctly");
            }
        }

        #[test]
        fn challenge9() {
            let block_size = 20;
            let test_cases = [
                ("YELLOW SUBMARINE", "YELLOW SUBMARINE\x04\x04\x04\x04"),
                ("YELLOW SUBMARINE1234", "YELLOW SUBMARINE1234\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14"),
                ("YELLOW SUBMARINE1234YELLOW SUBMARINE", "YELLOW SUBMARINE1234YELLOW SUBMARINE\x04\x04\x04\x04"),
                ("YELLOW SUBMARINE123", "YELLOW SUBMARINE123\x01"),
                ("YELLOW SUBMARINE12", "YELLOW SUBMARINE12\x02\x02"),
                ("YELLOW SUBMARINE1", "YELLOW SUBMARINE1\x03\x03\x03"),
                ("Y", "Y\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13"),
                ("", "\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14"),
            ];

            for test_case in test_cases.iter() {
                let (msg_str, expected_padded_msg_str) = *test_case;
                let msg = s2b(&msg_str);
                let expected_padded_msg = s2b(&expected_padded_msg_str);
                let padded_msg = pkcs7_pad(block_size, &msg);
                assert_eq!(padded_msg, expected_padded_msg);
                assert!(padded_msg.len() % block_size == 0, "padded msg is a multiple of block size");
                let unpadded_msg = pkcs7_unpad(block_size, &padded_msg).unwrap();
                assert_eq!(unpadded_msg, msg);
            }
        }
    }

    mod set1 {
        use convert::*;
        use util::*;
        use set1::*;
        use set2::*;

        #[test]
        fn test_encrypt_decrypt() {
            let test_cases = [
                // block size
                "cavorting badger",
                "cavorting badgeryellow submarine",
                // short
                "a",
                "",
                // long
                "cavorting badger sleeps",
            ];
            let key = &s2b("yellow submarine");
            let iv = &s2b("badger cavorting");
            for test_case in test_cases.iter() {
                let plain_text = &s2b(test_case);
                let ecb_cipher_text = &aes128_ecb_encode(&key, plain_text);
                let re_ecb_plain_text = &aes128_ecb_decode(&key, &ecb_cipher_text);
                assert_eq!(plain_text, re_ecb_plain_text, "Get back the text we expect - ecb {}", *test_case);
                let cbc_cipher_text = &aes128_cbc_encode(&key, iv, plain_text);
                let re_cbc_plain_text = &aes128_cbc_decode(&key, iv, &cbc_cipher_text);
                assert_eq!(plain_text, re_cbc_plain_text, "Get back the text we expect - cbc {}", *test_case);
            }
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
        assert!(block_size < 256, "PKCS7 won't work for block size of >= 256");
        // We want a full block if we already match block size
        let padding_needed = block_size - buf.len() % block_size;
        let padding_needed = padding_needed as u8;
        let mut v = buf.to_vec();
        v.extend((0..padding_needed).map(|_| padding_needed));
        v
    }

    pub fn pkcs7_unpad(block_size: usize, buf: &[u8]) -> Result<Vec<u8>,String> {
        let num_blocks = buf.len() / block_size;
        if num_blocks * block_size != buf.len() {
            return Err(format!("Length [{}] not a multiple of block size [{}]", num_blocks, block_size))
        }

        let last_chunk = &buf[(num_blocks-1) * block_size..];
        let discard_bytes = *last_chunk.last().unwrap() as usize;
        if discard_bytes > last_chunk.len() {
            return Err(format!("Invalid padding value: discard {} len {}", discard_bytes, last_chunk.len()));
        }
        for _ in 0..discard_bytes {
            if last_chunk[last_chunk.len() - discard_bytes] != discard_bytes as u8 {
                return Err("Invalid padding bytes".to_string());
            }
        }
        Ok(buf[0..buf.len() - discard_bytes].to_vec())
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
