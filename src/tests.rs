
mod set4 {
    use convert::*;
    use set4::*;
    use sha1::*;

    #[test]
    pub fn test_challenge29() {
        let orig_msg = s2b("The quick brown fox jumps over the lazy dog");
        // This is hash of msg+glue1
        let original_hash = sha1(&orig_msg);

        // Predict the glue used in the original_hash.
        let glue_padding = sha1_glue_padding(orig_msg.len() as u64);

        // So if we do a real sha1 of (msg+glue+suffix)
        let suffix = &s2b(" - quickly");
        let mut msg = orig_msg.clone();
        msg.extend_from_slice(&glue_padding);
        msg.extend_from_slice(suffix);
        let hash_extended_msg = sha1(&msg);

        // Now go back to the original hash - we can extract the state
        let s = c29_split_sha1_hash(&original_hash);
        // And build a hash just from suffix+state (and knowledge of original length)
        let hash_state_plus_padding = sha1_with_state(
            suffix,
            (orig_msg.len() + glue_padding.len() + suffix.len()) as u64,
            s[0],
            s[1],
            s[2],
            s[3],
            s[4],
        ).unwrap();

        // And they match
        assert_eq!(
            hash_extended_msg, hash_state_plus_padding,
            "hashing nothing extra leaves hash in same state"
        );
    }

    #[test]
    pub fn test_challenge28() {
        // $ echo -n "The quick brown fox jumps over the lazy dog" | sha1sum
        // 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12  -
        let h = sha1(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            h,
            hex2bytes("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap()
        );
        println!("hash is {:02x?}", h);
    }
}

mod set3 {
    use convert::*;
    use rand::Rng;
    use set3::*;

    /*
     * Too slow to leave in
     *
    use util::*;

    #[test]
    pub fn challenge24_b() {
        let token_length = 16;
        let test_cases = (0..20).map(|_| {
            let is_a_token = rand::thread_rng().gen();
            if is_a_token {
                (is_a_token, mt_make_password_token(token_length))
            } else {
                (is_a_token, get_random_bytes(token_length))
            }
        });

        for test_case in test_cases {
            let (actually_is_a_token, buf) = test_case;
            let detected_token = is_current_time_mt_token(&buf);
            assert_eq!(actually_is_a_token, detected_token);
        }
    }
    */

    #[test]
    pub fn test_longest_common_substring() {
        let test_cases = [
            ("fooo", "poodle", "oo"),
            ("fooo", "pooodle", "ooo"),
            ("fooo", "badger", ""),
            ("foofoooofoo", "fooxfooooboo", "foooo"),
        ];

        for test_case in test_cases.iter() {
            let (xs, ys, expected_longest) = *test_case;
            let xs = &s2b(xs);
            let ys = &s2b(ys);
            let longest_ss = b2s(&longest_common_substring(xs, ys));
            assert_eq!(longest_ss, expected_longest);
        }
    }

    #[test]
    pub fn test_slice_contains() {
        let test_cases = [
            ("fooo", "f", true),
            ("ooo", "f", false),
            ("furrfuu", "furr", true),
            ("furrfuu", "urrf", true),
            ("furrfuu", "fuu", true),
            ("furrfuu", "rrr", false),
            ("furrfuu", "uuu", false),
        ];

        for test_case in test_cases.iter() {
            let (xs, ys, expected_contains) = *test_case;
            let xs = s2b(xs);
            let ys = s2b(ys);
            let contains = slice_contains(&xs, &ys);
            assert_eq!(contains, expected_contains);
        }
    }

    #[test]
    pub fn test_substring_finder() {
        //            let test_cases = [("foo", ["f", "fo", "foo", "o", "oo", "o"])];
        let test_cases = [("foo", ["foo", "fo", "oo", "f", "o", "o"])];
        for test_case in test_cases.iter() {
            let (s, ss) = *test_case;
            let s = &s2b(&s);
            let ss = ss.iter().map(|ss_str| s2b(ss_str));
            let finder = SubstringFinder::new(s);
            finder.for_each(|substr| println!("JB found {}", b2s(&substr)));
            let finder = SubstringFinder::new(s);
            assert!(finder.eq(ss));
        }
    }

    #[test]
    pub fn test_mt_ctr() {
        let plain_text = &s2b("Wooodle booodle fluffetey buffetey");

        let random_seed: u16 = rand::thread_rng().gen();
        let cipher_text = &mt_ctr_cryptor(random_seed, &plain_text);
        assert_ne!(cipher_text, plain_text);

        let replain_text = &mt_ctr_cryptor(random_seed, &cipher_text);
        assert_eq!(plain_text, replain_text);
    }

    #[test]
    pub fn test_challenge23_tempering() {
        let test_cases = (0..10).map(|_| rand::random::<u32>());
        let l = 18;
        let t = 15;
        let c = 0xEFC60000;

        let mt = MersenneTwister::new();

        for tc in test_cases {
            let y = tc ^ (tc >> l);
            let x = y ^ (y >> l);
            assert_eq!(x, tc);

            let y = tc ^ (tc << l);
            let x = y ^ (y << l);
            assert_eq!(x, tc);

            let y = tc ^ ((tc << t) & c);
            let x = y ^ ((y << t) & c);
            assert_eq!(x, tc);

            let y_tempered = mt.temper(tc);
            let y_untempered = mt.untemper(y_tempered);
            assert_eq!(y_untempered, tc);
        }
    }

    #[test]
    pub fn test_challenge23() {
        let random_seed = rand::thread_rng().gen();
        let mut mt = MersenneTwister::new();
        mt.seed(random_seed);

        let mut cloned_mt = mt_clone(&mut mt);

        let count = 100;
        for _ in 0..count {
            let orig_num = mt.genrand_int32();
            let cloned_num = cloned_mt.genrand_int32();
            //                println!("orig {:x} cloned {:x}", orig_num, cloned_num);
            assert_eq!(orig_num, cloned_num, "orig and clone agree");
        }
    }

    #[test]
    fn test_mt_seed() {
        let mut mt_a = MersenneTwister::new();
        mt_a.seed(19650218);
        let mut mt_b = MersenneTwister::new();
        mt_b.seed(19650218);
        let mut mt_x = MersenneTwister::new();
        mt_x.seed(1623577);

        let num_tests = 100;
        for _ in 0..num_tests {
            let a = mt_a.genrand_int32();
            let b = mt_b.genrand_int32();
            let x = mt_x.genrand_int32();
            assert_eq!(
                a,
                b,
                //                    format!("Same seed for iteration {} still the same", i)
            );
            assert_ne!(
                a,
                x,
                //                    format!("Diff seed for iteration {} still the same", i)
            );
        }
    }
}

mod set2 {
    use convert::*;
    use set2::*;
    use std::collections::*;
    use util::*;

    #[test]
    fn challenge15() {
        let test_cases = [
            ("ICE ICE BABY\x04\x04\x04\x04", true, "ICE ICE BABY"),
            ("ICE ICE BABY\x04\x01\x04\x04", false, ""),
            ("ICE ICE BABY\x04\x04\x01\x04", false, ""),
            ("ICE ICE BABY\x01\x04\x04\x04", false, ""),
            ("ICE ICE BABY\x05\x05\x05\x05", false, ""),
            ("ICE ICE BABY\x01\x02\x03\x04", false, ""),
        ];
        let block_size = 16;

        for test_case in test_cases.iter() {
            let (s, should_work, expected_unpadded) = *test_case;
            match pkcs7_unpad(block_size, &s2b(&s)) {
                Ok(unpadded) => {
                    assert!(should_work, "Succeeded successfully");
                    assert_eq!(unpadded, s2b(expected_unpadded), "Correct unpadded string");
                }
                Err(_) => {
                    assert!(!should_work, "Failed successfully");
                }
            }
        }
    }

    fn hm_to_string(hm: &HashMap<&str, &str>) -> HashMap<String, String> {
        hm.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn challenge13() {
        let test_cases = [
            ("foo=bar", Ok(hashmap!("foo" => "bar"))),
            (
                "foo=bar&baz=quux",
                Ok(hashmap!("foo" => "bar", "baz" => "quux")),
            ),
            (
                "baz=quux&foo=bar",
                Ok(hashmap!("foo" => "bar", "baz" => "quux")),
            ),
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
            assert_eq!(&c13_parse_kv_to_hm(&s2b(s)), &expected_result);
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
            assert!(
                padded_msg.len() % block_size == 0,
                "padded msg is a multiple of block size"
            );
            let unpadded_msg = pkcs7_unpad(block_size, &padded_msg).unwrap();
            assert_eq!(unpadded_msg, msg);
        }
    }
}

mod set1 {
    use convert::*;
    use set1::*;
    use set2::*;
    use util::*;

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
            assert_eq!(
                plain_text, re_ecb_plain_text,
                "Get back the text we expect - ecb {}",
                *test_case
            );
            let cbc_cipher_text = &aes128_cbc_encode(&key, iv, plain_text);
            let re_cbc_plain_text = &aes128_cbc_decode(&key, iv, &cbc_cipher_text);
            assert_eq!(
                plain_text, re_cbc_plain_text,
                "Get back the text we expect - cbc {}",
                *test_case
            );
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
        let test_cases = [("000000", "000001", 1), ("000000", "000003", 2)];

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

        assert_eq!(
            xor_buf("".as_bytes(), "".as_bytes()).unwrap(),
            "".as_bytes()
        );

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
        let expected_b64_str =
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(expected_b64_str, b64_str);
    }

    #[test]
    fn order_freq() {
        let test_cases = [
            ("foo", "of"),
            ("aaabcde", "abcde"), // equal freqencies match in lexo order
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
            let expected_cipher_text =
                hex2bytes(&expected_cipher_text_hex).expect("Test is wrong");
            let key = hex2bytes(&key_hex).expect("Test is wrong");
            let cipher_text = xor_decode(&key, &plain_text);
            assert_eq!(cipher_text, expected_cipher_text);
        }
    }

}

