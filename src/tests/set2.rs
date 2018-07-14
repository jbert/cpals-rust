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
