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
