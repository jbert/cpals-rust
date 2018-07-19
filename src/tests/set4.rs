use convert::*;
use set4::*;
use sha1::*;

#[test]
pub fn test_hmac_sha1() {
    let test_cases = [
        ("", "", "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"),
        ("key", "The quick brown fox jumps over the lazy dog", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"),
    ];
    for test_case in test_cases.iter() {
        let key = s2b(test_case.0);
        let msg = s2b(test_case.1);
        let expected_h = hex2bytes(&test_case.2).unwrap();
        let h = hmac_sha1(&key, &msg);
        assert_eq!(h, expected_h);
    }
}

#[test]
pub fn test_md4() {
    let test_cases = [
        ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"),
    ];
    for test_case in test_cases.iter() {
//        println!("JB msg [{}]", test_case.0);
//        println!("JB sha1 glue padding [{:?}]", &md4_glue_padding(test_case.0.len() as u64));
        let msg = s2b(test_case.0);
        let expected_h = hex2bytes(&test_case.1).unwrap();
        let h = md4(&msg);
        assert_eq!(h, expected_h);
    }
}

#[test]
pub fn test_challenge30() {
    let orig_msg = s2b("The quick brown fox jumps over the lazy dog");
    // This is hash of msg+glue1
    println!("JB - before orig hash");
    let original_hash = md4(&orig_msg);
    println!("JB - after  orig hash");

    // Predict the glue used in the original_hash.
    let glue_padding = md4_glue_padding(orig_msg.len() as u64);

    // So if we do a real sha1 of (msg+glue+suffix)
    let suffix = &s2b(" - quickly");
    let mut msg = orig_msg.clone();
    msg.extend_from_slice(&glue_padding);
    msg.extend_from_slice(suffix);
    println!("JB - before ext hash");
    let hash_extended_msg = md4(&msg);
    println!("JB - after  ext hash");

    // Now go back to the original hash - we can extract the state
    let s = c30_md4_hash_to_state(&original_hash);
    // And build a hash just from suffix+state (and knowledge of original length)
    println!("JB - before hash-with-state");
    let hash_state_plus_padding = md4_with_state(
        suffix,
        (orig_msg.len() + glue_padding.len()) as u64,
        s
    ).unwrap();
    println!("JB - after  hash-with-state");

    // And they match
    assert_eq!(
        hash_extended_msg, hash_state_plus_padding,
        "hashing nothing extra leaves hash in same state"
    );
}

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
