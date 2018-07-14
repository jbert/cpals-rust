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
