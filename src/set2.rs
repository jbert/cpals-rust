use convert::*;
use itertools::Itertools;
use rand::Rng;
use set1::*;
use std::collections::*;
use std::iter;
use std::panic::catch_unwind;
use util::*;

pub fn challenge16() {
    let block_size = 16;
    let key = get_random_bytes(block_size);
    let iv = get_random_bytes(block_size);
    let c16_encryptor = |user_data: &[u8]| c16_encryptor_helper(&key, &iv, user_data);
    let c16_decryptor = |cipher_text: &[u8]| c16_decryptor_helper(&key, &iv, cipher_text);

    // We can choose plaintext and flip bits in ciphertext
    // We'll have a sacrificial block in the plaintext which will get garbled when we flip
    // followed by a target block starting ';admin=true;', but with a bit flipped in the ; and =
    // chars
    // We will flip the three bits needed in the ciphertext corresponding to the sacrificial
    // block to flip back those three chars to the special chars.
    // How to find the block offsets? Try 'em all

    let pad_char = 'A' as u8;
    let mut payload = s2b(";admin=true;");
    payload[0] ^= 0x01;
    payload[6] ^= 0x01;
    payload[11] ^= 0x01;
    for offset in 0..block_size {
        // Sacrificial block plus pad chars to try offset
        let mut chosen_plain_text: Vec<u8> =
            iter::repeat(pad_char).take(block_size + offset).collect();
        chosen_plain_text.extend_from_slice(&payload);
        let mut cipher_text = c16_encryptor(&chosen_plain_text);
        // We don't know which block to flip. Let's try 'em all
        for block_index in 0..=cipher_text.len() / block_size {
            // bit those flips
            cipher_text[block_index * block_size + offset + 0] ^= 0x01;
            cipher_text[block_index * block_size + offset + 6] ^= 0x01;
            cipher_text[block_index * block_size + offset + 11] ^= 0x01;
            match c16_decryptor(&cipher_text) {
                Ok(is_admin) => {
                    println!("Got is_admin: {}", is_admin);
                    if is_admin {
                        println!("Woo dunnit");
                        return;
                    }
                }
                Err(err_str) => println!("Error decypting: {}", err_str),
            }
        }
    }
}

pub fn c16_decryptor_helper(key: &[u8], iv: &[u8], cipher_text: &[u8]) -> Result<bool, String> {
    let plain_text = match catch_unwind(|| aes128_cbc_decode(&key, &iv, &cipher_text)) {
        Ok(plain_text) => Ok(plain_text),
        Err(o) => Err(format!("Decode/padding error: {:?}", o)),
    }?;
    // Keep only ascii chars
    let plain_text = plain_text
        .iter()
        .filter(|c| c.is_ascii())
        .map(|c| *c)
        .collect::<Vec<_>>();
    match String::from_utf8(plain_text.to_vec()) {
        Err(_) => {
            println!("from_utf8 error");
            // It's not an encoding error
            Ok(false)
        }
        Ok(s) => {
            println!("got {}", &s);
            Ok(s.contains(";admin=true;"))
        }
    }
}

pub fn c16_encryptor_helper(key: &[u8], iv: &[u8], user_data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    assert!(
        key.len() == block_size,
        format!("AES128 requires {} byte key", block_size)
    );
    assert!(
        iv.len() == block_size,
        format!("AES128 requires {} byte iv", block_size)
    );

    // Escape special chars
    let user_data = &b2s(user_data).replace(";", "%3b").replace("=", "%3d");

    let prefix = &s2b("comment1=cooking%20MCs;userdata=");
    let suffix = &s2b(";comment2=%20like%20a%20pound%20of%20bacon");

    let mut plain_text = prefix.to_vec();
    plain_text.extend_from_slice(&s2b(&user_data));
    plain_text.extend_from_slice(suffix);
    aes128_cbc_encode(&key, &iv, &plain_text) // Include PKCS7 padding
}

pub fn challenge14() {
    let key = get_random_bytes(16);
    let c14_cryptor = |pt: &[u8]| c14_cryptor_helper(&key, pt);

    let block_size = 16;

    let mut recovered_plain_text: Vec<u8> = Vec::new();
    let pad_char = 'A' as u8;

    // We need to:
    // - build our next trick block
    // - get the ciphertext for the trick block
    //   we can do this even with random prefix because:
    //   - we can pad enough before trick block to get duplicates
    //   - the post-duplicates block has 1-in-16 chance of being our trick block, so 16*256
    //   possible
    //   - we can repeat until we have all 16 possible trick cipher blocks
    // - with our (16 possible) cipher trick blocks, we can repeat the previous attack
    // until one of our trick blocks shows up

    loop {
        let mut chosen_plain_text = recovered_plain_text.clone();
        let cptl = chosen_plain_text.len();
        if cptl > block_size - 1 {
            chosen_plain_text = chosen_plain_text[cptl - (block_size - 1)..].to_vec();
        }
        let mut added_pad = 0;
        while chosen_plain_text.len() < block_size - 1 {
            chosen_plain_text.insert(0, pad_char);
            added_pad = added_pad + 1;
        }
        //            println!("JB - cpt {}", b2s(&chosen_plain_text));
        assert_eq!(
            chosen_plain_text.len(),
            block_size - 1,
            "Using correct size chosen_plain_text block"
        );

        //            println!("JB - getting dictionary");
        let dictionary =
            c14_dictionary_for_block(block_size, &chosen_plain_text, &c14_cryptor).unwrap();
        //            println!("JB - got dictionary {} elts", dictionary.len());

        let mut next_byte = None;
        let num_attempts = 10 * block_size;
        for _ in 0..num_attempts {
            // Now use the same amount of pad chars
            let pad: Vec<u8> = iter::repeat(pad_char).take(added_pad).collect();
            let cipher_text = c14_cryptor(&pad);
            for block in cipher_text.chunks(block_size) {
                next_byte = dictionary.get(block);
                if next_byte.is_some() {
                    break;
                }
            }
            if next_byte.is_some() {
                break;
            }
        }
        match next_byte {
            Some(next_byte) => recovered_plain_text.push(*next_byte),
            None => {
                println!("Failed to find next byte in {} iterations", num_attempts);
                break;
            }
        }
        println!("Recovered: {}", &b2s(&recovered_plain_text));
    }
    println!("S2C14 msg is {}", b2s(&recovered_plain_text));
}

fn c14_dictionary_for_block(
    block_size: usize,
    chosen_plain_text: &[u8],
    cryptor: &Fn(&[u8]) -> Vec<u8>,
) -> Result<HashMap<Vec<u8>, u8>, String> {
    assert_eq!(
        chosen_plain_text.len(),
        block_size - 1,
        "Using correct size chosen_plain_text block"
    );

    let enough_padding_for_only_two_duplicates = iter::repeat('_' as u8)
        .take(3 * block_size - 1)
        .collect::<Vec<_>>();
    let mut dictionary = HashMap::new();
    let mut duplicates = HashSet::new();
    for end_byte in 0..=255 {
        //            println!("Getting byte {}", end_byte);
        let mut candidates = HashSet::new();

        let mut plain_text = enough_padding_for_only_two_duplicates.clone();
        plain_text.append(&mut chosen_plain_text.to_vec());
        plain_text.push(end_byte);

        while candidates.len() < 16 {
            let cipher_text = cryptor(&plain_text);
            let candidate = find_block_after_duplicates(block_size, &cipher_text)
                .expect("There was no duplicate!");
            candidates.insert(candidate);
        }
        for candidate in candidates {
            if { duplicates.contains(&candidate) } {
                continue;
            }
            if { dictionary.contains_key(&candidate) } {
                dictionary.remove(&candidate);
                duplicates.insert(candidate);
                continue;
            }
            /*
            println!(
                "JB - dict len {} byte {} adding candidate {:?}",
                dictionary.len(),
                end_byte,
                &candidate
            );
            */
            dictionary.insert(candidate, end_byte);
        }
    }
    //        for duplicate in duplicates {
    //            println!("JB - dup {:?}", duplicate);
    //        }
    return Ok(dictionary);
}

fn find_block_after_duplicates(block_size: usize, buf: &[u8]) -> Option<Vec<u8>> {
    let mut target_block: Vec<u8> = Vec::new();
    let mut next_is_target = false;
    let mut last_block: Vec<u8> = Vec::new();
    for block in buf.chunks(block_size) {
        let this_block = block.to_vec();
        if this_block == last_block {
            next_is_target = true;
            continue;
        }
        if next_is_target {
            target_block = block.to_vec();
            break;
        }
        last_block = this_block;
    }
    if target_block.len() > 0 {
        Some(target_block)
    } else {
        None
    }
}

pub fn c14_cryptor_helper(key: &[u8], plain_text_middle: &[u8]) -> Vec<u8> {
    let block_size = 16;
    assert!(
        key.len() == block_size,
        format!("AES148 requires {} byte key", block_size)
    );

    let num_prefix_bytes = rand::thread_rng().gen_range(block_size, 6 * block_size);
    let prefix = get_random_bytes(num_prefix_bytes);

    let suffix = str::replace(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK",
        "\n",
        "",
    );

    let suffix = &base642bytes(&s2b(&suffix)).expect("Must be base64!");

    let mut plain_text = prefix.to_vec();
    plain_text.extend_from_slice(plain_text_middle);
    plain_text.extend_from_slice(suffix);
    aes128_ecb_encode(&key, &plain_text)
}

pub fn challenge13() {
    let key = get_random_bytes(16);
    let mut encode_profile_for_email =
        |email_address: &[u8]| aes128_ecb_encode(&key, &s2b(&c13_profile_for(email_address)));
    let decode_to_profile = |cipher_text: &[u8]| {
        let profile_str = aes128_ecb_decode(&key, &cipher_text);
        c13_parse_kv(&profile_str)
    };

    let email = &s2b("bob@example.com");
    println!(
        "S2C13 - Profile for [{}] is [{}]",
        b2s(&email),
        c13_profile_for(email)
    );
    let cipher_text = encode_profile_for_email(email);
    let profile = decode_to_profile(&cipher_text);
    println!(
        "S2C13 - Role for decoded profile: {}",
        profile.expect("can get profile").role
    );

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
    let mut target_cipher_block: Vec<u8> = Vec::new();
    for padding in block_size - 1..block_size * 3 {
        let mut padded_email_address = "_".repeat(padding);
        padded_email_address.push_str(&target_text_str);
        padded_email_address.push_str("@example.com"); // because why not
        let cipher_text = encode_profile_for_email(&s2b(&padded_email_address));

        let mut next_is_target = false;
        let mut last_block: Vec<u8> = Vec::new();
        for block in cipher_text.chunks(block_size) {
            if block.to_vec() == last_block {
                next_is_target = true;
                continue;
            }
            if next_is_target {
                target_cipher_block = block.to_vec();
                break;
            }
            last_block = block.to_vec();
        }
        if target_cipher_block.len() > 0 {
            println!("S2C13 - found target at offset {}", padding);
            break;
        }
    }
    if target_cipher_block.len() <= 0 {
        panic!("Didn't find target cipher block")
    }

    // At some padding between 0..block_size the end block should
    // be 'user<pkcspadding>'. If so, replacing it with our
    // target cipher block should give us something which will decode
    // to our desired plaintext
    for padding in 0..block_size - 1 {
        let mut padded_email_address = "_".repeat(padding);
        padded_email_address.push_str("@example.com");

        let mut cipher_text = encode_profile_for_email(&s2b(&padded_email_address));
        //            cipher_text[cipher_text.len() - block_size..cipher_text.len()] = target_cipher_block;
        let cipher_text_len = cipher_text.len();
        cipher_text.splice(
            cipher_text_len - block_size..cipher_text_len,
            target_cipher_block.clone(),
        );
        match decode_to_profile(&cipher_text) {
            Ok(profile) => if profile.role == "admin" {
                println!("S2C13 - did it! got an admin role");
                return;
            },
            Err(_) => {
                continue; // We don't care about failed decodes, we'll probably get a few
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
    fn from_hm(hm: &HashMap<String, String>) -> UserProfile {
        UserProfile {
            email: hm.get(&"email".to_string())
                .expect("Must have email")
                .clone(),
            uid: hm.get(&"uid".to_string()).expect("Must have email").clone(),
            role: hm.get(&"role".to_string())
                .expect("Must have email")
                .clone(),
        }
    }
}

pub fn c13_profile_for(email_address: &[u8]) -> String {
    let email_address = &b2s(email_address);
    let email_address = email_address.replace("&", "").replace("=", "");
    UserProfile {
        email: email_address.to_string(),
        uid: "10".to_string(),
        role: "user".to_string(),
    }.to_string()
}

pub fn c13_parse_kv(s: &[u8]) -> Result<UserProfile, String> {
    let hm = c13_parse_kv_to_hm(&s)?;
    Ok(UserProfile::from_hm(&hm))
}

pub fn c13_parse_kv_to_hm(buf: &[u8]) -> Result<HashMap<String, String>, String> {
    let s = &b2s(buf);
    s.split("&")
        .map(|sub_string| {
            match sub_string.split("=").next_tuple() {
                Some(t) => Ok(t),
                None => Err("No equals sign".to_string()),
            }.map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

pub fn challenge12() {
    let key = get_random_bytes(16);
    let mut c12_cryptor = |pt: &[u8]| c12_cryptor_helper(&key, pt);

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
        let added_pad = block_size - ((recovered_plain_text.len() + 1) % block_size);
        let pad: Vec<u8> = iter::repeat(pad_char).take(added_pad).collect();

        let cipher_text = c12_cryptor(&pad);

        let mut chosen_plain_text: Vec<u8> = pad.clone();
        chosen_plain_text.extend(recovered_plain_text.clone());
        assert_eq!(
            chosen_plain_text.len() % block_size,
            block_size - 1,
            "Padding worked"
        );

        let last_block = chosen_plain_text.len() / block_size;
        let trick_plain_block = &chosen_plain_text[last_block * block_size..];
        let trick_cipher_block =
            &cipher_text[last_block * block_size..(last_block + 1) * block_size];
        //            println!("JB - trick_plain [{}]", b2s(&trick_plain_block));

        let next_byte =
            c12_find_next_byte(&c12_cryptor, &trick_plain_block, &trick_cipher_block);
        if !(next_byte == 0x0a || next_byte == 0xad || (next_byte >= 32 && next_byte < 127)) {
            break;
        }
        recovered_plain_text.push(next_byte);
    }
    println!("S2C12 msg is {}", b2s(&recovered_plain_text));
}

fn c12_find_next_byte(
    cryptor: &Fn(&[u8]) -> Vec<u8>,
    plain_block: &[u8],
    trick_cipher_block: &[u8],
) -> u8 {
    let block_size = trick_cipher_block.len();
    for guess in 0..=255 {
        let mut trial_plain_text = plain_block.to_vec();
        trial_plain_text.push(guess);
        //            println!("JB - trial_plain [{}]", b2s(&trial_plain_text));
        let trial_cipher_text = cryptor(&trial_plain_text);
        //            println!("JB - trial block is: {:?}", &trial_cipher_text[0..block_size]);
        //            println!("JB - trick_cipher is: {:?}", &trick_cipher_block);
        if &trial_cipher_text[0..block_size] == trick_cipher_block {
            return guess;
        }
    }
    panic!("Failed to find byte");
}

fn find_blocksize(cryptor: &Fn(&[u8]) -> Vec<u8>) -> usize {
    let mut last_cipher_text_size = 0;
    for plaintext_len in 0..1024 {
        let cipher_text = cryptor(&s2b(&"_".repeat(plaintext_len)));
        if last_cipher_text_size > 0 {
            // Not really necessary...can't we just encode 1 byte and assume PCKS-7?
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
    assert!(
        key.len() == block_size,
        format!("AES128 requires {} byte key", block_size)
    );
    let suffix = str::replace(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK",
        "\n",
        "",
    );
    let suffix = &base642bytes(&s2b(&suffix)).expect("Must be base64!");

    let mut plain_text = plain_text.to_vec();
    plain_text.extend_from_slice(suffix);
    aes128_ecb_encode(&key, &plain_text)
}

pub fn get_random_buf(lo: usize, hi: usize) -> Vec<u8> {
    let num = rand::thread_rng().gen_range(lo, hi);
    get_random_bytes(num)
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
    let cipher_text = slurp_base64_file("10.txt");
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
    match try_aes128_cbc_decode(&key, &iv, &cipher_text) {
        Ok(plain_text) => plain_text,
        Err(s) => panic!(format!("Decode failed: {}", s)),
    }
}

pub fn try_aes128_cbc_decode(
    key: &[u8],
    iv: &[u8],
    cipher_text: &[u8],
) -> Result<Vec<u8>, String> {
    let block_size = 16;
    let padded_plain_text = aes128_cbc_decode_no_padding(&key, &iv, &cipher_text);
    pkcs7_unpad(block_size, &padded_plain_text)
}

pub fn aes128_cbc_decode_no_padding(key: &[u8], iv: &[u8], cipher_text: &[u8]) -> Vec<u8> {
    let block_size = 16;
    assert!(
        key.len() == block_size,
        format!("AES128 requires {} byte key", block_size)
    );
    assert!(
        iv.len() == block_size,
        format!("AES128 requires {} byte iv", block_size)
    );
    assert!(
        cipher_text.len() % block_size == 0,
        "Cipher text must be multiple of block size"
    );

    // CBC consumes previous ciphertext blocks, prepended with the IV
    let mut last_cipher_block = iv.to_vec();
    let cipher_blocks = cipher_text.chunks(block_size);
    let plain_blocks = cipher_blocks.map(|cipher_block| {
        //            println!("JB - about to decode key len {} block len {}", key.len(), last_cipher_block.len());
        //            println!("JB - decode last cipher block block {:x?}", last_cipher_block);
        //            println!("JB - decode this cipher block block {:x?}", cipher_block);
        let xor_input_block = aes128_crypt_block(false, &key, &cipher_block);
        let plain_block =
            xor_buf(&xor_input_block, &last_cipher_block).expect("Block size mismatch!?");
        last_cipher_block = cipher_block.clone().to_vec();
        plain_block
    });
    plain_blocks.collect::<Vec<_>>().concat()
}

pub fn aes128_cbc_encode(key: &[u8], iv: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let block_size = 16;
    assert!(
        key.len() == block_size,
        format!("AES128 requires {} byte key", block_size)
    );
    assert!(
        iv.len() == block_size,
        format!("AES128 requires {} byte iv", block_size)
    );

    // CBC consumes previous ciphertext blocks, prepended with the IV
    let mut last_cipher_block = iv.to_vec();
    let padded_plain_text = pkcs7_pad(block_size, plain_text);
    let plain_blocks = padded_plain_text.chunks(block_size);
    let cipher_blocks = plain_blocks.map(|plain_block| {
        let ecb_input_block =
            &xor_buf(&plain_block, &last_cipher_block).expect("Block size mismatch!?");
        let cipher_block = aes128_crypt_block(true, &key, &ecb_input_block);
        //            println!(
        //                "JB - CBC prev cipher {:x?} plain block {:x?} cipher block {:x?}",
        //                last_cipher_block, plain_block, cipher_block
        //            );
        last_cipher_block = cipher_block.clone();
        cipher_block
    });
    cipher_blocks.collect::<Vec<_>>().concat()
}
