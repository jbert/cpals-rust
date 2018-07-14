use convert::*;
use md4::*;
use set1::*;
use set2::*;
use set3::*;
use sha1::*;
use util::*;
use digest::Input;
use digest::FixedOutput;
use simd::u32x4;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};

pub fn challenge30() {
    let params =
        &s2b("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
    let hidden_key = s2b("giraffe");
    let mac = c30_mac(&hidden_key, &params);
    let c30_validator =
        |p: &[u8], m: &[u8]| c30_validated_url_str_is_admin(&hidden_key.clone(), &p, &m);

    let result = c30_validator(&params, &mac).unwrap();
    println!(
        "S4C30 - We have a valid params (len {}) which gives admin: {:?}",
        params.len(),
        result
    );

    let attack_suffix = s2b(";admin=true");
    let s = c30_md4_hash_to_state(&mac);

    for guessed_key_len in 0..16 {
        let mut attack_params = params.to_vec();

        // Predict the glue used in the original_hash.
        let guessed_orig_msg_len = params.len() as u64 + guessed_key_len;
        let guessed_orig_glue = &sha1_glue_padding(guessed_orig_msg_len);

        attack_params.extend_from_slice(guessed_orig_glue);
        attack_params.extend_from_slice(&attack_suffix);

        let attack_mac = match md4_with_state(&attack_suffix, attack_params.len() as u64 + guessed_key_len, s) {
            Ok(am) => am,
            Err(err_str) => {
                println!("sha1 failed (bad length?) : {:?}", err_str);
                continue;
            }
        };

        match c30_validator(&attack_params, &attack_mac) {
            Ok(is_admin) => if is_admin {
                println!(
                    "S4C30 - got admin params with a good mac (guessed key len {})",
                    guessed_key_len
                );
                break;
            } else {
                println!("S4C30 - wtf!? got a good mac but no admin?");
                break;
            },
            Err(err_str) => {
                println!(
                    "S4C30 - guess len [{}] failed with: {}",
                    guessed_key_len, err_str
                );
            }
        }
    }
}

pub fn md4_with_state(input: &[u8], full_input_len: u64, s: Md4State) -> Result<Vec<u8>, String> {
    let mut h = Md4::new();
    h.state = s;
    h.length_bytes = full_input_len;
    h.process(&input);
    Ok(h.fixed_result().to_vec())
}

pub fn c30_md4_hash_to_state(buf: &[u8]) -> Md4State {
    let words = buf.chunks(4)
        .map(|mut i| i.read_u32::<BigEndian>().unwrap())
        .collect::<Vec<_>>();
    Md4State{s: u32x4(words[0], words[1], words[2], words[3])}
}

pub fn c30_validated_url_str_is_admin(
    key: &[u8],
    params: &[u8],
    mac: &[u8],
) -> Result<bool, String> {
    let check_mac = c30_mac(key, params);
    if check_mac != mac.to_vec() {
        return Err("Invalid mac".to_string());
    }
    let ascii_param_str = b2s(&ascii_filter(&params));
    Ok(ascii_param_str.contains(";admin=true"))
}


pub fn c30_mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&key);
    buf.extend_from_slice(&msg);
    md4(&buf)
}

pub fn md4(buf: &[u8]) -> Vec<u8> {
    let mut h = Md4::new();
    h.process(&buf);
    h.fixed_result().to_vec()
}

pub fn challenge29() {
    let params =
        &s2b("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
    let hidden_key = s2b("badger");
    let mac = c28_mac(&hidden_key, &params);
    let c29_validator =
        |p: &[u8], m: &[u8]| c29_validated_url_str_is_admin(&hidden_key.clone(), &p, &m);

    let result = c29_validator(&params, &mac).unwrap();
    println!(
        "S4C29 - We have a valid params (len {}) which gives admin: {:?}",
        params.len(),
        result
    );

    let attack_suffix = s2b(";admin=true");
    let s = c29_split_sha1_hash(&mac);

    for guessed_key_len in 0..16 {
        let mut attack_params = params.to_vec();

        // Predict the glue used in the original_hash.
        let guessed_orig_msg_len = params.len() as u64 + guessed_key_len;
        let guessed_orig_glue = &sha1_glue_padding(guessed_orig_msg_len);

        attack_params.extend_from_slice(guessed_orig_glue);
        attack_params.extend_from_slice(&attack_suffix);

        let attack_mac = match sha1_with_state(
            &attack_suffix,
            attack_params.len() as u64 + guessed_key_len,
            s[0],
            s[1],
            s[2],
            s[3],
            s[4],
        ) {
            Ok(am) => am,
            Err(err_str) => {
                println!("sha1 failed (bad length?) : {:?}", err_str);
                continue;
            }
        };

        match c29_validator(&attack_params, &attack_mac) {
            Ok(is_admin) => if is_admin {
                println!(
                    "S4C29 - got admin params with a good mac (guessed key len {})",
                    guessed_key_len
                );
                break;
            } else {
                println!("S4C29 - wtf!? got a good mac but no admin?");
                break;
            },
            Err(err_str) => {
                println!(
                    "S4C29 - guess len [{}] failed with: {}",
                    guessed_key_len, err_str
                );
            }
        }
    }
}

pub fn c29_split_sha1_hash(h: &[u8]) -> Vec<u32> {
    h.chunks(4)
        .map(|mut i| i.read_u32::<BigEndian>().unwrap())
        .collect()
}

pub fn c29_validated_url_str_is_admin(
    key: &[u8],
    params: &[u8],
    mac: &[u8],
) -> Result<bool, String> {
    let check_mac = c28_mac(key, params);
    if check_mac != mac.to_vec() {
        return Err("Invalid mac".to_string());
    }
    let ascii_param_str = b2s(&ascii_filter(&params));
    Ok(ascii_param_str.contains(";admin=true"))
}

pub fn challenge28() {
    let msg_a = s2b("play that funky music, white boy");
    let key = get_random_bytes(10);
    let mac_a = c28_mac(&key, &msg_a);
    println!("mac a is {:02x?}", mac_a);
    let mut msg_b = msg_a.clone();
    msg_b[0] = 'P' as u8;
    let mac_b = c28_mac(&key, &msg_b);
    println!("mac b is {:02x?}", mac_a);
    assert_ne!(mac_a, mac_b);

    assert!(c28_validate_mac(&key, &msg_a, &mac_a));
    assert!(c28_validate_mac(&key, &msg_b, &mac_b));
    assert!(!c28_validate_mac(&key, &msg_b, &mac_a));
    assert!(!c28_validate_mac(&key, &msg_a, &mac_b));
}

pub fn c28_validate_mac(key: &[u8], msg: &[u8], mac: &[u8]) -> bool {
    let calculated_mac = c28_mac(key, msg);
    mac.to_vec() == calculated_mac
}

pub fn c28_mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&key);
    buf.extend_from_slice(&msg);
    sha1(&buf)
}

pub fn challenge27() {
    let block_size = 16;
    let hidden_key = get_random_bytes(block_size);
    println!("S4C27 - the sekr1t key is [{:x?}]", hidden_key);
    let iv = hidden_key.clone(); // This is the badness
    let c27_encryptor = |user_data: &[u8]| c16_encryptor_helper(&hidden_key, &iv, user_data);
    let c27_decryptor =
        |cipher_text: &[u8]| c27_decryptor_helper(&hidden_key, &iv, cipher_text);
    let cipher_text = c27_encryptor(&get_random_bytes(3 * block_size));

    // Now let's attack - we want ciphertext block 0
    let first_cipher_block = cipher_text.chunks(block_size).next().unwrap();

    let mut zero_block = Vec::new();
    let mut attack_blocks = Vec::new();
    zero_block.resize(block_size, 0);
    attack_blocks.push(first_cipher_block);
    attack_blocks.push(&zero_block);
    attack_blocks.push(first_cipher_block);

    let attack_cipher_text = attack_blocks.concat();
    let error = c27_decryptor(&attack_cipher_text);
    match error {
        Ok(_) => panic!("Somehow that decrypt was ascii <shrug>"),
        Err(err_str) => {
            let err_str = &err_str[12..];
            let err_str = &err_str[..err_str.len() - 1];
            let err_str = err_str.replace(", ", "");
            let plain_text = hex2bytes(&err_str).unwrap();
            let mut plain_blocks = plain_text.chunks(block_size);
            let plain_1 = plain_blocks.next().unwrap();
            plain_blocks.next();
            let plain_3 = plain_blocks.next().unwrap();

            //                let key = plain_0
            //                    .iter()
            //                    .zip(plain_2.iter())
            //                    .map(|(x, y)| x ^ y)
            //                    .collect::<Vec<_>>();
            let key = xor_buf(&plain_1, &plain_3).unwrap();
            println!("S4C27 - found key [{:x?}]: {}", key, key == hidden_key);
        }
    }
}

pub fn c27_decryptor_helper(key: &[u8], iv: &[u8], cipher_text: &[u8]) -> Result<bool, String> {
    let padded_plain_text = aes128_cbc_decode_no_padding(&key, &iv, &cipher_text);
    let ascii_plain_text = ascii_filter(&padded_plain_text);
    if ascii_plain_text.len() != padded_plain_text.len() {
        return Err(format!("Not ASCII: {:02x?}", padded_plain_text));
    }
    match String::from_utf8(ascii_plain_text.to_vec()) {
        Err(_) => {
            println!("from_utf8 error");
            // It's not an encoding error
            Ok(false)
        }
        Ok(s) => Ok(s.contains(";admin=true;")),
    }
}

// We can choose plaintext and flip bits in ciphertext
pub fn challenge26() {
    let block_size = 16;
    let key = get_random_bytes(block_size);
    let nonce = 0;
    let c26_encryptor = |user_data: &[u8]| c26_encryptor_helper(&key, nonce, user_data);
    let c26_decryptor = |cipher_text: &[u8]| c26_decryptor_helper(&key, nonce, cipher_text);

    let target_text = s2b(";admin=true;");
    let chosen_plain_text = &s2b(&"\x00".repeat(target_text.len())).clone();
    let cipher_text = c26_encryptor(chosen_plain_text);

    // Somewhere in the cipher output is the keystream XOR'd with our chosen plaintext,
    // which happens to be all zeros
    // So if we XOR in our target_text at all different offsets, we should hit it
    // at some point
    for offset in 0..(cipher_text.len() - target_text.len()) {
        let mut flipped_cipher_text = cipher_text.clone();
        target_text.iter().enumerate().for_each(|(i, b)| {
            flipped_cipher_text[offset + i] = flipped_cipher_text[offset + i] ^ b
        });

        let result = c26_decryptor(&flipped_cipher_text);
        if result.is_ok() && result.unwrap() {
            println!("S4C26 - yasss...got admin");
            break;
        }
    }
}

pub fn c26_decryptor_helper(
    key: &[u8],
    nonce: u64,
    cipher_text: &[u8],
) -> Result<bool, String> {
    let plain_text = aes128_ctr_cryptor(&key, nonce, &cipher_text);
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
            //                println!("got {}", &s);
            Ok(s.contains(";admin=true;"))
        }
    }
}

pub fn c26_encryptor_helper(key: &[u8], nonce: u64, user_data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    assert!(
        key.len() == block_size,
        format!("AES128 requires {} byte key", block_size)
    );

    // Escape special chars
    let user_data = &b2s(user_data).replace(";", "%3b").replace("=", "%3d");

    let prefix = &s2b("comment1=cooking%20MCs;userdata=");
    let suffix = &s2b(";comment2=%20like%20a%20pound%20of%20bacon");

    let mut plain_text = prefix.to_vec();
    plain_text.extend_from_slice(&s2b(&user_data));
    plain_text.extend_from_slice(suffix);
    aes128_ctr_cryptor(&key, nonce, &plain_text)
}

pub fn challenge25() {
    let file_key = &s2b("YELLOW SUBMARINE");
    let ecb_cipher_text = slurp_base64_file("25.txt");
    let plain_text = aes128_ecb_helper(false, &file_key, &ecb_cipher_text);

    let key = get_random_bytes(16);
    let nonce = 0;
    let mut editable_cipher_text = aes128_ctr_cryptor(&key, nonce, &plain_text);
    let original_cipher_text = editable_cipher_text.clone();

    let mut chosen_plain_text = Vec::new();
    chosen_plain_text.resize(original_cipher_text.len(), 0);
    c25_aes128_ctr_seek_edit(
        &mut editable_cipher_text,
        &key,
        nonce,
        0,
        &chosen_plain_text,
    );
    // Huh. That's just the key.
    let recovered_plain_text = xor_buf(&editable_cipher_text, &original_cipher_text).unwrap();
    println!("JB ct len {}", b2s(&recovered_plain_text));
}

pub fn c25_aes128_ctr_seek_edit(
    cipher_text: &mut [u8],
    key: &[u8],
    nonce: u64,
    offset: usize,
    new_text: &[u8],
) -> Option<String> {
    let key_stream_for_block = |i_block: u64| {
        let mut v = Vec::new();
        v.write_u64::<LittleEndian>(nonce).unwrap();
        v.write_u64::<LittleEndian>(i_block).unwrap();
        aes128_crypt_block(true, &key, &v)
    };
    let block_size = 16;

    for i in 0..new_text.len() {
        let j = i + offset;
        let j_block = j / block_size;
        let key_stream = key_stream_for_block(j_block as u64);
        let j_key_byte = key_stream[j % block_size];

        cipher_text[j] = new_text[i] ^ j_key_byte;
    }
    None
}
