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

use hyper::{Body, Response, Server, Request, StatusCode};
use hyper::service::service_fn_ok;
use hyper::rt::Future;

use std::iter::*;
use std::time::{Duration, Instant};
use std::collections::*;
use std::thread::{spawn};

pub fn challenge31() {

    let hostport = "127.0.0.1:8080";
    let server_thread = spawn(move ||{
        let socketaddr = hostport.parse().unwrap();
        let server = Server::bind(&socketaddr)
            .serve(|| service_fn_ok(c31_handler))
            .map_err(|e| eprintln!("server error: {}", e));
        hyper::rt::run(server);
    });

    let example_file = "badger";
    let insecure_msecs = 50;
    let discovered_mac = &c31_find_mac_for_file(&example_file, hostport, insecure_msecs);
    println!("Discovered mac {} for file {}", bytes2hex(discovered_mac), example_file);

    let mut resp = c31_check_mac(&example_file, &hostport, &bytes2hex(discovered_mac), true, insecure_msecs);
    if resp.status() == reqwest::StatusCode::Ok {
        println!("S4C31 - discoverd mac is good");
    } else {
        println!("S4C31 - boo - failed to find mac {}: [{}]", resp.status(), resp.text().unwrap());
    }
    let url = format!("http://{}?shutdown=true", hostport);
    reqwest::get(&url).unwrap();
    let res = server_thread.join();
    if res.is_err() {
        println!("Failed to join: {:?}", res.err().unwrap());
    }
}

pub fn c31_find_mac_for_file(fname: &str, hostport: &str, insecure_msecs: u64) -> Vec<u8> {
    let mac_len_bytes = 20;

    let mut guessed_mac = Vec::new();
    guessed_mac.resize(mac_len_bytes, 0);
    for i in 0..mac_len_bytes {
        let start = Instant::now();
        println!("Trying {}/{}", i+1, mac_len_bytes);
        let mut slowest_byte = 0;
        let mut slowest_dur = Duration::new(0,0);
        for try_byte in 0..=255 {
            guessed_mac[i] = try_byte;
            let start = Instant::now();
            c31_check_mac(fname, hostport, &bytes2hex(&guessed_mac), false, insecure_msecs);
            let dur = start.elapsed();
            //            println!("JB - req took {}: {}", dur_to_fsecs(&dur), resp.text().unwrap());
            if dur > slowest_dur {
                slowest_dur = dur;
                slowest_byte = try_byte;
            }
        }
        guessed_mac[i] = slowest_byte;
        let dur = start.elapsed();
        println!("Got {}: took {}", bytes2hex(&guessed_mac), dur_to_fsecs(&dur));
    }
    guessed_mac
}

pub fn dur_to_fsecs(dur: &Duration) -> f32 {
    let subsec_millis = dur.subsec_nanos() / 1000000;
    dur.as_secs() as f32 + (subsec_millis as f32 / 1000.0)
}

pub fn c31_check_mac(fname: &str, hostport: &str, mac: &str, log_mac: bool, insecure_msecs: u64) -> reqwest::Response {
    let base_url = format!("http://{}?file={}&signature={}&log_mac={}&insecure_msecs={}", hostport, fname, mac, log_mac, insecure_msecs);
    //    println!("JB - sending url {}", base_url);
    reqwest::get(&base_url).unwrap()
}

pub fn c31_insecure_compare(xs: &[u8], ys: &[u8], insecure_msecs: u64) -> bool {
    //    let start = Instant::now();
    if xs.len() != ys.len() {
        return false
    }
    for i in 0..xs.len() {
        if xs[i] != ys[i] {
            //            let dur = start.elapsed();
            //            println!("JB - compare took: {}", dur_to_fsecs(&dur));
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(insecure_msecs));
    }
    //    let dur = start.elapsed();
    //    println!("JB - compare took: {}", dur_to_millis(&dur));
    return true;
}

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let sha1_block_size = 64;

    let key = if key.len() > sha1_block_size {
        sha1(&key)
    } else {
        key.to_vec()
    };
    let key_len = key.len();
    let key = if key_len < sha1_block_size {
        let mut key = key.to_vec();
        key.extend(repeat(0).take(sha1_block_size - key_len));
        key
    } else {
        key
    };
    assert_eq!(key.len(), sha1_block_size, "keylen is now block size");
    let opad = repeat(0x5c).take(sha1_block_size).collect::<Vec<_>>();
    let o_key_pad = xor_buf(&key, &opad).unwrap();
    let ipad = repeat(0x36).take(sha1_block_size).collect::<Vec<_>>();
    let i_key_pad = xor_buf(&key, &ipad).unwrap();
    let mut i_msg = i_key_pad;
    i_msg.extend_from_slice(msg);
    let i_hash = sha1(&i_msg);
    let mut o_msg = o_key_pad;
    o_msg.extend_from_slice(&i_hash);
    sha1(&o_msg)
}

pub fn c31_handler(req: Request<Body>) -> Response<Body> {
    // OK, I give up. Hyper may be in transition (2018/07/19)
    // or I may just be frustrated by docco, but for now I'll assume the
    // whole query string is the mac to verify, rather than "?mac=1234"
    //    println!("JB - got url: {}", req.uri());
    let q = req.uri().query();
    let q = match q {
        Some(q) => q,
        None => "<absent>",
    };
    let params = url::form_urlencoded::parse(q.as_bytes()).into_owned().collect::<HashMap<_,_>>();
    if params.get("shutdown").is_some() {
        println!("Done! bye....");
        std::process::exit(0);
    }
    let file = params.get("file");
    if file.is_none() {
        return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from("Must supply 'file' param\n")).unwrap();
    }
    let file = file.unwrap();
    let sig = params.get("signature");
    if sig.is_none() {
        return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from("Must supply 'signature' param\n")).unwrap();
    }
    let sig = sig.unwrap();
    let sig = hex2bytes(&sig);
    if sig.is_err() {
        let msg = sig.err().unwrap();
        return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from(format!("Bad hex in sig: {}\n", msg))).unwrap();
    }
    let sig = sig.unwrap();
    if sig.len() != 20 {
        return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from("'signature' param wrong length\n")).unwrap();
    }
    let log_mac = match params.get("log_mac") {
        None => false,
        Some(s) => match &s[..] {
            "true" => true,
            _ => false,
        },
    };
    let default_insecure_msecs = 50;
    let insecure_msecs = match params.get("insecure_msecs") {
        None => default_insecure_msecs,
        Some(num_str) => num_str.parse().expect("Must provide numeric value"),
    };

    let secret = s2b("sekr1t");
    // We actually just hash the filename
    let expected_sig = hmac_sha1(&secret, &s2b(&file));
    if log_mac {
        println!("real mac: {}", bytes2hex(&expected_sig));
    }
    let sig_is_good = c31_insecure_compare(&sig, &expected_sig, insecure_msecs);
    let body = Body::from(format!("file: {}\nsignature: {:x?}\nsig_is_good: {}\nlog_mac: {}\n", file, bytes2hex(&sig), sig_is_good, log_mac));
    if sig_is_good {
        Response::new(body)
    } else {
        Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(body).unwrap()
    }
}

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
    println!("JB - recovered state [{}]", &s.to_string());

    for guessed_key_len in 0..16 {
        let mut attack_params = params.to_vec();

        // Predict the glue used in the original_hash.
        let guessed_orig_msg_len = params.len() as u64 + guessed_key_len;
        let guessed_orig_glue = &md4_glue_padding(guessed_orig_msg_len);

        attack_params.extend_from_slice(guessed_orig_glue);
        attack_params.extend_from_slice(&attack_suffix);

        let attack_mac = match md4_with_state(&attack_suffix, params.len() as u64 + guessed_orig_glue.len() as u64 + guessed_key_len, s) {
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

pub fn md4_glue_padding(buflen_bytes: u64) -> Vec<u8> {
    let bit_length = buflen_bytes * 8;

    let mut glue = Vec::new();
    //
    // append the bit '1' to the message e.g. by adding 0x80 if message length
    // is a multiple of 8 bits.
    glue.push(0x80);

    // append 0 ≤ k < 512 bits '0', such that the resulting message length in
    // bits is congruent to −64 ≡ 448 (mod 512)
    let to_fill = (2 * 512 - ((bit_length + 8) % 512) - 64) % 512;

    for _ in 0..to_fill / 8 {
        glue.push(0);
    }

    // append ml, the original message length, as a 64-bit big-endian integer.
    // Thus, the total length is a multiple of 512 bits.
    let mut msglen_bytes: Vec<u8> = vec![];
    msglen_bytes
        .write_u64::<LittleEndian>(bit_length)
        .expect("Couldn't write msglen");

    glue.append(&mut msglen_bytes);
    glue
}

pub fn md4_with_state(input: &[u8], full_input_len: u64, s: Md4State) -> Result<Vec<u8>, String> {
    let mut h = Md4::new();
    h.state = s;
    h.length_bytes = full_input_len;
    h.process(&input);
    let r = h.fixed_result().to_vec();
    Ok(r)
}

pub fn c30_md4_hash_to_state(buf: &[u8]) -> Md4State {
    let words = buf.chunks(4)
        .map(|mut i| i.read_u32::<LittleEndian>().unwrap())
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
    let r = h.fixed_result();
    r.to_vec()
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
