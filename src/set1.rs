use convert::*;
use openssl::symm;
use std::collections::HashSet;
use util::*;

pub fn challenge8() {
    let lines = slurp_hex_file_as_lines("8.txt");
    let block_size = 16;
    for (lineno, line) in lines.iter().enumerate() {
        let num_blocks = line.len() / block_size;
        let mut blocks = line.chunks(block_size);
        let distinct_blocks = blocks.collect::<HashSet<_>>();
        if distinct_blocks.len() != num_blocks {
            println!(
                "s1 c8: Line {} has only {} distinct blocks, not {}",
                lineno,
                distinct_blocks.len(),
                num_blocks
                );
        }
    }
}

pub fn challenge7() {
    let key = s2b(&"YELLOW SUBMARINE");
    let cipher_text = slurp_base64_file("7.txt");

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
    println!(
        "S1 C7 msg is {}",
        b2s(&aes128_ecb_decode(&key, &cipher_text))
        );
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

pub fn aes128_ecb_helper(encode: bool, key: &[u8], in_text: &[u8]) -> Vec<u8> {
    let block_size = 16;
    in_text
        .chunks(block_size)
        .map(|in_block| aes128_crypt_block(encode, &key, &in_block))
        .collect::<Vec<_>>()
        .concat()
}

pub fn aes128_crypt_block(encode: bool, key: &[u8], in_text: &[u8]) -> Vec<u8> {
    aes128_crypt_block_helper(encode, key, in_text).expect("Failed to crypt")
}

pub fn aes128_crypt_block_helper(
    encode: bool,
    key: &[u8],
    in_text: &[u8],
    ) -> Result<Vec<u8>, String> {
    let cipher = symm::Cipher::aes_128_ecb();
    let block_size = cipher.block_size();
    assert_eq!(block_size, key.len(), "wrong size key");
    assert_eq!(block_size, in_text.len(), "wrong size input text");
    let iv = s2b(&"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    let mut crypter = symm::Crypter::new(
        cipher,
        match encode {
            true => symm::Mode::Encrypt,
            false => symm::Mode::Decrypt,
        },
        key,
        Some(&iv),
        ).unwrap();
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
    let keysizes =
        guess_repeated_xor_keysize(max_keysize_to_try, num_keysizes_to_return, &cipher_text);

    //        println!("keysizes {:?}", keysizes);

    let mut guesses = keysizes
        .iter()
        .map(|&ks| break_repeated_xor(ks, &cipher_text))
        .collect::<Vec<_>>();
    guesses.sort_by(|&(score_a, _), &(score_b, _)| {
        score_b.partial_cmp(&score_a).expect("Not a nan")
    });
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
    let key = blocks
        .iter()
        .map(|block| {
            //            println!("buf len is {}", block.len());
            //            println!("beginning of buf is {:?}", &block[0..10]);
            let (k, _) = break_single_byte_xor(&block);
            //            println!("key byte is {:?}", k);
            k
        })
    .collect::<Vec<_>>();

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

pub fn guess_repeated_xor_keysize(
    max_keysize_checked: usize,
    num_keysizes_to_return: usize,
    cipher_text: &[u8],
    ) -> Vec<usize> {
    let mut hd_keysizes = (2..max_keysize_checked)
        .map(|keysize| {
            // Look at the distances between the first block and the next few
            let abuf = &cipher_text[0..keysize];
            let bbuf = &cipher_text[keysize..keysize * 2];
            let cbuf = &cipher_text[keysize * 2..keysize * 3];
            let dbuf = &cipher_text[keysize * 3..keysize * 4];
            let hd = (hamming_distance(abuf, bbuf) + hamming_distance(bbuf, cbuf)
                      + hamming_distance(cbuf, dbuf)) / 3;
            (keysize, hd as f64 / keysize as f64)
        })
    .collect::<Vec<_>>();
    hd_keysizes.sort_by(|&(_, hd_a), &(_, hd_b)| hd_a.partial_cmp(&hd_b).expect("Not a nan"));
    hd_keysizes
        .iter()
        .take(num_keysizes_to_return)
        .map(|&(ks, _)| ks)
        .collect()
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
    let cipher_text = hex2bytes(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        ).unwrap();

    let (min_dist_k, _) = break_single_byte_xor(&cipher_text);
    let plain_text = xor(min_dist_k, &cipher_text);
    println!("S1 C3 msg is: {}", b2s(&plain_text));
}

pub fn break_single_byte_xor(cipher_text: &[u8]) -> (u8, f64) {
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
    return (max_score_k, max_score);
    //        return (min_dist_k, min_distance)
}

