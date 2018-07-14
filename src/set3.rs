use convert::*;
use rand::Rng;
use set1::*;
use set2::*;
use std::clone::Clone;
use util::*;

//    use std::iter::Iterator;
use std::time::{Duration, SystemTime};

pub fn is_current_time_mt_token(token_buf: &[u8]) -> bool {
    let now_epoch = epoch_seconds(SystemTime::now()) as u32;
    let search_delta = 300;
    for delta in 0..search_delta {
        let mut mt = MersenneTwister::new();
        let test_seed_time = now_epoch - delta;
        mt.seed(test_seed_time);

        let mt_start = mt.genrand_buf(200);
        let overlap = longest_common_substring(&mt_start, &token_buf);
        if overlap.len() == token_buf.len() {
            return true;
        }
    }
    return false;
}

pub fn mt_make_password_token(length: usize) -> Vec<u8> {
    let now = SystemTime::now();

    let mut mt = MersenneTwister::new();
    mt.seed(epoch_seconds(now) as u32);
    mt.genrand_buf(length)
}

pub fn challenge24() {
    let hidden_random_seed: u16 = rand::thread_rng().gen();
    let a_length = 18;
    let fixed_plain_text = &s2b(&"A".repeat(a_length)).clone();

    let c24_cryptor = {
        println!("hidden random seed is {:x}", hidden_random_seed);
        |pt| c24_cryptor_helper(hidden_random_seed, pt)
    };

    let cipher_text = c24_cryptor(fixed_plain_text);

    let mut found_it = false;
    for guessed_seed in 0..=65535 {
        //        for guessed_seed in 0..=100 {
        //            println!("Guessed seed {}", guessed_seed);
        let key_stream_with_prefix = cipher_text
            .iter()
            .map(|&b| b ^ 'A' as u8)
            .collect::<Vec<_>>();

        let mut mt = MersenneTwister::new();
        mt.seed(guessed_seed as u32);
        let enough_bytes = 100;
        let seed_key_stream = (0..)
            .flat_map(|_| {
                let mut v = Vec::new();
                let r = mt.genrand_int32();
                v.write_u32::<LittleEndian>(r).unwrap();
                v
            })
            .take(enough_bytes)
            .collect::<Vec<_>>();

        let overlap = longest_common_substring(&key_stream_with_prefix, &seed_key_stream);
        //            println!("JB - overlap len {} a_length {}", overlap.len(), a_length);
        if overlap.len() >= a_length {
            println!("Discovered seed: {:x}", guessed_seed);
            found_it = true;
            break;
        }
    }
    if !found_it {
        println!("Didn't find it :-(");
    }
}

pub fn longest_common_substring(xs: &[u8], ys: &[u8]) -> Vec<u8> {
    // algorithm shmalgorithm
    let longest_first_all_substrings = SubstringFinder::new(ys);
    for y_ss in longest_first_all_substrings {
        if slice_contains(xs, &y_ss) {
            return y_ss;
        }
    }
    Vec::new()
}

pub fn slice_contains<I>(haystack: &[I], needle: &[I]) -> bool
where
    I: PartialEq,
{
    'HAYSTACK: for i in 0..haystack.len() {
        'NEEDLE: for j in 0..needle.len() {
            if i + j >= haystack.len() {
                return false;
            }
            if haystack[i + j] != needle[j] {
                continue 'HAYSTACK;
            }
        }
        return true;
    }
    return false;
}

pub struct SubstringFinder<T> {
    start: usize,
    length: usize,
    s: Vec<T>,
}
impl<T> SubstringFinder<T>
where
    T: Clone,
{
    pub fn new(s: &[T]) -> SubstringFinder<T> {
        let sv = s.to_vec();
        SubstringFinder {
            start: 0,
            length: sv.len(),
            s: sv,
        }
    }
}
impl<T> Iterator for SubstringFinder<T>
where
    T: Clone,
{
    type Item = Vec<T>;
    fn next(&mut self) -> Option<Vec<T>> {
        if self.start + self.length > self.s.len() {
            self.start = 0;
            self.length = self.length - 1;
        }
        if self.length == 0 {
            return None;
        }
        // TODO - learn about lifetime so we don't need to allocate
        let v = self.s[self.start..self.start + self.length].to_vec();
        self.start = self.start + 1;
        return Some(v);
    }
}

pub fn c24_cryptor_helper(seed: u16, input_plain_text: &[u8]) -> Vec<u8> {
    let num_prefix_bytes = rand::thread_rng().gen_range(30, 50);
    let prefix = get_random_bytes(num_prefix_bytes);

    let mut plain_text = prefix.to_vec();
    plain_text.extend_from_slice(input_plain_text);
    mt_ctr_cryptor(seed, &plain_text)
}

pub fn mt_ctr_cryptor(seed: u16, in_buf: &[u8]) -> Vec<u8> {
    let mut mt = MersenneTwister::new();
    mt.seed(seed as u32);

    let key_stream = (0..).flat_map(|_| {
        let mut v = Vec::new();
        //            v.clear();

        let r = mt.genrand_int32();
        v.write_u32::<LittleEndian>(r).unwrap();
        v
    });
    in_buf.iter().zip(key_stream).map(|(b, k)| b ^ k).collect()
}

pub fn mt_clone(mt: &mut MersenneTwister) -> MersenneTwister {
    let mut state = Vec::new();
    for _ in 0..624 {
        let r = mt.genrand_int32();
        //            println!("orig - got {:x}", r);
        let y = mt.untemper(r);
        state.push(y);
    }
    let mut cloned_mt = MersenneTwister::new();
    cloned_mt.seed_from_state(&state);
    for _ in 0..624 {
        cloned_mt.genrand_int32();
    }

    cloned_mt
}

pub fn challenge22() {
    let now = SystemTime::now();
    let offset = Duration::new(500, 0);
    let delta = rand::thread_rng().gen_range(0, 1000);
    let seed_time = now - offset + Duration::new(delta, 0);

    let c22_helper = || {
        let mut mt = MersenneTwister::new();
        mt.seed(epoch_seconds(seed_time) as u32);
        println!(
            "S3C22 - sssh...seeded with {}",
            epoch_seconds(seed_time) as u32
        );
        mt.genrand_int32()
    };

    // Find seed
    let now = SystemTime::now();
    let search_delta = 2000;
    let offset = Duration::new(1000, 0);
    let helper_first_rand = c22_helper();
    for delta in 0..search_delta {
        let mut mt = MersenneTwister::new();
        let test_seed_time = now - offset + Duration::new(delta, 0);
        mt.seed(epoch_seconds(test_seed_time) as u32);
        let first_rand = mt.genrand_int32();
        if helper_first_rand == first_rand {
            println!(
                "S3C22 - found seed {}",
                epoch_seconds(test_seed_time) as u32
            );
            break;
        }
    }
}

pub fn challenge21() {
    let mut mt = MersenneTwister::new();
    mt.seed(19650218);
    /*
     * 1000 outputs of genrand_int32()
     */
    let genrand_int32_expected = [
        1067595299, 955945823, 477289528, 4107218783, 4228976476, 3344332714, 3355579695,
        227628506, 810200273, 2591290167, 2560260675, 3242736208, 646746669, 1479517882,
        4245472273, 1143372638, 3863670494, 3221021970, 1773610557, 1138697238, 1421897700,
        1269916527, 2859934041, 1764463362, 3874892047, 3965319921, 72549643, 2383988930,
        2600218693, 3237492380,
    ];

    let mut oll_korrect = true;
    for expected in genrand_int32_expected.iter() {
        let actual = mt.genrand_int32();
        /*
        println!(
            "JB - mt number: {} expected {} OK {}",
            actual,
            expected,
            actual == *expected
        );
        */
        if actual != *expected {
            oll_korrect = false;
        }
    }
    println!("S3C21 - all correct: {}", oll_korrect);
}

pub struct MersenneTwister {
    // See https://en.wikipedia.org/wiki/Mersenne_Twister#Algorithmic_detail
    w: u32,
    n: usize,
    m: usize,
    r: u32,
    a: u32,
    u: u32,
    d: u32,
    s: u32,
    b: u32,
    t: u32,
    c: u32,
    l: u32,
    f: u32,

    mt: Vec<u32>,
    index: usize,
}
impl MersenneTwister {
    pub fn new() -> MersenneTwister {
        let mut mt = MersenneTwister {
            w: 32,
            n: 624,
            m: 397,
            r: 31,
            a: 0x9908B0DF,
            u: 11,
            d: 0xFFFFFFFF,
            s: 7,
            b: 0x9D2C5680,
            t: 15,
            c: 0xEFC60000,
            l: 18,
            f: 1812433253,
            mt: Vec::new(),

            index: 0,
        };
        mt.mt.resize(mt.n as usize, 0);
        mt.index = mt.n + 1;
        mt
    }

    pub fn seed_from_state(&mut self, state: &[u32]) {
        if state.len() != 624 {
            panic!(format!("Invalid state size: {}", state.len()));
        }
        for (i, y) in state.iter().enumerate() {
            self.mt[i] = *y;
        }
        self.index = 0;
    }

    pub fn seed(&mut self, seed: u32) {
        self.index = self.n;
        self.mt[0] = seed;
        for i in 1..self.n as usize {
            // Don't need to truncate to 32bit because MT[] is Vec<u32>
            self.mt[i as usize] = (self.f as u64
                * (self.mt[i - 1] as u64 ^ (self.mt[i - 1] as u64 >> (self.w - 2)))
                + i as u64) as u32;
        }
    }

    pub fn genrand_int32(&mut self) -> u32 {
        if self.index >= self.n {
            if self.index > self.n {
                panic!("Generator was never seeded");
                // Alternatively, seed with constant value; 5489 is used in reference C code[46]
            }
            self.twist()
        }

        let y = self.mt[self.index];
        self.index = self.index + 1;
        self.temper(y)
    }

    pub fn genrand_buf(&mut self, length: usize) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let r = self.genrand_int32();
            v.write_u32::<LittleEndian>(r).unwrap();
            if v.len() >= length {
                v.truncate(length);
                return v;
            }
        }
    }

    pub fn temper(&self, y: u32) -> u32 {
        let y = self.rshift(y, self.u, self.d);
        let y = self.lshift(y, self.s, self.b);
        let y = self.lshift(y, self.t, self.c);
        let y = self.rshift(y, self.l, 0xffffffff);

        y
    }

    pub fn untemper(&self, y: u32) -> u32 {
        let y = self.invert_rshift(y, self.l, 0xffffffff);
        let y = self.invert_lshift(y, self.t, self.c);
        let y = self.invert_lshift(y, self.s, self.b);
        let y = self.invert_rshift(y, self.u, self.d);

        y
    }

    pub fn rshift(&self, y: u32, num_bits: u32, mask: u32) -> u32 {
        y ^ ((y >> num_bits) & mask)
    }

    pub fn lshift(&self, y: u32, num_bits: u32, mask: u32) -> u32 {
        y ^ ((y << num_bits) & mask)
    }

    pub fn invert_rshift(&self, mut y: u32, num_bits: u32, mask: u32) -> u32 {
        let mut read_bitmask = 1 << 31;
        let mut write_bitmask = read_bitmask >> num_bits;
        while write_bitmask > 0 {
            let bit = y & read_bitmask;
            if bit != 0 {
                y = y ^ write_bitmask & mask;
            }
            read_bitmask = read_bitmask >> 1;
            write_bitmask = write_bitmask >> 1;
        }
        y
    }

    pub fn invert_lshift(&self, mut y: u32, num_bits: u32, mask: u32) -> u32 {
        let mut read_bitmask = 1;
        let mut write_bitmask = read_bitmask << num_bits;
        while write_bitmask > 0 {
            let bit = y & read_bitmask;
            if bit != 0 {
                y = y ^ write_bitmask & mask;
            }
            read_bitmask = read_bitmask << 1;
            write_bitmask = write_bitmask << 1;
        }
        y
    }

    fn twist(&mut self) {
        let lower_mask: u32 = (1 << self.r) - 1;
        let upper_mask: u32 = !lower_mask;
        for i in 0..self.n {
            let x = (self.mt[i] & upper_mask) + ((self.mt[(i + 1) % self.n]) & lower_mask);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a = x_a ^ self.a;
            }
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ x_a;
        }
        self.index = 0;
    }
}

use byteorder::{LittleEndian, WriteBytesExt};

pub fn challenge20() {
    let cipher_texts = slurp_base64_file_as_lines("20.txt");
    let shortest_length = cipher_texts
        .iter()
        .map(|ct| ct.len())
        .min()
        .expect("Must have a min");
    let joined_cipher_text: Vec<u8> = cipher_texts
        .iter()
        .flat_map(|buf| buf[0..shortest_length].iter())
        .map(|&b| b)
        .collect();
    let (_, joined_plain_text) = break_repeated_xor(shortest_length, &joined_cipher_text);
    let lines = joined_plain_text.chunks(shortest_length);
    for line in lines {
        println!("S3C30 {}", b2s(&line));
    }
}

pub fn challenge19_20() {
    let plain_texts = [
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    ].iter()
        .map(|s| base642bytes(&s2b(&s)).expect("Must be base64!"));

    // Each character position is XOR'd with the same byte (because the keystream
    // is the same). So treat echo char position as a single-byte-xor problem.
    // a la challenge 6

    //        let key = get_random_bytes(16);
    let key = hex2bytes("ed31796705d916b9f8b3a5a54c1dd6d2").unwrap();
    let nonce = 0;
    let c19_cryptor = |pt: &[u8]| aes128_ctr_cryptor(&key, nonce, &pt);

    let cipher_texts = plain_texts.map(|pt| c19_cryptor(&pt)).collect::<Vec<_>>();

    let longest_cipher_text_size = cipher_texts
        .iter()
        .map(|ct| ct.len())
        .max()
        .expect("Must have a max");
    let mut guessed_key_stream = Vec::new();
    guessed_key_stream.resize(longest_cipher_text_size, 0x00);

    for i in 0..longest_cipher_text_size {
        let transpose_buf: Vec<u8> = cipher_texts
            .iter()
            .filter_map(|buf| if buf.len() > i { Some(buf[i]) } else { None })
            .collect();
        let (k, _) = break_single_byte_xor(&transpose_buf);
        guessed_key_stream[i] = k;

        for cipher_text in cipher_texts.iter() {
            let plain_text = b2s(&binary_dots(&xor_iter(
                cipher_text,
                guessed_key_stream.iter(),
            ).unwrap()));
            println!("{:x?}", plain_text);
        }
    }
}

pub fn challenge18() {
    let key = &s2b("YELLOW SUBMARINE");
    let cipher_text_base64 =
        &s2b("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let cipher_text = &base642bytes(cipher_text_base64).expect("Must be base64!");
    let plain_text = aes128_ctr_cryptor(&key, 0, &cipher_text);
    println!("S3C18 {}", b2s(&plain_text));
}

pub fn aes128_ctr_cryptor(key: &[u8], nonce: u64, in_buf: &[u8]) -> Vec<u8> {
    let key_stream = (0..).flat_map(|i: u64| {
        let mut v = Vec::new();
        //            v.clear();
        v.write_u64::<LittleEndian>(nonce).unwrap();
        v.write_u64::<LittleEndian>(i).unwrap();
        aes128_crypt_block(true, &key, &v)
    });
    in_buf.iter().zip(key_stream).map(|(b, k)| b ^ k).collect()
}

pub fn challenge17() {
    let block_size = 16;
    let key = get_random_bytes(block_size);
    let iv = get_random_bytes(block_size);
    let c17_encryptor = || c17_encryptor_helper(&key, &iv);
    let mut c17_decryptor =
        |cipher_text: &[u8]| aes128_cbc_decode_check_padding(&key, &iv, &cipher_text);

    let cipher_text = c17_encryptor();
    //        let (padding_ok, _) = c17_decryptor(&cipher_text);
    //        println!("padding_ok {}", padding_ok);

    let mut cipher_blocks = cipher_text.chunks(block_size).collect::<Vec<_>>();
    cipher_blocks.insert(0, &iv);

    let plain_text = cipher_blocks
        .iter()
        .enumerate()
        .filter(|(i, _)| i + 1 < cipher_blocks.len())
        .map(|(i, cipher_block)| {
            let pblock =
                c17_break_block(cipher_block, &cipher_blocks[i + 1], &mut c17_decryptor);
            //                println!("block is {}", &b2s(&pblock));
            pblock
        })
        .collect::<Vec<_>>()
        .concat();
    let plain_text = pkcs7_unpad(block_size, &plain_text).unwrap();
    println!("S3C17: {}", b2s(&plain_text));
    //        let cblock_a = &iv;
    //        let cblock_b = &cipher_text[0..block_size];
    //        let pblock_b = c17_break_block(&cblock_a, &cblock_b, &mut c17_decryptor);
    //        println!("block is {}", &b2s(&pblock_b));
}

fn c17_break_block(
    cblock_a: &[u8],
    cblock_b: &[u8],
    padding_oracle: &mut FnMut(&[u8]) -> (bool, Vec<u8>),
) -> Vec<u8> {
    let block_size = cblock_a.len();
    assert!(block_size > 0, "sanity");
    assert_eq!(cblock_a.len(), cblock_b.len(), "Block sizes consistent");

    let mut recovered_plain_text = Vec::new();
    // We work from the end backwards.
    // We want to guess a byte. Try all of them, xoring into the preceding block ciphertext
    // until we get good padding.
    // Then we know 'target_plain_text_byte XOR trial_byte == padding_byte'
    // So we can reverse to get target_plain_text_byte
    // Start at the end (padding 0x01) and work backwards to recover each byte (different
    // padding each time)
    for attack_index in (0..block_size).rev() {
        let desired_padding_byte = block_size as u8 - attack_index as u8;
        //            println!("JB ai {} desired {:?}", attack_index, desired_padding_byte);
        // TODO: write as filter over 0..=256
        let mut found_it = false;
        for trial_byte in 0..=255 {
            let mut attack_block = cblock_a.to_vec();
            let mut xor_data: Vec<u8> = recovered_plain_text
                .clone()
                .iter()
                .map(|b| b ^ desired_padding_byte)
                .collect();
            xor_data.insert(0, trial_byte ^ desired_padding_byte);
            xor_data.iter().enumerate().for_each(|(i, b)| {
                //                    println!("JB - xor at {} with {:x?}", attack_index, b);
                attack_block[attack_index + i] = attack_block[attack_index + i] ^ b
            });
            let mut attack_cipher_text = attack_block.clone();
            attack_cipher_text.extend_from_slice(cblock_b);
            let (mut padding_ok, _) = padding_oracle(&attack_cipher_text);
            //                println!("JB byte {} ok {}", trial_byte, padding_ok);

            if padding_ok && attack_index > 0 {
                // Also ensure byte before trial byte doesn't come out as 0x02, 0x03 etc (if there
                // is one)
                attack_block[attack_index - 1] = attack_block[attack_index - 1] ^ 0xf0;
                let mut attack_cipher_text = attack_block.clone();
                attack_cipher_text.extend_from_slice(cblock_b);
                let (second_padding_ok, _) = padding_oracle(&attack_cipher_text);
                padding_ok = second_padding_ok;
                //println!("JB - 2nd check on {:x}: {}", trial_byte, padding_ok);
            }
            if padding_ok {
                recovered_plain_text.insert(0, trial_byte);
                /*
                println!(
                    "JB - found {:x?} {}",
                    recovered_plain_text[0], recovered_plain_text[0] as char
                );
                */
                found_it = true;
                break;
            }
        }
        if !found_it {
            panic!("didn't find it");
        }
        /*
        println!(
            "Recovered: [{}] {:x?}",
            b2s(&recovered_plain_text),
            recovered_plain_text
        );
        */
    }
    recovered_plain_text
}

fn aes128_cbc_decode_check_padding(
    key: &[u8],
    iv: &[u8],
    cipher_text: &[u8],
) -> (bool, Vec<u8>) {
    match try_aes128_cbc_decode(&key, &iv, &cipher_text) {
        Ok(plain_text) => (true, plain_text),
        Err(_err_str) => {
            //                println!("JB Bad padding: {}", err_str);
            (false, Vec::new())
        }
    }
}

fn c17_encryptor_helper(key: &[u8], iv: &[u8]) -> Vec<u8> {
    let plain_texts = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ].iter()
        .map(|b64_str| base642bytes(&s2b(&b64_str)).expect("Must be base64!"))
        .collect::<Vec<_>>();

    let plain_text = &plain_texts[rand::thread_rng().gen_range(0, plain_texts.len())];
    aes128_cbc_encode(&key, &iv, &plain_text)
}
