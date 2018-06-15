#![feature(iterator_step_by)]
#![feature(extern_prelude)]
extern crate base64;
extern crate byteorder;
extern crate itertools;
extern crate openssl;
extern crate rand;

#[macro_use]
extern crate maplit;

pub mod set4 {
    use convert::*;
    use set1::*;
    use set3::*;
    use util::*;

    use byteorder::{LittleEndian, WriteBytesExt};

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
}

pub mod set3 {
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
            println!("orig - got {:x}", r);
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

            println!("{} =====================", i);
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
}

pub mod set2 {
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
        pkcs7_unpad(block_size, &plain_blocks.collect::<Vec<_>>().concat())
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
            last_cipher_block = cipher_block.clone();
            cipher_block
        });
        cipher_blocks.collect::<Vec<_>>().concat()
    }

}

pub mod set1 {
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
}

#[cfg(test)]
mod tests {
    mod set3 {
        use convert::*;
        use rand::Rng;
        use set2::*;
        use set3::*;

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
}

pub mod util {

    use convert::*;
    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::io::Read;

    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn get_random_bytes(n: usize) -> Vec<u8> {
        //        let mut rng = rand::thread_rng();
        //        (0..n).map(|_| rng.gen()).collect()
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    pub fn epoch_seconds(t: SystemTime) -> u64 {
        let duration = t.duration_since(UNIX_EPOCH)
            .expect("Hope epoch was a long time ago");
        duration.as_secs()
    }

    pub fn pkcs7_pad(block_size: usize, buf: &[u8]) -> Vec<u8> {
        assert!(
            block_size < 256,
            "PKCS7 won't work for block size of >= 256"
        );
        // We want a full block if we already match block size
        let padding_needed = block_size - buf.len() % block_size;
        let padding_needed = padding_needed as u8;
        let mut v = buf.to_vec();
        v.extend((0..padding_needed).map(|_| padding_needed));
        v
    }

    pub fn pkcs7_unpad(block_size: usize, buf: &[u8]) -> Result<Vec<u8>, String> {
        /*
        let num_blocks = buf.len() / block_size;
        if num_blocks * block_size != buf.len() {
            return Err(format!(
                "Length [{}] not a multiple of block size [{}]",
                num_blocks, block_size
            ));
        }

        let last_chunk = &buf[(num_blocks - 1) * block_size..];
        let discard_bytes = *last_chunk.last().unwrap() as usize;
        if discard_bytes > last_chunk.len() {
            return Err(format!(
                "Invalid padding value: discard {} len {}",
                discard_bytes,
                last_chunk.len()
            ));
        }
        for pos in 0..discard_bytes {
            if last_chunk[last_chunk.len() - pos - 1] != discard_bytes as u8 {
                return Err(format!(
                    "Invalid padding byte [{:x?} != {:x?}] at pos [{}]: {:x?}",
                    last_chunk[last_chunk.len() - pos - 1],
                    discard_bytes,
                    pos,
                    last_chunk
                ));
            }
        }
        Ok(buf[0..buf.len() - discard_bytes].to_vec())
        */
        //        println!("JB unpad: {:x?}", buf);
        if buf.len() % block_size != 0 {
            return Err(format!(
                "Non-block size buffer [{}] [{}]",
                buf.len(),
                block_size
            ));
        }

        let buf = buf.clone();
        let num_padding_bytes = *buf.last().unwrap() as usize;
        if num_padding_bytes > block_size || num_padding_bytes == 0 {
            return Err(format!(
                "Invalid padding value: discard {} block_size {}: {:x?}",
                num_padding_bytes, block_size, buf
            ));
        }
        let (unpadded_buf, padding) = buf.split_at(buf.len() - num_padding_bytes);
        for b in padding {
            if *b != num_padding_bytes as u8 {
                return Err(format!(
                    "Invalid padding byte [{:x?} != {:x?}]: {:x?}",
                    b, num_padding_bytes, padding
                ));
            }
        }
        return Ok(unpadded_buf.to_vec());
    }

    pub fn slurp_base64_file(filename: &str) -> Vec<u8> {
        let mut contents = String::new();
        let mut f = File::open(filename).expect("Can't open file");
        f.read_to_string(&mut contents).expect("Can't read bytes");
        let contents = contents.replace("\n", "");
        let contents = base642bytes(&s2b(&contents)).expect("Data is not base64");
        contents
    }

    pub fn slurp_base64_file_as_lines(filename: &str) -> Vec<Vec<u8>> {
        let f = File::open(filename).expect("File  not found");
        let reader = BufReader::new(f);

        reader
            .lines()
            .map(|l| l.expect("Error reading line"))
            .map(|l| base642bytes(&s2b(&l)).expect("Must be base64"))
            .collect()
    }

    pub fn slurp_hex_file_as_lines(filename: &str) -> Vec<Vec<u8>> {
        let f = File::open(filename).expect("File  not found");
        let reader = BufReader::new(f);

        reader
            .lines()
            .map(|l| l.expect("Error reading line"))
            .map(|l| hex2bytes(&l).unwrap())
            .collect()
    }

    pub fn hamming_distance(xs: &[u8], ys: &[u8]) -> usize {
        xs.iter()
            .zip(ys.iter())
            .map(|(x, y)| (x ^ y).count_ones() as usize)
            .sum()
    }

    pub fn english_score_counting_method(buf: &[u8]) -> f64 {
        let mut score = 0;
        let tier1 = "etaoin";
        let tier2 = "shrdlu";

        for b in buf {
            let c = *b as char;
            let c = c.to_lowercase().next().unwrap(); // We are only handling ascii
            if c.is_alphabetic() {
                score += 1;
                if let Some(_) = tier1.find(c) {
                    score += 2;
                } else if let Some(_) = tier2.find(c) {
                    score += 1;
                }
            } else if c == ' ' {
                score += 3;
            }
        }
        score as f64 / buf.len() as f64
    }

    use std::collections::HashMap;
    use std::f64;

    pub fn english_score_histo_order(buf: &[u8]) -> f64 {
        let ec = english_frequencies();
        let cc = CharFreq::from_bytes(&buf);
        let distance = cc.distance(&ec);
        if distance == 0 {
            f64::MAX
        } else {
            1.0 / distance as f64
        }
    }

    pub fn english_score(fast: bool, buf: &[u8]) -> f64 {
        if fast {
            english_score_counting_method(buf)
        } else {
            english_score_histo_order(buf)
        }
    }

    #[derive(Debug)]
    pub struct CharFreq(pub HashMap<char, f64>);

    impl CharFreq {
        pub fn freq(&self, c: char) -> f64 {
            match self.0.get(&c) {
                None => 0.0,
                Some(f) => *f,
            }
        }

        pub fn from_bytes(buf: &[u8]) -> CharFreq {
            let mut cf = CharFreq(HashMap::new());
            cf.add_bytes(buf);
            cf.normalise()
        }

        fn add_bytes(&mut self, buf: &[u8]) {
            for b in buf {
                self.add_byte(*b);
            }
        }

        fn add_byte(&mut self, b: u8) {
            self.add_char(b as char);
        }

        fn add_char(&mut self, mut c: char) {
            if !((c.is_alphabetic() && c.is_ascii()) || c == ' ') {
                return;
            }
            c = c.to_lowercase().next().unwrap(); // We are only handling ascii
            let counter = self.0.entry(c).or_insert(0.0);
            *counter += 1.0;
        }

        pub fn order(&self) -> Vec<char> {
            let mut chars = self.0.keys().map(|c| *c).collect::<Vec<_>>();
            // Don't mind my NaN
            // HashMap starts in random order, so make deterministic by falling back
            // to comparing the chars if the frequecies are the same
            chars.sort_by(|a, b| {
                self.freq(*b)
                    .partial_cmp(&self.freq(*a))
                    .unwrap()
                    .then(a.cmp(b))
            });
            chars
        }

        pub fn distance(&self, other: &CharFreq) -> usize {
            let d = order_distance(&mut self.order(), &mut other.order());
            //            println!("JB - distance ({}) between [{}] and [{}]", d, self.order().iter().collect::<String>(), other.order().iter().collect::<String>());
            d
        }

        pub fn normalise(&self) -> CharFreq {
            let total: f64 = self.0.values().sum();
            CharFreq(self.0.iter().map(|(k, v)| (*k, *v / total)).collect())
        }
    }

    use std;

    pub fn order_distance<T: std::cmp::Eq>(xs: &mut Vec<T>, ys: &mut Vec<T>) -> usize {
        // Always have shortest first
        if xs.len() > ys.len() {
            return order_distance(ys, xs);
        }
        // If we run out of chars, penalise
        if xs.len() == 0 {
            //            return ys.len() * ys.len() * ys.len() * ys.len()
            return ys.len() * ys.len();
        }
        let x = xs.remove(0);
        let pos = ys.iter().position(|c| *c == x);
        let this_distance = match pos {
            Some(d) => {
                ys.swap(0, d);
                ys.remove(0);
                d
            }
            None => ys.len(),
        };
        this_distance + order_distance(xs, ys)
    }

    // Ladies and gentlemen - your friend and mine - Etaoin Shrdlu
    pub fn english_frequencies() -> CharFreq {
        CharFreq(hashmap!(
            'a' => 8.167,
            'b' => 1.492,
            'c' => 2.782,
            'd' => 4.253,
            'e' => 12.702,
            'f' => 2.228,
            'g' => 2.015,
            'h' => 6.094,
            'i' => 6.966,
            'j' => 0.153,
            'k' => 0.772,
            'l' => 4.025,
            'm' => 2.406,
            'n' => 6.749,
            'o' => 7.507,
            'p' => 1.929,
            'q' => 0.095,
            'r' => 5.987,
            's' => 6.327,
            't' => 9.056,
            'u' => 2.758,
            'v' => 0.978,
            'w' => 2.360,
            'x' => 0.150,
            'y' => 1.974,
            'z' => 0.074,
            ' ' => 25.0,
//            '\0' => 0.0,  // Other
            )).normalise()
    }

    pub fn xor(x: u8, ys: &[u8]) -> Vec<u8> {
        ys.iter().map(|y| x ^ y).collect()
    }

    pub fn xor_iter<'a, I>(xs: &[u8], yiter: I) -> Result<Vec<u8>, String>
    where
        I: IntoIterator<Item = &'a u8>,
    {
        let buf = xs.iter()
            .zip(yiter)
            .map(|xy| xy.0 ^ xy.1)
            .collect::<Vec<_>>();
        if buf.len() == xs.len() {
            Ok(buf)
        } else {
            Err(format!("Iterator too short: {} != {}", buf.len(), xs.len()))
        }
    }

    pub fn xor_buf(xs: &[u8], ys: &[u8]) -> Result<Vec<u8>, String> {
        if xs.len() != ys.len() {
            return Err(format!(
                "xor: buf size mismatch: {} != {}",
                xs.len(),
                ys.len()
            ));
        }
        Ok(xs.iter().zip(ys.iter()).map(|xy| xy.0 ^ xy.1).collect())
    }

    pub fn xor_decode(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
        let keystream = key.iter().cycle();
        plain_text
            .iter()
            .zip(keystream)
            .map(|(c, k)| c ^ k)
            .collect()
    }
}

pub mod convert {

    use base64;
    use itertools::Itertools;

    pub fn binary_dots(buf: &[u8]) -> Vec<u8> {
        buf.iter()
            .map(|&b| if b >= 0x20 && b <= 0x7f { b } else { '.' as u8 })
            .collect()
    }

    pub fn strip_binary(buf: &[u8]) -> Vec<u8> {
        buf.iter()
            .map(|&b| b)
            .filter(|b| *b >= 0x20 && *b <= 0x7f)
            .collect()
    }

    pub fn b2s(buf: &[u8]) -> String {
        //        match String::from_utf8(buf.to_vec()) {
        match String::from_utf8(buf.to_vec()) {
            Ok(s) => s,
            Err(err) => format!("Can't decode bytes as utf8: {:?}: {}", buf, err),
        }
    }
    pub fn s2b(s: &str) -> Vec<u8> {
        s.bytes().collect()
    }

    pub fn hex2bytes(hex_str: &str) -> Result<Vec<u8>, String> {
        // Get iterator of nibbles-or-errors
        hex_str
            .chars()
            .map(hexchar2nibble)
            .batching(|it| match it.next() {
                None => None,
                Some(x) => match it.next() {
                    None => None,
                    Some(y) => Some((x, y)),
                },
            })
            .map(hilo2byte)
            .collect()
    }

    pub fn base642bytes(b64str: &[u8]) -> Result<Vec<u8>, String> {
        base64::decode(b64str).map_err(|e| e.to_string())
    }

    pub fn bytes2base64(bytes: &[u8]) -> String {
        base64::encode(bytes)
    }

    fn hilo2byte(hilo: (Result<u8, String>, Result<u8, String>)) -> Result<u8, String> {
        match hilo.0 {
            Err(s) => Err(s),
            Ok(hi) => match hilo.1 {
                Err(s) => Err(s),
                Ok(lo) => Ok(hi << 4 | lo),
            },
        }
    }

    fn hexchar2nibble(c: char) -> Result<u8, String> {
        match c.to_digit(16) {
            None => Err(format!("Can't parse hex digit: {}", c)),
            Some(n) => Ok(n as u8),
        }
    }
}
