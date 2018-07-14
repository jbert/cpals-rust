use convert::*;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;

use std::time::{SystemTime, UNIX_EPOCH};

pub fn ascii_filter(in_buf: &[u8]) -> Vec<u8> {
    in_buf.iter().filter(|c| c.is_ascii()).map(|c| *c).collect()
}

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
