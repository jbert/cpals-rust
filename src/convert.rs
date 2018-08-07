use base64;
use itertools::Itertools;

pub fn binary_dots(buf: &[u8]) -> Vec<u8> {
    buf.iter()
        .map(|&b| if b >= 0x20 && b <= 0x7f { b } else { '.' as u8 })
        .collect()
}

/* - unused
pub fn strip_binary(buf: &[u8]) -> Vec<u8> {
    buf.iter()
        .map(|&b| b)
        .filter(|b| *b >= 0x20 && *b <= 0x7f)
        .collect()
}
*/

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
        .filter(|&b| b != '\n')
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

pub fn bytes2hex(buf: &[u8]) -> String {
    // I am not proud
    let s = format!("{:02x?}", buf);
    let s = &s[1..s.len()-1];
    let s = s.replace(", ", "");
    s.to_string()
}

pub fn base642bytes(b64str: &[u8]) -> Result<Vec<u8>, String> {
    base64::decode(b64str).map_err(|e| e.to_string())
}

#[cfg(test)]
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
