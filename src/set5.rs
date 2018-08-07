//use rand::Rng;
use sha1::*;
use util::*;
use set2::*;
use convert::*;
use byteorder::{BigEndian, WriteBytesExt};
use num::bigint::{BigUint, RandBigInt, ToBigUint};
use rand::Rng;

#[derive(Default)]
struct DH {
    p: BigUint,
    g: BigUint,

    my_pubkey: BigUint,
    my_privkey: BigUint,

    their_pubkey: BigUint,

    received_msg: Vec<u8>,
}

impl DH {
    pub fn new() -> DH {
        DH::default()
    }

    pub fn init(&mut self, p: &BigUint, g: &BigUint) {
        let mut rng = rand::thread_rng();
        self.p = p.clone();
        self.g = g.clone();
        self.my_privkey = rng.gen_biguint(p.bits());
        self.my_pubkey = g.modpow(&self.my_privkey, &p);
    }

    pub fn swap_pub_key(&mut self, their_pubkey: &BigUint) -> &BigUint {
        self.their_pubkey = their_pubkey.clone();
        &self.my_pubkey
    }

    fn derive_key(&self) -> Vec<u8> {
        let s = self.their_pubkey.modpow(&self.my_privkey, &self.p);
        let h = sha1(&s.to_bytes_be());
        h[0..16].to_vec()
    }
    
    pub fn send_msg(&mut self, them: &mut DH, msg: &[u8]) {
        them.init(&self.p, &self.g);
        self.their_pubkey = them.swap_pub_key(&self.my_pubkey).clone();
        let key = self.derive_key();
        let iv = get_random_bytes(16);
        let cipher_text = aes128_cbc_encode(&key, &iv, &msg);
        them.accept_msg(&iv, &cipher_text);
    }

    fn accept_msg(&mut self, iv: &[u8], cipher_text: &[u8]) {
        println!("S5C34 - bob sees [{}]", bytes2hex(&cipher_text));
        let key = self.derive_key();
        self.received_msg = aes128_cbc_decode(&key, iv, cipher_text)
    }

    pub fn received_msg(&self) -> Vec<u8> {
        self.received_msg.clone()
    }

    const P_NIST_HEX_STR: &'static str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff";
}

pub fn challenge34() {
    let p = BigUint::from_bytes_be(&hex2bytes(DH::P_NIST_HEX_STR).expect("Decode hex failed"));
    let g = 2.to_biguint().unwrap();
    let mut alice = DH::new();
    let mut bob = DH::new();
    alice.init(&p, &g);
    let msg = s2b("hello, there");
    alice.send_msg(&mut bob, &msg);
    println!("S5C34 - alice send : [{}]", b2s(&msg));
    assert_eq!(&bob.received_msg(), &msg, "Bob receives the message!");
    println!("S5C34 - bob receive: [{}]", b2s(&bob.received_msg()));
}

pub fn challenge33() {
//    c33_smallnum_diffie_helman();
    c33_bignum_diffie_helman();
}

pub fn c33_bignum_diffie_helman() {
    let mut rng = rand::thread_rng();
    let p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff";
    let p = BigUint::from_bytes_be(&hex2bytes(&p_hex).expect("Decode hex failed"));
    let g = 2.to_biguint().unwrap();

    let a = rng.gen_biguint(p.bits());
    let a_pub = g.modpow(&a, &p);

    let b = rng.gen_biguint(p.bits());
    let b_pub = g.modpow(&b, &p);

    let a_sess = b_pub.modpow(&a, &p);
    let b_sess = a_pub.modpow(&b, &p);
    assert_eq!(a_sess, b_sess, "Get same session key from both sides");
    println!("S5C33 -  bignum DH worked - made a session key");

    let session_key = sha1(&a_sess.to_bytes_be());
    println!("S5C33 - session key: {}", bytes2hex(&session_key));
}

pub fn c33_smallnum_diffie_helman() {
    let p = 37;
    let g : u64 = 5;

    let a = rand::thread_rng().gen_range(0, p);
    let a_pub = g.pow(a as u32) % p;    // Can overflow

    let b = rand::thread_rng().gen_range(0, p);
    let b_pub = g.pow(b as u32) % p;    // Can overflow

    let a_sess = b_pub.pow(a as u32) % p;
    let b_sess = a_pub.pow(b as u32) % p;
    assert_eq!(a_sess, b_sess, "Get same session key from both sides");
    println!("S5C33 - u64 DH worked - made a session key");

    let session_key = sha1(&u64_to_bytes(a_sess));
    println!("S5C33 - session key: {}", bytes2hex(&session_key));
}

fn u64_to_bytes(a: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.write_u64::<BigEndian>(a).expect("Failed to write bytes");
    buf
}
