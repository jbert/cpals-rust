use sha1::*;
use util::*;
use set2::*;
use convert::*;
use byteorder::{BigEndian, WriteBytesExt};
use num::bigint::{BigUint, RandBigInt, ToBigUint};
use rand::Rng;

pub trait DHServer {
    fn init(&mut self, p: &BigUint, g: &BigUint);
    fn swap_pub_key(&mut self, their_pubkey: &BigUint) -> &BigUint;
    fn accept_and_reply_to_msg(&mut self, iv: &[u8], cipher_text: &[u8]) -> (Vec<u8>, Vec<u8>);
    fn received_msg(&mut self) -> Vec<u8>;
}

// Don't know why I can't derive default here. I get:
// error[E0277]: the trait bound `&mut set5::DH: std::default::Default` is not satisfied
//   --> src/set5.rs:18:5
//    |
// 18 |     bob: &'a mut DH,
//    |     ^^^^^^^^^^^^^^^ the trait `std::default::Default` is not implemented for `&mut set5::DH`
//    |
//    = help: the following implementations were found:
//              <set5::DH as std::default::Default>
//    = note: required by `std::default::Default::default`
// 
struct DHMitm<'a> {
    bob: &'a mut DH,

    p: BigUint,
    g: BigUint,
}

impl<'a> DHMitm<'a> {
    fn new(bob: &'a mut DH) -> DHMitm {
        let mitm = DHMitm{
            bob: bob,
            p: 0.to_biguint().unwrap(),
            g: 0.to_biguint().unwrap(),
        };
        mitm
    }

    fn bob_received_msg(&mut self) -> Vec<u8> {
        self.bob.received_msg()
    }

    fn decrypt_with_zero_key(&self, iv: &[u8], buf: &[u8]) -> Vec<u8> {
        let h = sha1(&0.to_biguint().unwrap().to_bytes_be());
        let zero_key = h[0..16].to_vec();
        aes128_cbc_decode(&zero_key, iv, buf)
    }

}

impl<'a> DHServer for DHMitm<'a> {
    fn init(&mut self, p: &BigUint, g: &BigUint) {
        self.p = p.clone();
        self.g = g.clone();
        self.bob.init(p, g)
    }

    fn swap_pub_key(&mut self, _their_pubkey: &BigUint) -> &BigUint {
        // Tee hee - we tell bob that Alice's pubkey is p. Mwahahaha.
        self.bob.swap_pub_key(&self.p); // We don't care what Bob's real pubkey is
        // And we tell Alice that bob's pubkey is also p. Tee hee.
        &self.p
    }
    fn accept_and_reply_to_msg(&mut self, iv: &[u8], cipher_text: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // So, we told Bob that Alice's pubkey was p
        // So bob will have calcualated session as:
        // let s = p.modpow(bob_privkey, &self.p); == p^k mod p == (p mod p)^k == 0
        // i.e. the zero key

        let plain_text = self.decrypt_with_zero_key(iv, cipher_text);
        println!("S5C34 - mitm can zero decrypt to see: [{}]", b2s(&plain_text));
        let (reply_iv, reply_cipher_text) = self.bob.accept_and_reply_to_msg(iv, cipher_text);
        let reply_plain_text = self.decrypt_with_zero_key(&reply_iv, &reply_cipher_text);
        println!("S5C34 - mitm can zero decrypt to see: [{}]", b2s(&reply_plain_text));
        (reply_iv, reply_cipher_text)
    }

    fn received_msg(&mut self) -> Vec<u8> {
        self.bob.received_msg()
    }
}

#[derive(Default)]
struct DH {
    p: BigUint,
    g: BigUint,

    my_pubkey: BigUint,
    my_privkey: BigUint,

    their_pubkey: BigUint,

    received_msg: Vec<u8>,
}

impl DHServer for DH {
    fn init(&mut self, p: &BigUint, g: &BigUint) {
        let mut rng = rand::thread_rng();
        self.p = p.clone();
        self.g = g.clone();
        self.my_privkey = rng.gen_biguint(p.bits());
        self.my_pubkey = g.modpow(&self.my_privkey, &p);
    }

    fn swap_pub_key(&mut self, their_pubkey: &BigUint) -> &BigUint {
        self.their_pubkey = their_pubkey.clone();
        &self.my_pubkey
    }

    fn accept_and_reply_to_msg(&mut self, iv: &[u8], cipher_text: &[u8]) -> (Vec<u8>, Vec<u8>) {
        println!("S5C34 - bob sees [{}]", bytes2hex(&cipher_text));
        let key = self.derive_key(); 
        self.received_msg = aes128_cbc_decode(&key, iv, cipher_text);
        let return_iv = get_random_bytes(16);
        let return_cipher_text = aes128_cbc_encode(&key, &return_iv, &self.received_msg);
        (return_iv, return_cipher_text)
    }

    fn received_msg(&mut self) -> Vec<u8> {
        self.received_msg.clone()
    }

}

impl DH {
    pub fn new() -> DH {
        DH::default()
    }

    fn derive_key(&self) -> Vec<u8> {
        let s = self.their_pubkey.modpow(&self.my_privkey, &self.p);
        let h = sha1(&s.to_bytes_be());
        h[0..16].to_vec()
    }
    
    pub fn send_msg(&mut self, them: &mut DHServer, msg: &[u8]) -> bool {
        them.init(&self.p, &self.g);
        self.their_pubkey = them.swap_pub_key(&self.my_pubkey).clone();
        let key = self.derive_key();
        let iv = get_random_bytes(16);
        let cipher_text = aes128_cbc_encode(&key, &iv, &msg);
        let (return_iv, return_cipher_text) = them.accept_and_reply_to_msg(&iv, &cipher_text);
        let return_msg = aes128_cbc_decode(&key, &return_iv, &return_cipher_text);
        msg.to_vec() == return_msg
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
    {
        let mut alice = DH::new();
        let mut bob = DH::new();
        alice.init(&p, &g);
        let msg = s2b("hello, there");
        println!("S5C34 - alice send : [{}]", b2s(&msg));
        let reply_good = alice.send_msg(&mut bob, &msg);
        assert!(reply_good, "alice received the correct reply");
        assert_eq!(&bob.received_msg(), &msg, "Bob receives the message!");
        println!("S5C34 - bob receive: [{}]", b2s(&bob.received_msg()));
        println!("S5C34 - alice got correct reply?: {}", reply_good);
    }
    {
        let mut alice = DH::new();
        let mut bob = DH::new();
        let mut mitm = DHMitm::new(&mut bob);
        alice.init(&p, &g);
        let msg = s2b("hello, there - Mr Who?");
        println!("S5C34 - alice send via mitm: [{}]", b2s(&msg));
        let reply_good = alice.send_msg(&mut mitm, &msg);
        assert!(reply_good, "alice received the correct reply");
        println!("S5C34 - mitm says bob receive: [{}]", b2s(&mitm.bob_received_msg()));
        println!("S5C34 - alice got correct reply?: {}", reply_good);
    }

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
