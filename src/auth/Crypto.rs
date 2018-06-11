#![allow(non_snake_case)]

/*
extern crate bytes;
extern crate num;
extern crate sha1;
extern crate itertools;
extern crate crypto;
*/

use num::bigint::{BigInt, Sign, ToBigInt};
use num::One;
use num::Signed;
use itertools::Itertools;

use crypto::rc4;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::buffer::{ RefReadBuffer, RefWriteBuffer, BufferResult };
use crypto::symmetriccipher::Encryptor;
use crypto::symmetriccipher::Decryptor;
use crypto::mac::Mac;
use std::io::Write;

use sha1;
use auth::Messages::SAuthLogonChallenge;


use bytes::{BufMut, BytesMut};

pub struct SRP {
    pub b: BigInt,
    pub g: BigInt,
    pub n: BigInt,
    pub s: BigInt,
    pub user: String,
    pub pass: String,
}

#[derive(Clone)]
pub struct ClientProof{
    pub M1: Vec<u8>,
    pub S: Vec<u8>,
    pub A: Vec<u8>,
    pub crc: Vec<u8>,
}

impl SRP {


    pub fn new(msg: &Box<SAuthLogonChallenge>, user: String, pass: String)->SRP{
        SRP{
            b: BigInt::from_bytes_be(Sign::Plus,&msg.b),
            g: BigInt::from_bytes_be(Sign::Plus,&msg.g),
            n: BigInt::from_bytes_be(Sign::Plus,&msg.n),
            s: BigInt::from_bytes_be(Sign::Plus,&msg.s),
            user,
            pass,
        }
    }


    pub fn compute_default_challenge(&self) -> ClientProof {
        let a = BigInt::parse_bytes(
            b"00000000000000000000000000861565895658c4b0118940b7245c2f264ccc72",
            16,
        ).unwrap();
        let k = BigInt::parse_bytes(b"03", 16).unwrap();
        self.compute_challenge(a,k)
    }

    pub fn compute_challenge(&self, a: BigInt, k: BigInt) -> ClientProof{
        let mut m = sha1::Sha1::new();
        m.update(self.user.as_bytes());
        m.update(":".to_string().as_bytes());
        m.update(self.pass.as_bytes());

        let mut n = sha1::Sha1::new();
        n.update(&self.s.to_bytes_be().1);
        n.update(&m.digest().bytes());
        let mut nd = n.digest().bytes();
        nd.reverse();

        let x = BigInt::from_bytes_be(Sign::Plus, &nd);

        let v = self.g.modpow(&x, &self.n);

        println!("v: {}", v.to_str_radix(16));

        let A = self.g.modpow(&a, &self.n);

        let mut ab = A.to_bytes_be().1;
        let mut abr = ab.clone();
        abr.reverse();

        let mut b = self.b.to_bytes_be().1;
        let mut br = b.clone();
        br.reverse();

        let mut o = sha1::Sha1::new();
        o.update(&abr);
        o.update(&br);
        let mut od = o.digest().bytes();
        od.reverse();

        //-----
        println!("A: {}", A.to_str_radix(16));
        println!("b: {}", self.b.to_str_radix(16));
        println!("od: {}", od.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));
        //-----

        //calculate session key

        let odi = BigInt::from_bytes_be(Sign::Plus, &od);

        let kgx = k * v;
        let aux = a + (odi * x);
        let sub = &self.b - kgx;
        let sub = sub.abs();

        //copmite the session key
        // S = |B - kg^x| ^ (a + ux)
        let session_key = sub.modpow(&aux, &self.n);
        println!("S: {}", session_key.to_str_radix(16));

        //Store odd and even bytes in separate byte-arrays
        let s_bytes = session_key.to_bytes_be().1;
        let mut s0 = s_bytes
            .iter()
            .enumerate()
            .filter(|a| a.0 % 2 == 0)
            .map(|a| *a.1)
            .collect::<Vec<_>>();
        let mut s1 = s_bytes
            .iter()
            .enumerate()
            .filter(|a| a.0 % 2 == 1)
            .map(|a| *a.1)
            .collect::<Vec<_>>();

        //reverse and hash them
        &s0.reverse();
        &s1.reverse();

        let mut hs0 = sha1::Sha1::new();
        let mut hs1 = sha1::Sha1::new();

        hs0.update(&s0);
        hs1.update(&s1);

        let mut ds0 = hs0.digest().bytes();
        let mut ds1 = hs1.digest().bytes();

        ds0.reverse();
        ds1.reverse();

        //interleave the digests

        let mut K = ds0.iter().interleave(ds1.iter()).map(|i|*i).collect::<Vec<_>>();
        println!("K: {}", &K.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));

        //Hash prime and generator

        let mut dn =  sha1::Sha1::new();
        let mut nc = self.n.to_bytes_be().1;
        nc.reverse();
        dn.update(&nc);
        let mut prime = dn.digest().bytes();
        prime.reverse();

        let mut dg =  sha1::Sha1::new();
        let mut gc = self.g.to_bytes_be().1;
        gc.reverse();
        dg.update(&gc);
        let mut generator = dg.digest().bytes();
        generator.reverse();

        let mut ngh = generator.iter().zip(prime.iter()).map(|i|(i.0)^(i.1)).collect::<Vec<_>>();
        println!("ngh: {}", &ngh.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));

        // hash identifier (username)
        let Ih = sha1::Sha1::from(self.user.clone()).digest().bytes();


        //reverse all the things... actually only some...
        ngh.reverse();
        K.reverse();

        //calculate client proof M
        //M1 = H( (H(N) ^ H(G)) | H(I) | s | A | B | K )
        let mut m1d =  sha1::Sha1::new();
        m1d.update(&ngh);
        m1d.update(&Ih);
        m1d.update(&self.s.to_bytes_be().1);
        m1d.update(&abr);
        m1d.update(&br);
        m1d.update(&K);

        let M1 = m1d.digest().bytes();
        println!("M1: {}", &M1.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));

        ClientProof{
            M1: M1.to_vec(),
            S: session_key.to_bytes_be().1,
            A: A.to_bytes_le().1,
            crc: BigInt::parse_bytes(
                b"288900a60dae387aeb4335ca9b48a6c0d3122442",
                16,
            ).unwrap().to_bytes_be().1
        }

    }
}


pub struct WorldCrypt{
    sessionKey: Vec<u8>,
    enc: rc4::Rc4,
    dec: rc4::Rc4,

}

impl WorldCrypt{
    pub fn new(key: &Vec<u8>)->WorldCrypt{

        let sessionKey = (*key).clone().to_vec();


        let srv_enc_key_seed : Vec<u8> = vec![ 0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE ];
        let srv_dec_key_seed : Vec<u8> = vec![ 0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57 ];


        let enc_sha1 = Sha1::new();
        let mut enc_mac = Hmac::new(enc_sha1,&srv_enc_key_seed);
        enc_mac.input(&(*sessionKey));
        let mut enc_session_key=vec![0;enc_mac.output_bytes()];
        enc_mac.raw_result(&mut (*enc_session_key));

        let dec_sha1 = Sha1::new();
        let mut dec_mac = Hmac::new(dec_sha1,&srv_dec_key_seed);
        dec_mac.input(&(*sessionKey));
        let mut dec_session_key=vec![0;dec_mac.output_bytes()];
        dec_mac.raw_result(&mut (*dec_session_key));


        let enc = rc4::Rc4::new(&(*enc_session_key));
        let dec = rc4::Rc4::new(&(*dec_session_key));


        let mut wc = WorldCrypt{
            sessionKey,
            enc,
            dec
        };

        let mut padding: Vec<u8> = vec![0;1024];
        wc.encrypt(&mut padding);
        let mut padding: Vec<u8> = vec![0;1024];
        wc.decrypt(&mut padding);

        wc
    }


    pub fn encrypt(&mut self, data: &mut Vec<u8>){
        let mut buffer = vec![0; data.len()];
        {
            let mut read_buffer = RefReadBuffer::new(data);
            let mut write_buffer = RefWriteBuffer::new(&mut buffer);
            let res = self.enc.encrypt(&mut read_buffer,&mut write_buffer,false).unwrap();

        }
        data.clear();
        data.write_all(&(*buffer));
    }

    pub fn decrypt(&mut self, data: &mut Vec<u8>){
        let mut buffer = vec![0; data.len()];
        {
            let mut read_buffer = RefReadBuffer::new(data);
            let mut write_buffer = RefWriteBuffer::new(&mut buffer);
            let res = self.dec.decrypt(&mut read_buffer,&mut write_buffer,false).unwrap();

        }
        data.clear();
        data.write_all(&(*buffer));
    }
}



/*

fn main() {
    let user = "PLAYER".to_string();
    let pass = "PLAYER".to_string();

    let srp = SRP {
        b: BigInt::parse_bytes(
            b"82e0fc2575616dfa7e64d6475fe080325b090eca5be40d443e1d0660835af9ee",
            16,
        ).unwrap(),
        g: BigInt::parse_bytes(b"07", 16).unwrap(),
        n: BigInt::parse_bytes(
            b"894b645e89e1535bbdad5b8b290650530801b18ebfbf5e8fab3c82872a3e9bb7",
            16,
        ).unwrap(),
        s: BigInt::parse_bytes(
            b"15257775d01079c9814a905fbd832028ce986d855f1f18ca97c8746f65eb86b1",
            16,
        ).unwrap(),
        user,
        pass,
    };

    let a = BigInt::parse_bytes(
        b"00000000000000000000000000861565895658c4b0118940b7245c2f264ccc72",
        16,
    ).unwrap();
    let k = BigInt::parse_bytes(b"03", 16).unwrap();

    let proof = srp.compute_challenge(a, k);

    let mut key = BigInt::parse_bytes(b"7AB39E230475341FA69A8CE649A73E64BB6FA5B3AED0DC0F595447AF2E772BE6460CCF77F3C830C0",16,).unwrap().to_bytes_be().1;
    key.reverse();
    let mut crypt = WorldCrypt::new(&key);

    let mut data = vec![0xe2, 0x7c, 0x26, 0xd5];  // Len: 11-15 OC: 0x01EE
    println!("1: {:?}",data);
    //crypt.encrypt(&mut data);
    //println!("2: {:?}",data);
    crypt.decrypt(&mut data);
    println!("3: {}",to_hex_string(data));



}

*/


pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join(" ")
}
