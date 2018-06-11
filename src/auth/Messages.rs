use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use bytes::LittleEndian;
use bytes::BigEndian;
use bytes::{BufMut, Bytes, BytesMut};
use std::io::{Cursor, Read, Write};

use net::*;
use auth::AuthNet::*;
use auth::Crypto::ClientProof;
use auth::Crypto::to_hex_string;


pub const C_AUTH_LOGON_CHALLENGE_OPCODE: u16 = 0x00;
pub const S_AUTH_LOGON_CHALLENGE_OPCODE: u16 = 0x00;
pub const C_AUTH_LOGON_PROOF_OPCODE: u16 = 0x01;
pub const S_AUTH_LOGON_PROOF_OPCODE: u16 = 0x01;
pub const C_REALM_LIST_OPCODE: u16 = 0x10;
pub const S_REALM_LIST_OPCODE: u16 = 0x10;


#[derive(Clone)]
pub struct SAuthLogonChallenge {
    pub command: u8,
    pub error: u16,
    pub b: Vec<u8>,
    pub gl: u8,
    pub g: Vec<u8>,
    pub nl: u8,
    pub n: Vec<u8>,
    pub s: Vec<u8>,
}

impl ServerMessage for SAuthLogonChallenge {
    fn deserialize(buf: &mut BytesMut) -> Box<Self>
    where
        Self: Sized + Sync,
    {
        let mut rdr = Cursor::new(buf);
        let command = rdr.read_u8().unwrap();
        let error = rdr.read_u16::<LittleEndian>().unwrap();

        let mut b = vec![0; 32];
        rdr.read_exact(&mut b);
        b.reverse();

        let gl = rdr.read_u8().unwrap();
        let mut g = vec![0; gl as usize];
        rdr.read_exact(&mut g);

        let nl = rdr.read_u8().unwrap();
        let mut n = vec![0; nl as usize];
        rdr.read_exact(&mut n);
        n.reverse();

        let mut s = vec![0; 32];
        rdr.read_exact(&mut s);
        //s.reverse();

        let s2 = s.clone();
        let b2 = b.clone();
        let n2 = n.clone();
        println!("s : {}", to_hex_string(s2));
        println!("b : {}", to_hex_string(b2));
        println!("n : {}", to_hex_string(n2));

        Box::new(SAuthLogonChallenge {
            command,
            error,
            b,
            gl,
            g,
            nl,
            n,
            s,
        })
    }

    fn get_opcode(&self) -> u16 {
        S_AUTH_LOGON_CHALLENGE_OPCODE
    }
}


#[derive(Clone)]
pub struct SAuthLogonProof {
    command: u8,
    error: u8
}
impl ServerMessage for SAuthLogonProof {
    fn deserialize(_: &mut BytesMut) -> Box<Self> where
        Self: Sized + Sync {
        Box::new(SAuthLogonProof{
            command: 0,
            error: 0,
        })
    }

    fn get_opcode(&self) -> u16 {
        S_AUTH_LOGON_PROOF_OPCODE
    }
}

#[derive(Clone)]
pub struct SRealmList {
    command: u8,
    error: u8
}
impl ServerMessage for SRealmList {
    fn deserialize(_: &mut BytesMut) -> Box<Self> where
        Self: Sized + Sync {
        Box::new(SRealmList{
            command: 0,
            error: 0,
        })
    }

    fn get_opcode(&self) -> u16 {
        S_REALM_LIST_OPCODE
    }
}

//--------------Client messages --------------------------------------------------------------------

#[derive(Debug)]
pub struct CAuthLogonChallenge {
    command: u8,
    error: u8,
    size: u16,
    game_name: Bytes,
    version: Bytes,
    plattform: Bytes,
    os: Bytes,
    country: Bytes,
    timezone: Bytes,
    ipaddr: Bytes,
    SRPIL: Bytes,
    SRPI: Bytes,
}

impl CAuthLogonChallenge {
    pub fn new(player_name: String) -> CAuthLogonChallenge {
        CAuthLogonChallenge {
            command: 0x00,
            error: 0x08,
            size: 0,
            game_name: Bytes::from(&b"\x57\x6f\x57\x00"[..]),
            version: Bytes::from(&b"\x03\x03\x05\x34\x30"[..]),
            plattform: Bytes::from(&b"\x36\x38\x78\x00"[..]),
            os: Bytes::from(&b"\x6e\x69\x57\x00"[..]),
            country: Bytes::from(&b"\x53\x55\x6e\x65"[..]),
            timezone: Bytes::from(&b"\x3c\x00\x00\x00"[..]),
            ipaddr: Bytes::from(&b"\x7f\x00\x00\x01"[..]),
            SRPIL: Bytes::from(&vec![player_name.len() as u8][..]),
            SRPI: Bytes::from(player_name),
        }
    }

    fn body_len(&self) -> usize {
        let mut len = 0;
        len += self.game_name.len();
        len += self.version.len();
        len += self.plattform.len();
        len += self.os.len();
        len += self.country.len();
        len += self.timezone.len();
        len += self.ipaddr.len();
        len += self.SRPIL.len();
        len += self.SRPI.len();
        len
    }
}

impl ClientMessage for CAuthLogonChallenge {
    fn serialize(&self) -> BytesMut {
        let mut b = BytesMut::with_capacity(49);

        b.put(self.game_name.clone());
        b.put(self.version.clone());
        b.put(self.plattform.clone());
        b.put(self.os.clone());
        b.put(self.country.clone());
        b.put(self.timezone.clone());
        b.put(self.ipaddr.clone());
        b.put(self.SRPIL.clone());
        b.put(self.SRPI.clone());

        let mut l = b.len() as u16;
        let mut totalSize = (l + 4) as usize;

        let mut res = BytesMut::with_capacity(totalSize).writer();
        res.write_u8(self.command);
        res.write_u8(self.error);
        res.write_u16::<LittleEndian>(l);
        res.write_all(&b);

        res.into_inner()
    }
}


pub struct CAuthLogonProof {
    command: u8,
    a: Vec<u8>,
    m1: Vec<u8>,
    crc: Vec<u8>,
    blob: u16
}

impl CAuthLogonProof {
    pub fn new(proof: ClientProof) -> CAuthLogonProof {
        CAuthLogonProof {
            command: 0x01,
            a: proof.A,
            m1: proof.M1,
            crc: proof.crc,
            blob: 0x00,
        }
    }

    fn body_len(&self) -> usize {
        0
    }
}

impl ClientMessage for CAuthLogonProof {
    fn serialize(&self) -> BytesMut {
        let mut b = BytesMut::with_capacity(200);

        b.put(self.a.clone());
        b.put(self.m1.clone());
        b.put(self.crc.clone());

        let mut l = b.len() as u16;
        let mut totalSize = (l + 3) as usize;

        let mut res = BytesMut::with_capacity(totalSize).writer();
        res.write_u8(self.command);
        res.write_all(&b);
        //res.write_u16::<LittleEndian>(self.blob);
        res.write_u8(0x0);
        res.write_u8(0x0);
        res.into_inner()
    }
}



pub struct CRealmList {
    command: u8,
}

impl CRealmList {
    pub fn new() -> CRealmList {
        CRealmList {
            command: C_REALM_LIST_OPCODE as u8,
        }
    }

    fn body_len(&self) -> usize {
        0
    }
}
impl ClientMessage for CRealmList {
    fn serialize(&self) -> BytesMut {
        let mut b = BytesMut::with_capacity(5);
        let mut res = BytesMut::with_capacity(5).writer();
        res.write_u8(self.command);
        res.write_u8(0x0);
        res.write_u8(0x0);
        res.write_u8(0x0);
        res.write_u8(0x0);
        res.into_inner()
    }
}