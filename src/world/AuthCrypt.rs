
use net::Opcodes;

use core::{Handler,ContextHolder};
use net::ServerMessage;
use net::ClientMessage;

use std;
use bytes::{BigEndian,LittleEndian};
use bytes::{BufMut, Bytes, BytesMut};

use std::io::{Cursor, Read, Write};
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;


pub struct SAuthChallenge {
    salt: u32
}

impl ServerMessage for SAuthChallenge {
    fn deserialize(buf: &mut BytesMut) -> Box<Self>
        where
            Self: Sized + Sync{
        if buf.len()<8{
            panic!("Bullshit?");
        }
        let mut rdr = Cursor::new(buf);
        let _ = rdr.read_u32::<LittleEndian>().unwrap();
        let salt = rdr.read_u32::<LittleEndian>().unwrap();

        {Box::new(SAuthChallenge{
            salt
        })}

    }

    fn get_opcode(&self) -> u16 {
        0x00
    }
}

pub struct AuthCryptHandler<T> {
    pub t: T,
}
impl Handler<Box<ServerMessage + 'static>> for AuthCryptHandler<Box<SAuthChallenge>> {
    fn handle(&self, ctx: &mut ContextHolder) {
        println!("Handling authCrypt message")
    }
}

pub struct CAuthChallenge {
    build: u32,
    account: String,
    seed: u64,
    digest: Vec<u8>
}

impl ClientMessage for CAuthChallenge {
    fn serialize(&self) -> BytesMut {
        let body_size = 8 + self.account.len()+ 1 + 4 + 4 + 20 + 20 + 4;
        let mut res = BytesMut::with_capacity(body_size).writer();
        res.write_u32::<LittleEndian>(self.build);
        res.write_u32::<LittleEndian>(0x00);
        res.write_all(& self.account);
        res.write_u32::<LittleEndian>(0x00);
        res.write_u32::<LittleEndian>(self.seed);
        res.write_u32::<LittleEndian>(0x00);
        res.write_u32::<LittleEndian>(0x00);
        res.write_u32::<LittleEndian>(0x00);
        res.write_u32::<LittleEndian>(0x00);
        res.write_u32::<LittleEndian>(0x00);
        res.write_all(&self.digest);
        res.write_u32::<LittleEndian>(0x00);

        res.into_inner()

    }
}

/*
impl core::Handler<std::boxed::Box<net::ServerMessage + 'static>>  for net::OpcodeMatcher::UnknownHandler<net::OpcodeMatcher::UnknownMessage>{
    fn handle(&self, ctx: &mut ContextHolder) {
        println!("Handling unknown message")
    }
}
*/