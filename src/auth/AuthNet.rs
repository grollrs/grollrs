use std;
use std::io;
use tokio::prelude::*;

use bytes::{BufMut, BytesMut};
use tokio_io::codec::{Decoder, Encoder};

use auth::Handlers::*;
use auth::Messages::*;
use core::Handler;
use net::*;

pub struct Packet {
    pub content: PacketContent,
}


/*  ASSERT
    let challenge = CAuthLogonChallenge::new("TEST".to_string());
    let ser = challenge.serialize();
    println!("A: {:?}",ser);

    let mut b = BytesMut::new();
    b.extend(&b"\x00\x08\x22\x00\x57\x6f\x57\x00\x03\x03\x05\x34\x30\x36\x38\x78\x00\x6e\x69\x57\x00\x53\x55\x6e\x65\x3c\x00\x00\x00\x7f\x00\x00\x01\x04\x54\x45\x53\x54"[..]);
    println!("B: {:?}",b);
*/
