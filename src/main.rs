extern crate byteorder;
extern crate bytes;
extern crate futures;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_io;

extern crate num;
extern crate sha1;
extern crate itertools;
extern crate crypto;

pub mod auth;
pub mod core;
pub mod net;
pub mod world;

use std::{thread, time};
use futures::StreamExt;
use bytes::{BufMut, BytesMut};
use auth::Handlers::*;
use auth::Messages::*;
use core::Handler;
use core::ContextHolder;
use std::sync::{Arc,RwLock,Mutex};

use std::net::TcpStream;
use std::io::Write;
use std::io::Read;

use std::time::Duration;

use auth::*;
use auth::AuthNet::*;
use net::*;
use world::*;

fn main() {

    println!("Startup");
    //let addr = "127.0.0.1:3724".parse().unwrap();

    //let mut core = Core::new().unwrap();

    let (auth_logic_tx, auth_logic_rx) = std::sync::mpsc::channel();
    let (auth_net_tx, auth_net_rx) = std::sync::mpsc::channel();
    
    let (world_logic_tx, world_logic_rx) = std::sync::mpsc::channel();
    let (world_net_tx, world_net_rx) = std::sync::mpsc::channel();

    //let (net_tx,net_rx) = futures::channel::mpsc::channel(1);


    let auth_context = AuthContext::new(auth_net_tx.clone());
    let context_holder = ContextHolder{
        auth: auth_context,
    };

    let shareable_context_holder = Arc::new(Mutex::new(context_holder));


    let mut am = AuthMachine::new(auth_logic_rx, auth_net_tx,shareable_context_holder.clone());
    thread::spawn(move || am.run());


    let mut wm = WorldMachine::new(world_logic_rx, world_net_tx,shareable_context_holder.clone());
    thread::spawn(move || wm.run());
    

    let auth_con = TcpStream::connect("127.0.0.1:3724");
    if auth_con.is_err() {
        panic!("[A] Couldn't connect to auth server.");
    }
    let mut auth_stream = auth_con.unwrap();
    let mut auth_stream_clone = auth_stream.try_clone().expect("clone failed...");

    if let Ok(world_con) = TcpStream::connect("127.0.0.1:8085"){

        let mut world_con_clone = world_con.try_clone().expect("clone failed...");

        let mut ws = WorldSocket::WorldSocket::new();

        let rcv_crypt = ws.crypt.clone();
        let snd_crypt = ws.crypt.clone();

        thread::spawn(move || {
            WorldSocket::start_rcv(world_con,world_logic_tx, rcv_crypt);
        });

        thread::spawn( move|| {
            WorldSocket::start_snd(world_con_clone,world_net_rx, snd_crypt);
        });


    }

    //----------- auth  ----------------------


    thread::spawn(move || {
        loop {
            //println!("polling");
            let res = auth_net_rx.recv();
            match res {
                Ok(msg) => {
                    match msg.content {
                        PacketContent::CM(c) => {
                            println!("[A] sending some");
                            auth_stream.write(&c.serialize().to_vec())
                        }
                        PacketContent::SM(s, _) => panic!("[A] Wrong type to send"),
                    };
                },
                Err(e) => {
                    //println!("busy looping");
                }
            }
        }
    });

    thread::spawn(move || {
        loop {
            let mut buf = vec![0; 1028];
            let res = auth_stream_clone.read(&mut buf);
            println!("[A] done readig");

            match res {
                Ok(some) => {
                    println!("[A] read some");
                    //println!("buf: {:?} ", to_hex_string(buf.to_vec()));

                    let opcode = buf[0];

                    let mut bytes = BytesMut::from(buf);

                    if let Some(res) = decode_auth_packet(opcode as u16, &mut bytes){
                        auth_logic_tx.send(res);
                    }
                },
                Err(e) => {
                    println!("[A] read err");
                }
            }
        }
    });


    //TODO pls don't....
    loop {
        let ten_millis = time::Duration::from_millis(10);
        thread::sleep(ten_millis);
    }
}


fn decode_auth_packet(opcode: u16, mut bytes: &mut BytesMut) -> Option<Packet>{

    match opcode {
        S_AUTH_LOGON_CHALLENGE_OPCODE => {
            let payload = SAuthLogonChallenge::deserialize(&mut bytes);
            let payloadHandler = Box::new(AuthHandler { t: payload.clone() });
            Some(Packet {
                content: PacketContent::SM(payload, payloadHandler),
            })
        },
        S_AUTH_LOGON_PROOF_OPCODE => {
            let payload = SAuthLogonProof::deserialize(&mut bytes);
            let payloadHandler = Box::new(AuthHandler { t: payload.clone() });
            Some(Packet {
                content: PacketContent::SM(payload, payloadHandler),
            })
        },
        S_REALM_LIST_OPCODE => {
            let payload = SRealmList::deserialize(&mut bytes);
            let payloadHandler = Box::new(AuthHandler { t: payload.clone() });
            Some(Packet {
                content: PacketContent::SM(payload, payloadHandler),
            })
        },
        _ => {
            println!("Unknown opcode: {}",opcode);
            None
        }
    }
}



pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join(" ")
}


#[cfg(test)]
mod tests {
    use auth::Crypto::SRP;
    use num::bigint::{BigInt, Sign, ToBigInt};
    use auth::Crypto::WorldCrypt;


    #[test]
    fn always_true() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_SRP() {
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
        //println!("3: {}",to_hex_string(data));
        assert_eq!(2 + 2, 4);

    }
}