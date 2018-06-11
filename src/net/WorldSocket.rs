
use bytes::{BufMut, BytesMut};
use auth::Handlers::*;
use auth::Messages::*;
use core::Handler;

use std::net::TcpStream;
use std::io::Write;
use std::io::Read;

use std::time::Duration;

use auth::*;
use auth::AuthNet::*;
use net::*;
use world::*;
use auth::Crypto::*;
use std::{thread, time};
use std::sync::mpsc::{Sender,Receiver};
use std::sync::{Arc,RwLock};


pub struct WorldSocket{
    pub crypt: Arc<RwLock<Option<WorldCrypt>>>,
}

impl WorldSocket {
    pub fn new()->WorldSocket{
        WorldSocket{
            crypt:Arc::new(RwLock::new(None))
        }
    }
    pub fn init_crypt(&mut self, crypt: WorldCrypt) {
        if let Ok(mut guard)= self.crypt.write(){
            *guard = Some(crypt);
        }
    }
}

fn decode_world_packet(len: u16, opcode: u16, mut bytes: &mut BytesMut) -> Option<WorldPacketWrapper>{
    let header = Box::new(WorldHeader::new(len,opcode,false));
    let server_packet = ServerWorldPacket::deserialize(header,bytes);
    Some(WorldPacketWrapper{content: WorldPacketContent::SM(server_packet)})
}

pub fn start_rcv(mut world_con: TcpStream, mut world_logic_tx: Sender<WorldPacketWrapper>,crypt: Arc<RwLock<Option<WorldCrypt>>>) {
    let header_size = 4;
    loop {
        let mut buf = vec![0; header_size];
        let res = world_con.read_exact(&mut buf);
        println!("[W] done reading header: {}", to_hex_string(buf.clone()));

        match res {
            Ok(some) => {

                //decrypt if needed
                let len = (buf[0] as i32) * 16 * 16 + (buf[1] as i32);
                let oc = (buf[3] as i32) * 16 * 16 + (buf[2] as i32);

                println!("[W] Pkt Len: {}", len);
                println!("[W] Pkt OC:  {}", oc);

                let cur_pkt_size = (len - 2) as usize;
                let mut buf = vec![0; cur_pkt_size];
                world_con.read_exact(&mut buf);
                println!("[W] body: {:?} ", to_hex_string(buf.to_vec()));

                let mut body = BytesMut::from(buf);
                if let Some(res) = decode_world_packet(len as u16, oc as u16, &mut body) {
                    world_logic_tx.send(res);
                }
            },
            Err(e) => {
                println!("[W] read err");
            }
        }
    }
}

pub fn start_snd(mut world_con: TcpStream, mut world_net_rx: Receiver<WorldPacketWrapper>, crypt: Arc<RwLock<Option<WorldCrypt>>>) {
    loop {
        if let Ok(msg) = world_net_rx.recv(){
            match msg.content {
                WorldPacketContent::CM(c) => {
                    println!("[W] sending");
                    world_con.write(&c.serialize().to_vec())
                }
                WorldPacketContent::SM(s) => panic!("[W] Wrong type to send"),
            };
        }
        println!("[W] would send NOT YET IMPL");
    }
}












