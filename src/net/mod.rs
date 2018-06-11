
pub mod Opcodes;
pub mod WorldSocket;
pub mod OpcodeMatcher;

use bytes::{BufMut, BytesMut};
use core::Handler;


pub trait ClientMessage: Sync + Send {
    fn serialize(&self) -> BytesMut;
}

pub trait ServerMessage: Sync + Send {
    fn deserialize(&mut BytesMut) -> Box<Self>
        where
            Self: Sized + Sync;
    fn get_opcode(&self) -> u16;
}

pub enum PacketContent {
    CM(Box<ClientMessage>),
    SM(Box<ServerMessage>, Box<Handler<Box<ServerMessage>> + Send>),
}

#[derive(Clone)]
pub struct WorldHeader{
    pub opcode: u16,
    pub len: u16,
    pub encrypt: bool
}

pub struct ClientWorldPacket{
    header: WorldHeader,
    body: Box<ClientMessage>
}

pub struct ServerWorldPacket{
    header: Box<WorldHeader>,
    body: Box<ServerMessage>,
    pub handler: Box<Handler<Box<ServerMessage>> + Send>
}

pub enum WorldPacketContent {
    CM(Box<ClientWorldPacket>),
    SM(Box<ServerWorldPacket>),
}

pub struct WorldPacketWrapper{
    pub content: WorldPacketContent
}

impl WorldHeader{
    fn serialize(&self) -> BytesMut{
        BytesMut::new()
    }
    fn deserialize(data: &mut BytesMut) -> Box<Self>
        where
            Self: Sized + Sync{
        Box::new(WorldHeader::new(0,0,false))
    }
    fn new(len: u16, opcode: u16, encrypt: bool)->WorldHeader{
        WorldHeader{
            opcode,
            len,
            encrypt,
        }
    }
}

impl ServerWorldPacket{
    fn deserialize(header: Box<WorldHeader>,data: &mut BytesMut) -> Box<Self>
        where
            Self: Sized {
        //let header =  WorldHeader::deserialize(data);
        let (body,handler) = OpcodeMatcher::match_opcode(header.clone(), data);
        Box::new(ServerWorldPacket{
            header,
            body,
            handler,
        })
    }
}

impl ClientWorldPacket{
    fn serialize(&self) -> BytesMut{
        BytesMut::new()
    }
}
