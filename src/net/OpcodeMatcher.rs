
use bytes::BytesMut;

use core::*;
use net::*;
use net::Opcodes::Opcodes as OC;

use core;
use net;
use std;
use std::mem::transmute;

use world::AuthCrypt::{SAuthChallenge, AuthCryptHandler};


pub fn match_opcode(header: Box<WorldHeader>,mut data:&mut BytesMut)->(Box<ServerMessage>, Box<Handler<Box<ServerMessage + 'static>> + Send>){

    let oc: OC = unsafe { transmute(header.opcode as u16) };

    match oc {
        OC::SMSG_AUTH_CHALLENGE => (SAuthChallenge::deserialize(data), Box::new(AuthCryptHandler{t: SAuthChallenge::deserialize(data)})),
        _ =>     (Box::new(UnknownMessage{}),Box::new(UnknownHandler{t:UnknownMessage{}}))

    }
}


pub struct UnknownMessage;

impl ServerMessage for UnknownMessage {
    fn deserialize(buf: &mut BytesMut) -> Box<Self>
        where
            Self: Sized + Sync,
    {Box::new(UnknownMessage)}

    fn get_opcode(&self) -> u16 {
        0x00
    }
}

pub struct UnknownHandler<T> {
    pub t: T,
}
impl Handler<Box<ServerMessage + 'static>> for UnknownHandler<Box<UnknownMessage>> {
    fn handle(&self, ctx: &mut ContextHolder) {
        println!("Handling unknown message")
    }
}

impl core::Handler<std::boxed::Box<net::ServerMessage + 'static>>  for net::OpcodeMatcher::UnknownHandler<net::OpcodeMatcher::UnknownMessage>{
    fn handle(&self, ctx: &mut ContextHolder) {
        println!("Handling unknown message")
    }
}



