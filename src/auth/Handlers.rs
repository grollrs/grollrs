use auth::Messages::*;
use core::*;
use auth::AuthNet::*;
use net::*;
use auth::Crypto::*;


pub struct AuthHandler<T> {
    pub t: T,
}

impl Handler<Box<ServerMessage + 'static>> for AuthHandler<Box<SAuthLogonChallenge>> {
    fn handle(&self, ctx: &mut ContextHolder) {
        let mut ctx = &mut ctx.auth;
        println!("handling auth logon challenge");
        let srp = SRP::new(&self.t,"PLAYER".to_string(),"PLAYER".to_string());
        let mut proof = srp.compute_default_challenge();
        ctx.proof = Some(proof.clone());
        let answer = CAuthLogonProof::new(proof);
        ctx.snd.send(Packet {
            content: PacketContent::CM(Box::new(answer)),
        });
    }
}

impl Handler<Box<ServerMessage + 'static>> for AuthHandler<Box<SAuthLogonProof>> {
    fn handle(&self, ctx: &mut ContextHolder) {
        let ctx = &ctx.auth;
        println!("handling auth logon proof - ignoring");

        ctx.snd.send(Packet {
            content: PacketContent::CM(Box::new(CRealmList::new())),
        });
    }
}

impl Handler<Box<ServerMessage + 'static>> for AuthHandler<Box<SRealmList>> {
    fn handle(&self, ctx: &mut ContextHolder) {
        println!("handling realm list");
    }
}

