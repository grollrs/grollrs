pub mod Handlers;
pub mod Messages;
pub mod Crypto;
pub mod AuthNet;

use self::Messages::*;

use std;
use std::{thread, time};

use core::*;
use auth::AuthNet::*;
use net::*;
use std::sync::{Arc,RwLock,Mutex};



pub struct AuthContext {
    machine: AuthStateMachine,
    snd: std::sync::mpsc::Sender<Packet>,
    proof: Option<Crypto::ClientProof>
}

impl AuthContext {
    pub fn new(snd: std::sync::mpsc::Sender<Packet>) -> AuthContext {
        AuthContext {
            machine: AuthStateMachine {
                state: AuthStateMachineStates::New,
            },
            snd,
            proof: None
        }
    }
}

enum AuthStateMachineStates {
    New,
    Challenge,
    Complete,
    Failed,
}
use std::fmt;

impl std::fmt::Display for AuthStateMachineStates {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthStateMachineStates::New => write!(f, "New"),
            AuthStateMachineStates::Challenge => write!(f, "Requested"),
            _ => write!(f, "Sonstwas"),
        }
    }
}

struct AuthStateMachine {
    state: AuthStateMachineStates,
}

impl StateMachine for AuthStateMachine {
    fn advance(&mut self) {
        match self.state {
            AuthStateMachineStates::New => self.state = AuthStateMachineStates::Challenge,
            _ => self.state = AuthStateMachineStates::Failed,
        }
    }
}

pub struct AuthMachine {
    l_in: std::sync::mpsc::Receiver<Packet>,
    l_out: std::sync::mpsc::Sender<Packet>,
    ctx: Arc<Mutex<ContextHolder>>
}

impl AuthMachine {
    pub fn new(
        l_in: std::sync::mpsc::Receiver<Packet>,
        l_out: std::sync::mpsc::Sender<Packet>,
        ctx: Arc<Mutex<ContextHolder>>
    ) -> (AuthMachine) {
        let am = AuthMachine { l_in, l_out ,ctx};
        am
    }

    pub fn run(&mut self) {
        self.l_out.send(Packet {
            content: PacketContent::CM(Box::new(CAuthLogonChallenge::new("PLAYER".to_string()))),
        });

        self.l_in.iter().for_each(|i|
            {
                match i.content {
                    PacketContent::SM(msg, handler) => {

                        println!("got server message");

                        if let Ok(mut guard)= self.ctx.lock(){
                            handler.handle(&mut guard);
                        }

                        println!("after handling");
                    }
                    _ => unreachable!("at least i hope so"),
                };
            }
        );
    }
}























