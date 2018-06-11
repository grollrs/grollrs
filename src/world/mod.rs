
pub mod AuthCrypt;

use std;
use core::*;
use net::*;

use std::sync::{Arc,RwLock,Mutex};


pub struct WorldMachine {

    l_in: std::sync::mpsc::Receiver<WorldPacketWrapper>,
    l_out: std::sync::mpsc::Sender<WorldPacketWrapper>,
    ctx: Arc<Mutex<ContextHolder>>

}

impl WorldMachine {
    pub fn new(
        l_in: std::sync::mpsc::Receiver<WorldPacketWrapper>,
        l_out: std::sync::mpsc::Sender<WorldPacketWrapper>,
        ctx: Arc<Mutex<ContextHolder>>

    ) -> (WorldMachine) {
        let wm = WorldMachine { l_in, l_out, ctx};
        wm
    }

    pub fn run(&mut self) {
        println!("World is running");

        self.l_in.iter().for_each(|msg|{
            println!("[W] World logic rcv");
            match msg.content{
                WorldPacketContent::SM(msg) => {
                    if let Ok(mut guard)= self.ctx.lock(){
                        msg.handler.handle(&mut guard);
                    }                }
                _ => {}
            };
        });
    }
}


