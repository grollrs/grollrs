use auth::*;

pub struct ContextHolder {
    pub auth: AuthContext,
}

pub trait Handler<T> {
    fn handle(&self, ctx: &mut ContextHolder);
}

pub trait StateMachine {
    fn advance(&mut self);
}
