use mio::Token;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

pub const SERVER_TOKEN: Token = Token(0);

pub struct TokenManager {
    counter: AtomicU32,
}

impl TokenManager {
    pub fn new() -> Self {
        Self {
            counter: AtomicU32::new(1),
        }
    }

    pub fn next(&mut self) -> Token {
        let inner = self.counter.fetch_add(1, Ordering::Relaxed);
        Token(inner as usize)
    }
}
