use std::net::{SocketAddr, ToSocketAddrs};

use log::error;
const HOST: &str = "ap.spotify.com:4070";

pub struct ApResolver {
    addresses: std::vec::IntoIter<SocketAddr>,
    current_addr: Option<SocketAddr>,
}

impl ApResolver {
    pub fn new() -> Self {
        Self { addresses: vec![].into_iter(), current_addr: None }
    }

    pub fn get_resolved_ap(&mut self) -> Option<SocketAddr> {
        if self.current_addr.is_some() {
            return self.current_addr;
        }
        match HOST.to_socket_addrs() {
            Ok(new_addresses) => self.addresses = new_addresses,
            Err(e) => {
                error!("Failed to resolve {HOST}: {e}");
            },
        }
        self.current_addr = self.addresses.next();
        self.current_addr
    }

    pub fn mark_addr_as_invalid(&mut self, addr: SocketAddr) {
        if self.current_addr == Some(addr) {
            self.current_addr = self.addresses.next();
        }
    }
}
