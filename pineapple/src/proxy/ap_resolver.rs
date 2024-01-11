use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Mutex,
};

use lazy_static::lazy_static;

const HOST: &str = "ap.spotify.com:4070";

// TODO: Is Mutex really required?
lazy_static! {
    static ref ADDRESSES: Mutex<std::vec::IntoIter<SocketAddr>> = Mutex::new(vec![].into_iter());
    static ref CURRENT_ADDR: Mutex<Option<SocketAddr>> = Mutex::new(None);
}

pub fn get_resolved_ap() -> Option<SocketAddr> {
    let mut current_addr = CURRENT_ADDR.lock().unwrap();
    if current_addr.is_some() {
        return *current_addr;
    }
    let mut addresses = ADDRESSES.lock().unwrap();
    match HOST.to_socket_addrs() {
        Ok(new_addresses) => *addresses = new_addresses,
        Err(e) => {
            println!("Failed to resolve {HOST}: {e}");
        },
    }
    *current_addr = addresses.next();
    *current_addr
}

pub fn mark_addr_as_invalid(addr: SocketAddr) {
    let mut current_addr = CURRENT_ADDR.lock().unwrap();
    if *current_addr == Some(addr) {
        *current_addr = ADDRESSES.lock().unwrap().next();
    }
}
