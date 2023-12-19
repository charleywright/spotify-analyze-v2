use std::{
    io,
    net::TcpStream,
    sync::{Arc, RwLock},
};

mod ap_resolver;
mod dh;
mod pcap;
mod pow;
mod proxy;
mod proxy_session;
mod shannon;

fn main() -> io::Result<()> {
    let host = "0.0.0.0:4070";
    let is_running = Arc::new(RwLock::new(true));
    {
        let is_running = is_running.clone();
        ctrlc::set_handler(move || {
            *is_running.write().unwrap() = false;
            // Trigger running check
            let _ = TcpStream::connect(host);
        })
        .expect("Failed to set Ctrl+C handler");
    }
    proxy::run_proxy(host, is_running)?;
    Ok(())
}
