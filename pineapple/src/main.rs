use std::{io, net::TcpStream};

mod ap_resolver;
mod dh;
mod pcap;
mod pow;
mod proxy;
mod proxy_session;
mod shannon;

fn main() -> io::Result<()> {
    let host = "0.0.0.0:4070";
    {
        ctrlc::set_handler(move || {
            let _ = TcpStream::connect(host); // Trigger running check
        })
        .expect("Failed to set Ctrl+C handler");
    }
    proxy::run_proxy(host)?;
    Ok(())
}
