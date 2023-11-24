use std::{
    io,
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex, RwLock},
    thread,
};

mod dh;
mod pcap;
mod pow;
mod proxy_session;
mod shannon;
use pcap::PcapWriter;
use proxy_session::ProxySession;

fn main() -> io::Result<()> {
    let host = "192.168.1.120:4070";
    let listener = TcpListener::bind(host).unwrap_or_else(|_| panic!("Failed to bind to {}", host));
    println!("Listening on {}", host);

    let is_running = Arc::new(RwLock::new(true));
    {
        let is_running = is_running.clone();
        ctrlc::set_handler(move || {
            *is_running.write().unwrap() = false;
            let _ = TcpStream::connect(host); // Trigger running check
        })
        .expect("Failed to set Ctrl+C handler");
    }

    let pcap_writer = Arc::new(Mutex::new(PcapWriter::new()));
    for downstream in listener.incoming().flatten() {
        if !*is_running.read().unwrap() {
            break;
        }
        let is_running = is_running.clone();
        let pcap_writer = pcap_writer.clone();
        thread::spawn(move || {
            let upstream = TcpStream::connect("ap.spotify.com:4070").expect("Failed to connect to Spotify AP");
            let mut session = ProxySession::new(pcap_writer, downstream, upstream);
            if let Err(error) = session.start() {
                println!("[E] Failed to start proxy session: {}", error);
                return;
            }
            session.run(is_running);
        });
    }

    println!("\rServer shutdown");

    Ok(())
}
