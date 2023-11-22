use std::{
    io,
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

mod dh;
mod pcap;
mod proxy_session;
mod shannon;
use pcap::PcapWriter;
use proxy_session::ProxySession;

fn main() -> io::Result<()> {
    let host = "192.168.1.120:4070";
    let listener = TcpListener::bind(host).unwrap_or_else(|_| panic!("Failed to bind to {}", host));
    println!("Listening on {}", host);

    let pcap_writer = Arc::new(Mutex::new(PcapWriter::new()));
    for downstream in listener.incoming().flatten() {
        let pcap_writer = pcap_writer.clone();
        thread::spawn(move || {
            let upstream = TcpStream::connect("ap.spotify.com:4070").expect("Failed to connect to Spotify AP");
            let mut session = ProxySession::new(pcap_writer, downstream, upstream);
            if let Err(error) = session.start() {
                println!("[E] Failed to start proxy session: {}", error);
                return;
            }
            session.run();
        });
    }

    Ok(())
}
