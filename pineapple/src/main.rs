use std::{
    io,
    net::{TcpListener, TcpStream},
};

mod dh;
mod proxy_session;
use proxy_session::ProxySession;

fn handle_client(downstream: TcpStream) -> std::io::Result<()> {
    // Connect to real AP
    let upstream = TcpStream::connect("ap.spotify.com:4070").expect("Failed to connect to Spotify AP");
    // Create proxy session
    let mut session = ProxySession::new(downstream, upstream);
    session.start()
}

fn main() -> io::Result<()> {
    let host = "192.168.1.120:4070";
    let listener = TcpListener::bind(host).unwrap_or_else(|_| panic!("Failed to bind to {}", host));
    println!("Listening on {}", host);

    for stream in listener.incoming() {
        let _ = handle_client(stream?);
    }

    Ok(())
}
