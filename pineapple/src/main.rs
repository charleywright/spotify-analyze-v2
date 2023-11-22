use std::{
    io,
    net::{TcpListener, TcpStream},
    thread,
};

mod dh;
mod proxy_session;
mod shannon;
use proxy_session::ProxySession;

fn main() -> io::Result<()> {
    let host = "192.168.1.120:4070";
    let listener = TcpListener::bind(host).unwrap_or_else(|_| panic!("Failed to bind to {}", host));
    println!("Listening on {}", host);

    for downstream in listener.incoming().flatten() {
        thread::spawn(move || {
            let upstream = TcpStream::connect("ap.spotify.com:4070").expect("Failed to connect to Spotify AP");
            let mut session = ProxySession::new(downstream, upstream);
            if let Err(error) = session.start() {
                println!("[E] Failed to start proxy session: {}", error);
                return;
            }
            session.run();
        });
    }

    Ok(())
}
