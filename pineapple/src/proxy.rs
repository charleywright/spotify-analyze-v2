use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Error, ErrorKind};
use std::rc::Rc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

mod ap_resolver;
mod dh;
mod pcap;
mod pow;
mod proxy_session;
mod shannon;

use pcap::PcapWriter;
use proxy_session::ProxySession;

const SERVER: Token = Token(0);
fn next_token() -> Token {
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    let inner = COUNTER.fetch_add(1, Ordering::Relaxed);
    Token(inner as usize)
}

pub fn run_proxy(host: String) -> io::Result<()> {
    let is_running = Arc::new(RwLock::new(true));
    {
        let is_running = is_running.clone();
        let host = host.clone();
        ctrlc::set_handler(move || {
            *is_running.write().unwrap() = false;
            // Trigger running check
            let _ = std::net::TcpStream::connect(&host);
        })
        .expect("Failed to set Ctrl+C handler");
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);
    let host = host.parse().map_err(|_| Error::new(ErrorKind::InvalidInput, "Failed to parse host"))?;
    let mut server = TcpListener::bind(host)?;
    poll.registry().register(&mut server, SERVER, Interest::READABLE)?;

    let mut connections = HashMap::new();
    let pcap_writer = Rc::new(RefCell::new(PcapWriter::new()));

    println!("Listening on {host}");

    while *is_running.read().unwrap() {
        if let Err(poll_error) = poll.poll(&mut events, Some(Duration::from_secs(1))) {
            // SIGINT e.g. Ctrl+C
            if poll_error.kind() == ErrorKind::Interrupted {
                break;
            }
            return Err(poll_error);
        }
        for event in events.iter() {
            match event.token() {
                SERVER => loop {
                    let (mut downstream, address) = match server.accept() {
                        Ok((connection, address)) => (connection, address),
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            break;
                        },
                        Err(server_err) => {
                            return Err(server_err);
                        },
                    };
                    println!("Accepted connection from {address}");

                    // Begin connecting to upstream
                    let Some(ap_addr) = ap_resolver::get_resolved_ap() else {
                        println!("[{address}] Failed to get upstream address");
                        continue;
                    };
                    let Ok(mut upstream) = TcpStream::connect(ap_addr) else {
                        println!("[{address}] Failed to connect to upstream address");
                        continue;
                    };
                    let downstream_token = next_token();
                    let upstream_token = next_token();
                    poll.registry().register(&mut downstream, downstream_token, Interest::READABLE)?;
                    poll.registry().register(&mut upstream, upstream_token, Interest::WRITABLE)?;
                    let session =
                        ProxySession::new(downstream, downstream_token, upstream, upstream_token, pcap_writer.clone());
                    let session = Rc::new(RefCell::new(session));
                    connections.insert(downstream_token, session.clone());
                    connections.insert(upstream_token, session.clone());
                },
                token => {
                    let Some(session) = connections.get(&token) else {
                        continue;
                    };
                    let mut session = session.borrow_mut();
                    // #[cfg(debug_assertions)]
                    // println!("{event:?} for {session}");
                    let is_complete = match session.handle_event(&token, event) {
                        Ok(_) => {
                            session.reregister_sockets(poll.registry())?;
                            session.is_complete()
                        },
                        Err(error) => {
                            println!(
                                "[{}] Error while handling {event:?} for {session}: {error}",
                                session.downstream_addr
                            );
                            true
                        },
                    };
                    if is_complete {
                        std::mem::drop(session); // End immutable borrow of `connections`
                        let session = connections.remove(&token).unwrap();
                        let mut session = session.borrow_mut();
                        connections.remove(&session.downstream_token);
                        connections.remove(&session.upstream_token);
                        poll.registry().deregister(&mut session.downstream)?;
                        poll.registry().deregister(&mut session.upstream)?;
                        println!("Completed connection from {}", session.peer_addr());
                    }
                },
            }
        }
    }

    println!("\rServer shutdown");
    Ok(())
}
