use std::{
    cell::RefCell,
    collections::HashMap,
    io::ErrorKind,
    path::PathBuf,
    rc::Rc,
    sync::{Arc, RwLock},
    time::Duration,
};

use clap::ArgMatches;
use mio::{net::TcpListener, Events, Interest, Poll};

use super::HostConfiguration;
mod ap_resolver;
mod dh;
mod nonblocking;
mod pcap_writer;
mod pow;
mod proxy_session;
mod shannon;
mod token_manager;

use ap_resolver::ApResolver;
use pcap_writer::PcapWriter;
use proxy_session::{ProxySession, ProxyTimeoutAdvice};
use token_manager::{TokenManager, SERVER_TOKEN};

use super::proto;

pub fn run_proxy(args: &ArgMatches) -> anyhow::Result<()> {
    let host_config = HostConfiguration::from_args(args)?;
    let pcap_path = args.get_one::<String>("pcap-write").map(PathBuf::from);
    let is_running = Arc::new(RwLock::new(true));
    {
        let is_running = is_running.clone();
        let host = host_config.as_socket_addr();
        ctrlc::set_handler(move || {
            *is_running.write().unwrap() = false;
            // Trigger running check
            let _ = std::net::TcpStream::connect(host);
        })
        .expect("Failed to set Ctrl+C handler");
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);
    let mut server = TcpListener::bind(host_config.as_socket_addr())?;
    let pcap_writer = Rc::new(RefCell::new(PcapWriter::new(&host_config, pcap_path.as_deref())?));
    let mut token_manager = TokenManager::new();
    poll.registry().register(&mut server, SERVER_TOKEN, Interest::READABLE)?;
    let mut ap_resolver = ApResolver::new();
    let mut connections = HashMap::new();
    let mut connection_timeouts = Vec::new();

    println!("Listening on {}", host_config.as_socket_addr());

    while *is_running.read().unwrap() {
        if let Err(poll_error) = poll.poll(&mut events, Some(Duration::from_secs(1))) {
            // SIGINT e.g. Ctrl+C
            if poll_error.kind() == ErrorKind::Interrupted {
                break;
            }
            return Err(poll_error.into());
        }
        for event in events.iter() {
            match event.token() {
                SERVER_TOKEN => loop {
                    let (downstream, address) = match server.accept() {
                        Ok((connection, address)) => (connection, address),
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            break;
                        },
                        Err(server_err) => {
                            return Err(server_err.into());
                        },
                    };
                    println!("Accepted connection from {address}");

                    let mut session =
                        ProxySession::create(downstream, &mut token_manager, &mut ap_resolver, pcap_writer.clone())?;
                    session.register_sockets(poll.registry())?;
                    let (downstream_token, upstream_token) = (session.downstream_token, session.upstream_token);
                    let session = Rc::new(RefCell::new(session));
                    connections.insert(downstream_token, session.clone());
                    connections.insert(upstream_token, session.clone());
                    connection_timeouts.push(session.clone());
                },
                token => {
                    let Some(session) = connections.get(&token) else {
                        continue;
                    };
                    let mut session = session.borrow_mut();
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
                        drop(session); // End immutable borrow of `connections`
                        let session = connections.remove(&token).unwrap();
                        let mut session = session.borrow_mut();
                        session.deregister_sockets(poll.registry())?;
                        connections.remove(&session.downstream_token);
                        connections.remove(&session.upstream_token);
                        println!("Completed connection from {}", session.peer_addr());
                    }
                },
            }
        }
        // TODO: The frequency of this running is determined by poll.poll() above. At worst it will run once per second
        connection_timeouts.retain(|session| {
            let mut session = session.borrow_mut();
            match session.timeout_advice() {
                ProxyTimeoutAdvice::KeepWaiting => true,
                ProxyTimeoutAdvice::StopChecking => false,
                ProxyTimeoutAdvice::TimedOut => {
                    // TODO: Bubble up to run_proxy()
                    let _ = session.deregister_sockets(poll.registry());
                    connections.remove(&session.downstream_token);
                    connections.remove(&session.upstream_token);
                    println!(
                        "Connection from {} to {} failed: Timed out connecting to upstream",
                        session.downstream_addr, session.upstream_addr
                    );
                    ap_resolver.mark_addr_as_invalid(session.upstream_addr);
                    false
                },
            }
        });
    }

    println!("\rServer shutdown");
    Ok(())
}
