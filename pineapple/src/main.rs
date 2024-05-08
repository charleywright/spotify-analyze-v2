#![feature(if_let_guard)]

use std::{
    net::{SocketAddr, SocketAddrV4},
    path::PathBuf,
};

use anyhow::anyhow;
use clap::{Arg, ArgAction, ArgMatches, Args, Command, FromArgMatches, Parser};
use clap_verbosity_flag::{InfoLevel, Verbosity};

mod frida;
mod launch;
mod proto;
mod proxy;
mod wireshark;

#[derive(Parser)]
struct VerbosityArgs {
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}

pub struct HostConfiguration(SocketAddrV4);

impl HostConfiguration {
    pub fn from_args(args: &ArgMatches) -> anyhow::Result<Self> {
        // Safe to unwrap() due to default value
        let host = args.get_one::<String>("host").unwrap();
        let host = host.parse()?;
        match host {
            SocketAddr::V4(addr) => Ok(Self(addr)),
            SocketAddr::V6(_) => Err(anyhow!("Host must be IPv4")),
        }
    }

    pub fn fifo_path(&self) -> PathBuf {
        let mut raw_socket_addr = self.0.ip().octets().to_vec();
        raw_socket_addr.extend_from_slice(&self.0.port().to_be_bytes());
        let fifo_filename = format!("pineapple-{}", hex::encode(raw_socket_addr));
        #[cfg(target_os = "linux")]
        let fifo_path = PathBuf::from("/tmp").join(fifo_filename);
        #[cfg(target_os = "windows")]
        let fifo_path = PathBuf::from(r"\\.\pipe\").join(fifo_filename);
        fifo_path
    }

    pub fn as_socket_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.0)
    }
}

fn main() -> anyhow::Result<()> {
    let mut cli = Command::new("pineapple")
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .arg(
            Arg::new("host")
                .long("host")
                .value_name("HOST:PORT")
                .default_value("0.0.0.0:4070")
                .long_help(
                    "Specify the host of the proxy. Due to the method used to redirect traffic this should \n\
                    ideally be either port 80, 443 or 4070. Other ports will work but could cause very minor \n\
                    issues in the app (some strings not displaying properly). This address should also be\n\
                    reachable by any device that should be intercepted, e.g. 127.0.0.1 will not work for devices \n\
                    on a local network. Only IPv4 is supported, this is a limitation of Spotify.",
                )
                .global(true),
        )
        .subcommand(
            Command::new("listen").about("Start an instance of the proxy on the specified or default host").arg(
                Arg::new("pcap-write")
                    .long("write")
                    .required(false)
                    .value_name("file path")
                    .help("Write a PCAPNG file containing all the captured packets to the specified file path"),
            ),
        )
        .subcommand({
            Command::new("launch")
                .about("Start an instance of the app on the desired platform and redirect traffic to the proxy")
                .arg(
                    Arg::new("exec")
                        .long("exec")
                        .required(false)
                        .help("The identifier to pass to Frida for spawning")
                        .long_help(
                            "The file path or identifier to pass to Frida for spawning. \n\
                        By default pineapple will handle the default install routes for you:\n\
                        - On Windows it will look for %APPDATA%\\Spotify\\Spotify.exe\n\
                        - On Linux it will look for /opt/spotify/spotify\n\
                        - On Android it will use the package com.spotify.music\n\
                        - On iOS it will use the identifier com.spotify.client",
                        ),
                )
                .arg(
                    Arg::new("usb")
                        .short('U')
                        .long("usb")
                        .required(false)
                        .action(ArgAction::SetTrue)
                        .help("Spawn the app on the first USB connected device running Frida"),
                )
                .arg(Arg::new("device").short('D').long("device").required(false).conflicts_with("usb").help(
                    "Spawn the app on the device with the given ID. Use `frida-ls-devices` to find which ID to use",
                ))
        })
        .subcommand(
            Command::new("wireshark")
                .about(
                    "Launch Wireshark and display the intercepted packets in real time. \n\
                    Note: When running multiple instances --host should be specified to select an instance",
                )
                .arg(
                    Arg::new("wireshark-dir")
                        .short('d')
                        .long("dir")
                        .value_name("install dir")
                        .required(false)
                        .help("The directory that contains the Wireshark executable"),
                ),
        );
    cli = VerbosityArgs::augment_args(cli);
    let matches = cli.get_matches();

    let verbosity = VerbosityArgs::from_arg_matches(&matches)?;
    env_logger::Builder::new().filter_level(verbosity.verbosity.log_level_filter()).init();

    match matches.subcommand() {
        Some(("listen", matches)) => proxy::run_proxy(matches),
        Some(("launch", matches)) => launch::launch_app(matches),
        Some(("wireshark", matches)) => wireshark::launch_wireshark(matches),
        _ => unreachable!(),
    }
}
