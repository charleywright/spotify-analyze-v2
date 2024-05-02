#![feature(if_let_guard)]

use clap::{Arg, ArgAction, Command};

mod frida;
mod launch;
mod proto;
mod proxy;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let matches = Command::new("pineapple")
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
            let mut cmd = Command::new("launch")
                .about("Start an instance of the app on the desired platform and redirect traffic to the proxy")
                .subcommand_required(true)
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
                ));
            #[cfg(windows)]
            (cmd = cmd.subcommand(
                Command::new("windows")
                    .about("If the current host is windows, spawn Spotify and redirect traffic")
                    .disable_help_flag(true),
            ));
            #[cfg(unix)]
            (cmd = cmd.subcommand(
                Command::new("linux")
                    .long_about("If the current host is linux, spawn Spotify and redirect traffic")
                    .disable_help_flag(true),
            ));
            cmd.subcommand(
                Command::new("android")
                    .about("Spawn the app on a remote android device and redirect traffic")
                    .disable_help_flag(true),
            )
            .subcommand(
                Command::new("ios")
                    .about("Spawn the app on a remote iOS device and redirect traffic")
                    .disable_help_flag(true),
            )
        })
        .subcommand(
            Command::new("wireshark")
                .about(
                    "Launch Wireshark and display the intercepted packets in real time. \n\
                    Note: When running multiple instances --host should be specified to select an instance",
                )
                .arg(
                    Arg::new("dir")
                        .short('d')
                        .long("dir")
                        .value_name("install dir")
                        .required(false)
                        .help("The directory that contains the Wireshark executable"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("listen", matches)) => proxy::run_proxy(matches),
        Some(("launch", matches)) => launch::launch_app(matches),
        _ => unreachable!(),
    }
}
