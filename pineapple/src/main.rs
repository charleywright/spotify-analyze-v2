#![feature(if_let_guard)]

use clap::{Arg, Command};

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
        _ => unreachable!(),
    }
}
