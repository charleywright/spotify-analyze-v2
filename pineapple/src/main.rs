use clap::{command, Arg};
use std::io;

mod proxy;

fn main() -> io::Result<()> {
    let matches = command!()
        .arg(
            // arg! doesn't support colon in value name
            Arg::new("host")
                .value_name("HOST:PORT")
                .default_value("0.0.0.0:4070")
                .help("Specify the host for the proxy to listen on"),
        )
        .get_matches();

    // Unwrap is safe due to default value
    let host = matches.get_one::<String>("host").unwrap().clone();
    proxy::run_proxy(host)
}
