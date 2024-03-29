use std::fmt;
use std::fmt::Formatter;

mod kill;
mod scan;
mod scanner;
mod script;

#[derive(Clone, clap::ValueEnum)]
pub enum Target {
    Linux,
    Windows,
    Android,
    IOS,
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Target::Linux => write!(f, "linux"),
            Target::Windows => write!(f, "windows"),
            Target::Android => write!(f, "android"),
            Target::IOS => write!(f, "ios"),
        }
    }
}

fn main() {
    let mut cmd = clap::command!()
        .arg(clap::Arg::new("target").long("target").short('t').value_parser(clap::value_parser!(Target)).required(true)
            .help("Platform of the target"))
        .arg(clap::Arg::new("executable").long("exec").short('e').required(true)
            .help("Path or name of the executable to inject Frida into\n\
                   For Android, this is the package name\n\
                   For iOS, this is the bundle identifier\n\
                   For Windows & Linux this is the path to executable"))
        .arg(clap::Arg::new("binary").long("binary").short('b').required(false)
            .help("Path to the binary to scan for offsets\n\
                   For Android, this is the path to liborbit-jni-spotify.so for the correct architecture\n\
                   For iOS, this is the path to the Spotify file inside the decrypted IPA\n\
                   For Windows & Linux this is optional and will use the executable path if not specified"))
        .arg(clap::Arg::new("compile-script").long("compile-script").required(false).action(clap::ArgAction::SetTrue)
            .help("Install dependencies and compile the Frida script before injecting"))
        .arg(clap::Arg::new("macho-architecture").long("arch").required(false)
            .help("Mach-O architecture to use for iOS\n\
                   Only required if the binary is a fat binary. Identifiers are the same as lipo -info"))
        .arg(clap::Arg::new("kill").long("kill").short('k').required(false).action(clap::ArgAction::SetTrue)
            .help("Kill the target process before injecting. Only needed on Windows & Linux"))
        .arg(clap::Arg::new("enable-debug").long("enable-debug").required(false).action(clap::ArgAction::SetTrue)
            .help("Enable the internal app's logging features on desktop platforms"))
        .arg(clap::Arg::new("android-user").long("user").required(false)
            .help("Spawn the app as a specific user on Android. Can be used with work profiles"))
        .arg(clap::Arg::new("flags").last(true).allow_hyphen_values(true).num_args(0..)
            .help("Flags to pass to the Frida script. Possible values:\n\
                   \x20\x20shannonLogCallStacks=true       - Log a call stack for SPIRC packet encryption\n\
                   \x20\x20shannonLogInvalidCalls=true     - Log calls deemed to not be SPIRC related with return address\n\
                   \x20\x20shannonDisableSafeCallers=true  - Disable safe callers detection. Parsing will probably break\n\
                   \x20\x20shannonDisableParsing=true      - Disable all parsing of shannon data, only logging calls"));
    let matches = cmd.get_matches_mut();

    let target = matches.get_one("target").unwrap();
    match target {
        Target::Linux | Target::Windows => {
            let exec = matches.get_one::<String>("executable").unwrap();
            let exec_path = std::path::PathBuf::from(exec);
            if !exec_path.exists() {
                cmd.error(clap::error::ErrorKind::InvalidValue, "Executable does not exist").exit();
            }
        },
        Target::Android | Target::IOS => {
            if let Some(binary) = matches.get_one::<String>("binary") {
                let binary_path = std::path::PathBuf::from(binary);
                if !binary_path.exists() {
                    cmd.error(clap::error::ErrorKind::InvalidValue, "Binary does not exist").exit();
                }
            } else {
                cmd.error(clap::error::ErrorKind::MissingRequiredArgument, "Binary is required").exit();
            }
        },
    }

    let offsets = scan::scan_binary(target, &matches);
    if offsets.is_none() {
        cmd.error(clap::error::ErrorKind::InvalidValue, "Failed to scan binary").exit();
    }
    let offsets = offsets.unwrap();
    println!("Using offsets:");
    println!(" - shannon_offset1:   {:#012x}", offsets.shannon_offset1);
    println!(" - shannon_offset2:   {:#012x}", offsets.shannon_offset2);
    println!(" - server_public_key: {:#012x}", offsets.server_public_key_offset);

    let script_dir = script::locate_script_dir();
    if script_dir.is_none() {
        eprintln!("Failed to find Frida script directory");
        std::process::exit(1);
    }
    let script_dir = script_dir.unwrap();
    println!("Using script dir {}", script_dir.display());

    if matches.get_flag("compile-script") {
        if !script::compile_script(&script_dir) {
            eprintln!("Failed to compile Frida script");
        } else {
            println!("Compiled Frida script")
        }
    }

    if matches.get_flag("kill") {
        kill::kill_process_using_executable(matches.get_one::<String>("executable").unwrap());
    }

    script::bootstrap(target, &matches, &script_dir, &offsets);
}
