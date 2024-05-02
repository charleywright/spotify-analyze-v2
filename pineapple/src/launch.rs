use std::{net::SocketAddr, path::PathBuf};

use anyhow::anyhow;
use clap::ArgMatches;
use frida::{DeviceManager, DeviceType, Frida, ScriptOption, SpawnOptions};
use log::{debug, info};

use super::frida::FRIDA_SCRIPT_SRC;

fn get_config_script_src(host: &SocketAddr) -> anyhow::Result<String> {
    let SocketAddr::V4(host) = host else {
        return Err(anyhow!("Spotify only supports IPv4"));
    };
    let octets = host.ip().octets();
    let port = host.port();
    Ok(format!(
        r#"globalThis.TARGET_IP="{}.{}.{}.{}";globalThis.TARGET_PORT={port};"#,
        octets[0], octets[1], octets[2], octets[3]
    ))
}

pub fn launch_app(args: &ArgMatches) -> anyhow::Result<()> {
    // Safe due to default value
    let host = args.get_one::<String>("host").unwrap();
    let host: SocketAddr = host.parse()?;
    let exec = args.get_one::<String>("exec").map(String::to_owned);
    let usb = args.get_flag("usb");
    let device = args.get_one::<String>("device").map(String::to_owned);

    match args.subcommand() {
        #[cfg(windows)]
        Some(("windows", _matches)) => {
            use known_folders::{get_known_folder_path, KnownFolder};
            let exec = match exec {
                Some(exec) => PathBuf::from(exec),
                None => {
                    let appdata = get_known_folder_path(KnownFolder::RoamingAppData)
                        .ok_or(anyhow!("Failed to get AppData folder"))?;
                    debug!("Resolved appdata to {appdata:?}");
                    appdata.join("Spotify").join("Spotify.exe")
                },
            };
            if !exec.exists() {
                panic!("Spotify is not installed. If installed from the Microsoft Store please uninstall then install from https://download.scdn.co/SpotifySetup.exe");
            }
            info!("Using executable {}", exec.to_string_lossy());

            let frida = unsafe { Frida::obtain() };
            let device_manager = DeviceManager::obtain(&frida);
            let mut local_device = device_manager
                .get_device_by_type(DeviceType::Local)
                .expect("Failed to find local device on Windows. This may be a Frida bug");
            let spawn_options = SpawnOptions::new();
            let pid = local_device.spawn(exec.to_string_lossy(), &spawn_options)?;
            let session = local_device.attach(pid)?;

            let config_script_src = get_config_script_src(&host)?;
            debug!("Created config script: {config_script_src}");
            let mut config_script_options = ScriptOption::new();
            let config_script = session.create_script(&config_script_src, &mut config_script_options)?;
            config_script.load()?;
            debug!("Loaded config script");

            debug!("Loading redirect script");
            let mut frida_script_options = ScriptOption::new().set_name("pineapple");
            let frida_script = session.create_script(FRIDA_SCRIPT_SRC, &mut frida_script_options)?;
            frida_script.load()?;
            debug!("Loaded redirect script");

            debug!("Resuming process {pid}...");
            local_device.resume(pid)?;
            debug!("Resumed process");

            Ok(())
        },
        #[cfg(unix)]
        Some(("linux", _matches)) => Ok(()),
        Some(("android", _matches)) => Ok(()),
        Some(("ios", _matches)) => Ok(()),
        _ => unreachable!(),
    }
}
