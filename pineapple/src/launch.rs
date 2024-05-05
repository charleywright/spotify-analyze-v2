use std::{net::SocketAddr, path::PathBuf};

use anyhow::anyhow;
use clap::ArgMatches;
use frida::{Device, DeviceManager, DeviceType, Frida, ScriptOption, SpawnOptions};
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum LaunchTarget {
    Host,
    Remote,
}

fn get_device_for_target<'d>(
    target: LaunchTarget, device_manager: &'d DeviceManager, usb: bool, id: Option<&String>,
) -> anyhow::Result<Device<'d>> {
    match target {
        LaunchTarget::Host => device_manager
            .get_device_by_type(DeviceType::Local)
            .map_err(|_| anyhow!("Failed to get local device when spawning on host. This is likely a Frida bug")),
        LaunchTarget::Remote => {
            if usb {
                return Ok(device_manager.get_device_by_type(DeviceType::USB)?);
            }
            if let Some(id) = id {
                return Ok(device_manager.get_device_by_id(id)?);
            }
            device_manager
                .enumerate_all_devices()
                .into_iter()
                .next()
                .ok_or(anyhow!("Failed to find device, is frida-server running?"))
        },
    }
}

pub fn launch_app(args: &ArgMatches) -> anyhow::Result<()> {
    // Safe due to default value
    let host = args.get_one::<String>("host").unwrap();
    let host: SocketAddr = host.parse()?;
    let exec = args.get_one::<String>("exec").map(String::to_owned);
    let usb = args.get_flag("usb");
    let device_id = args.get_one::<String>("device").map(String::to_owned);

    let (exec, target) = match args.subcommand() {
        Some(("windows", _matches)) | Some(("linux", _matches)) => {
            let (exec, target) = match exec {
                Some(exec) => (PathBuf::from(exec), LaunchTarget::Host),
                None => {
                    #[cfg(windows)]
                    {
                        use known_folders::{get_known_folder_path, KnownFolder};
                        let appdata = get_known_folder_path(KnownFolder::RoamingAppData)
                            .ok_or(anyhow!("Failed to get AppData folder"))?;
                        debug!("Resolved appdata to {appdata:?}");
                        (appdata.join("Spotify").join("Spotify.exe"), LaunchTarget::Host)
                    }
                    #[cfg(unix)]
                    {
                        (PathBuf::from("/opt/spotify/spotify"), LaunchTarget::Host)
                    }
                    #[cfg(all(not(windows), not(unix)))]
                    {
                        unreachable!()
                    }
                },
            };
            if !exec.exists() {
                panic!("Spotify is not installed. If installed from the Microsoft Store please uninstall then install from https://download.scdn.co/SpotifySetup.exe");
            }
            (exec.to_string_lossy().to_string(), target)
        },
        Some(("android", _matches)) => (exec.unwrap_or("com.spotify.music".to_owned()), LaunchTarget::Remote),
        Some(("ios", _matches)) => (exec.unwrap_or("com.spotify.client".to_owned()), LaunchTarget::Remote),
        _ => unreachable!(),
    };
    info!("Using executable {}", exec);

    let frida = unsafe { Frida::obtain() };
    let device_manager = DeviceManager::obtain(&frida);
    let mut device = get_device_for_target(target, &device_manager, usb, device_id.as_ref())?;
    info!("Trying to launch on {}", device.get_name());
    let spawn_options = SpawnOptions::new();
    let pid = device.spawn(&exec, &spawn_options)?;
    debug!("Spawned process {pid}, attaching...");
    let session = device.attach(pid)?;
    debug!("Attached to process {pid} running {exec}. Resuming...");
    device.resume(pid)?;
    debug!("Resumed process");

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

    info!("Spawned and injected into pid {pid}");
    Ok(())
}
