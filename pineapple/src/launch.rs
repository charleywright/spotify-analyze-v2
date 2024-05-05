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
enum Target {
    Windows,
    Linux,
    #[allow(non_camel_case_types)]
    iOS,
    Android,
}

fn determine_device_target(device: &Device) -> anyhow::Result<Target> {
    let info = device.query_system_parameters()?;
    let Some(os_info) = info.get("os").and_then(|info| info.get_map()) else {
        return Err(anyhow!("Expected device info to contain OS info"));
    };
    let Some(os_id) = os_info.get("id").and_then(|id| id.get_string()) else {
        return Err(anyhow!("Expected OS info to contain ID"));
    };
    match os_id {
        "windows" => Ok(Target::Windows),
        "linux" => Ok(Target::Linux),
        "ios" => Ok(Target::iOS),
        "android" => Ok(Target::Android),
        _ => Err(anyhow!("Failed to detect target from OS ID: {os_id}")),
    }
}

pub fn launch_app(args: &ArgMatches) -> anyhow::Result<()> {
    // Safe due to default value
    let host = args.get_one::<String>("host").unwrap();
    let host: SocketAddr = host.parse()?;
    let exec = args.get_one::<String>("exec").map(String::to_owned);
    let usb = args.get_flag("usb");
    let device_id = args.get_one::<String>("device").map(String::to_owned);

    let frida = unsafe { Frida::obtain() };
    let device_manager = DeviceManager::obtain(&frida);
    let device = {
        if let Some(device_id) = device_id.as_deref() {
            device_manager.get_device_by_id(device_id).ok()
        } else if usb {
            device_manager.get_device_by_type(DeviceType::USB).ok()
        } else {
            device_manager.enumerate_all_devices().into_iter().next()
        }
    };
    let Some(mut device) = device else {
        return Err(anyhow!("Failed to get device. Try run frida-ls-devices"));
    };
    debug!("Found device {}, trying to determine platform...", device.get_name());
    let target = determine_device_target(&device)?;
    debug!("Determined device platform as {target:?}");
    info!("Trying to launch on {} ({target:?})", device.get_name());

    let exec = match target {
        Target::Windows | Target::Linux => {
            let exec = match exec {
                Some(exec) => PathBuf::from(exec),
                None => {
                    #[cfg(windows)]
                    {
                        use known_folders::{get_known_folder_path, KnownFolder};
                        let appdata = get_known_folder_path(KnownFolder::RoamingAppData)
                            .ok_or(anyhow!("Failed to get AppData folder"))?;
                        debug!("Resolved appdata to {appdata:?}");
                        appdata.join("Spotify").join("Spotify.exe")
                    }
                    #[cfg(unix)]
                    {
                        PathBuf::from("/opt/spotify/spotify")
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
            exec.to_string_lossy().to_string()
        },
        Target::iOS => exec.unwrap_or("com.spotify.client".to_owned()),
        Target::Android => exec.unwrap_or("com.spotify.music".to_owned()),
    };
    info!("Using executable {exec}");

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
