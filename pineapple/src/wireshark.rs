use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::anyhow;
use clap::ArgMatches;
use log::{debug, info};

use super::HostConfiguration;

pub fn launch_wireshark(args: &ArgMatches) -> anyhow::Result<()> {
    let host_config = HostConfiguration::from_args(args)?;
    let wireshark_path = match args.get_one::<String>("wireshark-dir") {
        #[cfg(windows)]
        Some(dir) => PathBuf::from(dir).join("Wireshark.exe"),
        #[cfg(unix)]
        Some(dir) => PathBuf::from(dir).join("wireshark"),
        None => {
            #[cfg(windows)]
            {
                // Get the default install dir (%ProgramFiles%\Wireshark)
                use known_folders::{get_known_folder_path, KnownFolder};
                use log::warn;
                let program_files_dir = get_known_folder_path(KnownFolder::ProgramFiles)
                    .ok_or(anyhow!("Failed to get ProgramFiles folder"))?;
                debug!("Resolved program files to {}", program_files_dir.to_string_lossy());
                let default_install_dir = program_files_dir.join("Wireshark");
                let default_bin_path = default_install_dir.join("Wireshark.exe");
                debug!("Resolved default install path to {}", default_bin_path.to_string_lossy());

                // Get the install directory from the registry. Control panel uses this to find the uninstaller
                use registry::{Hive, Security};
                let registry_key = Hive::LocalMachine
                    .open(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark", Security::Read)
                    .ok();
                let registry_install_dir =
                    registry_key.and_then(|key| key.value("InstallLocation").ok()).and_then(|install_location| {
                        match install_location {
                            registry::Data::String(install_location) => install_location.to_string().ok(),
                            _ => None,
                        }
                    });
                let registry_bin_path =
                    registry_install_dir.clone().map(|install_dir| PathBuf::from(install_dir).join("Wireshark.exe"));

                match registry_bin_path {
                    Some(registry_bin_path) => {
                        debug!("Found install path in registry {}", registry_bin_path.to_string_lossy());
                        if !registry_bin_path.exists() {
                            warn!(
                                "Found dangling path in registry that doesn't exist: {}",
                                registry_bin_path.to_string_lossy()
                            );
                            default_bin_path
                        } else {
                            if default_bin_path.exists() &&
                                !same_file::is_same_file(&default_bin_path, &registry_bin_path).unwrap_or(true)
                            {
                                warn!(
                                    "Wireshark is installed in both {0} and {1}, but the registry only points to {1}. Using the path from the registry as it is newer",
                                    default_bin_path.to_string_lossy(),
                                    registry_bin_path.to_string_lossy()
                                );
                            }
                            registry_bin_path
                        }
                    },
                    None => default_bin_path,
                }
            }
            #[cfg(unix)]
            {
                use std::env;
                let Ok(path) = env::var("PATH") else {
                    return Err(anyhow!(
                        "Failed to get PATH variable, try specifying Wireshark's install directory with --dir <install dir>"
                    ));
                };
                let mut bin_path = None;
                for path in env::split_paths(&path) {
                    let wireshark_path = path.join("wireshark");
                    debug!("Checking for {}", wireshark_path.display());
                    if wireshark_path.exists() {
                        bin_path = Some(wireshark_path);
                        break;
                    }
                }
                bin_path.unwrap_or(PathBuf::new())
            }
        },
    };

    if !wireshark_path.exists() {
        return Err(anyhow!("Failed to find wireshark install, either install wireshark or scpeify the install directory with --dir <install dir>"));
    }

    info!("Using wireshark path {}", wireshark_path.to_string_lossy());
    info!("Using fifo path {}", host_config.fifo_path().to_string_lossy());

    let process = Command::new(wireshark_path)
        .arg("-k") // Capture immediately
        .arg(format!("-i{}", host_config.fifo_path().to_string_lossy())) // Use FIFO as interface
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    info!("Spawned process {}", process.id());

    Ok(())
}
