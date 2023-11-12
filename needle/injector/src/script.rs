use std::path::PathBuf;

use clap::ArgMatches;
use package_json_schema::PackageJson;

use super::scan::Offsets;
use super::Target;

fn run_command(cmd: &str, dir: Option<&PathBuf>) -> std::io::Result<std::process::ExitStatus> {
    if cfg!(windows) {
        let mut command = std::process::Command::new("cmd");
        command.arg("/C").arg(cmd);
        if let Some(dir) = dir {
            command.current_dir(dir);
        }
        command.status()
    } else {
        let mut command = std::process::Command::new("sh");
        command.arg("-c").arg(cmd);
        if let Some(dir) = dir {
            command.current_dir(dir);
        }
        command.status()
    }
}

pub fn locate_script_dir() -> Option<PathBuf> {
    let executable = std::env::current_exe();
    if executable.is_err() {
        return None;
    }
    let executable = executable.unwrap();
    let executable_dir = executable.parent().expect("Failed to get executable parent directory");
    let mut parent_dir = executable_dir.parent();
    let mut package_path = PathBuf::new();

    while let Some(current_dir) = parent_dir {
        package_path = current_dir.join("package.json");
        if package_path.exists() {
            println!("Found package.json at {}", package_path.display());
            break;
        }

        parent_dir = current_dir.parent();
    }

    if parent_dir.is_none() {
        eprintln!("Failed to find package.json");
        return None;
    }

    if !package_path.exists() {
        eprintln!("Failed to find package.json");
        return None;
    }

    let package_str = std::fs::read_to_string(package_path);
    if package_str.is_err() {
        eprintln!("Failed to read package.json");
        return None;
    }
    let package_str = package_str.ok()?;
    let package = PackageJson::try_from(package_str);
    if package.is_err() {
        eprintln!("Failed to parse package.json");
        return None;
    }
    let package = package.ok()?;
    let package_name = package.name.unwrap_or("<none>".to_string());
    if package_name != "needle" {
        eprintln!("Found package.json with invalid name \"{}\", expected \"needle\"", package_name);
        return None;
    }

    Some(PathBuf::from(parent_dir.unwrap()))
}

pub fn compile_script(script_dir: &PathBuf) -> bool {
    let have_yarn = run_command("yarn --version", None).is_ok();
    let have_npm = run_command("npm --version", None).is_ok();

    if have_yarn {
        println!("Using yarn");

        if run_command("yarn install", Some(script_dir)).is_err() {
            return false;
        }

        if run_command("yarn run compile", Some(script_dir)).is_err() {
            return false;
        }

        true
    } else if have_npm {
        println!("Using npm");

        if run_command("npm install", Some(script_dir)).is_err() {
            return false;
        }

        if run_command("npm run compile", Some(script_dir)).is_err() {
            return false;
        }

        true
    } else {
        eprintln!("Failed to find yarn or npm");
        false
    }
}

pub fn bootstrap(target: &Target, args: &ArgMatches, script_dir: &PathBuf, offsets: &Offsets) -> bool {
    let bootstrap_path = script_dir.join("bootstrap.js");
    if !bootstrap_path.exists() {
        eprintln!("Failed to find bootstrap file");
        return false;
    }

    let have_node = run_command("node --version", None).is_ok();
    if !have_node {
        eprintln!("Failed to find node");
        return false;
    }

    let have_yarn = run_command("yarn --version", None).is_ok();
    let have_npm = run_command("npm --version", None).is_ok();
    if have_yarn {
        if run_command("yarn install", Some(script_dir)).is_err() {
            eprintln!("Failed to install bootstrap dependencies");
            return false;
        }
    } else if have_npm {
        if run_command("npm install", Some(script_dir)).is_err() {
            eprintln!("Failed to install bootstrap dependencies");
            return false;
        }
    } else {
        eprintln!("Failed to find npm or yarn");
        return false;
    }

    let mut bootstrap_command = std::process::Command::new("node");
    bootstrap_command.arg(bootstrap_path.to_str().unwrap());
    bootstrap_command.arg("--platform").arg(target.to_string());
    bootstrap_command.arg("--exec").arg(args.get_one::<String>("executable").unwrap());
    if args.get_flag("enable-debug") {
        bootstrap_command.arg("--enable-debug");
    }
    if let Target::Android = target {
        if let Some(android_id) = args.get_one::<String>("android-user") {
            bootstrap_command.arg("--android-user").arg(android_id);
        }
    }
    bootstrap_command.arg("--");
    // Everything after "--" is passed to the Frida script through RPC
    bootstrap_command.arg(format!("serverKey={:#x}", offsets.server_public_key_offset));
    bootstrap_command.arg(format!("shnAddr1={:#x}", offsets.shannon_offset1));
    bootstrap_command.arg(format!("shnAddr2={:#x}", offsets.shannon_offset2));
    if let Some(script_flags) = args.get_many::<String>("flags") {
        for flag in script_flags {
            bootstrap_command.arg(flag);
        }
    }

    println!("Running command `{:?}`", bootstrap_command);

    bootstrap_command.status().is_ok()
}
