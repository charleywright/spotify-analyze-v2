use package_json_schema::PackageJson;
use std::path::PathBuf;

pub fn locate_script_dir() -> Option<PathBuf> {
    let executable = std::env::current_exe();
    if executable.is_err() {
        return None;
    }
    let executable = executable.unwrap().canonicalize().expect("Failed to canonicalize executable path");
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

pub fn compile_script(base_dir: &PathBuf) -> bool {
    let have_yarn = std::process::Command::new("yarn").arg("--version").status().is_ok();
    let have_npm = std::process::Command::new("npm").arg("--version").status().is_ok();

    if have_yarn {
        println!("Using yarn");

        if std::process::Command::new("yarn").arg("install").current_dir(base_dir).status().is_err() {
            return false;
        }

        if std::process::Command::new("yarn").arg("run").arg("compile").current_dir(base_dir).status().is_err() {
            return false;
        }

        true
    } else if have_npm {
        println!("Using npm");

        if std::process::Command::new("npm").arg("install").current_dir(base_dir).status().is_err() {
            return false;
        }

        if std::process::Command::new("npm").arg("run").arg("compile").current_dir(base_dir).status().is_err() {
            return false;
        }

        true
    } else {
        eprintln!("Failed to find yarn or npm");
        false
    }
}
