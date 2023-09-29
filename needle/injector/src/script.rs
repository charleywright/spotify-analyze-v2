use std::path::PathBuf;
use package_json_schema::PackageJson;

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
