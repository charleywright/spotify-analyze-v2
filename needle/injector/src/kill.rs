use std::path::PathBuf;

pub fn kill_process_using_executable(executable: &String) -> bool {
    println!("Trying to kill {}", executable);

    #[cfg(target_os = "linux")]
    {
        use std::str::FromStr;
        use std::time::Duration;

        let proc = PathBuf::from("/proc");
        let children = proc.read_dir();
        if children.is_err() {
            eprintln!("Failed to iterator over /proc/");
            return false;
        }

        for entry in children.ok().unwrap() {
            if entry.is_err() {
                continue;
            }
            let entry = entry.ok().unwrap();
            if !entry.path().is_dir() {
                continue;
            }
            let filename = entry.file_name();
            let filename_str = filename.to_str();
            if filename_str.is_none() {
                continue;
            }
            let filename_str = filename_str.unwrap();
            if !filename_str.chars().all(char::is_numeric) {
                continue;
            }

            let cmdline = entry.path().join("cmdline");
            let cmdline_str = std::fs::read_to_string(cmdline);
            if cmdline_str.is_err() {
                continue;
            }
            let cmdline_str = cmdline_str.unwrap();
            if cmdline_str.starts_with(executable) {
                let proc_id = i32::from_str(filename_str);
                if proc_id.is_err() {
                    continue;
                }
                let proc_id = nix::unistd::Pid::from_raw(proc_id.unwrap());
                nix::sys::signal::kill(proc_id, nix::sys::signal::SIGTERM).expect("Failed to send SIGTERM");
                std::thread::sleep(Duration::from_millis(500));
                // Ignore result because its okay for this to fail if the process has already cleanly exited
                let _ = nix::sys::signal::kill(proc_id, nix::sys::signal::SIGKILL);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use winsafe::co::{PROCESS, PROCESS_NAME};
        use winsafe::prelude::*;

        let executable_path = PathBuf::from(executable).canonicalize();
        if executable_path.is_err() {
            eprintln!("Failed to canonicalize executable path");
            return false;
        }
        let executable_path = executable_path.unwrap();
        let snapshot = winsafe::HPROCESSLIST::CreateToolhelp32Snapshot(winsafe::co::TH32CS::SNAPPROCESS, None);
        if snapshot.is_err() {
            eprintln!("Failed to create snapshot");
            return false;
        }
        let mut snapshot = snapshot.unwrap();
        for process_entry in snapshot.iter_processes() {
            if process_entry.is_err() {
                continue;
            }
            let process_entry = process_entry.unwrap();
            let process = winsafe::HPROCESS::OpenProcess(
                PROCESS::QUERY_LIMITED_INFORMATION | PROCESS::TERMINATE,
                false,
                process_entry.th32ProcessID,
            );
            if process.is_err() {
                continue;
            }
            let process = process.unwrap();
            let process_executable = process.QueryFullProcessImageName(PROCESS_NAME::NATIVE);
            if process_executable.is_err() {
                continue;
            }
            let process_executable = process_executable.unwrap();
            let process_path = PathBuf::from(process_executable.replace("\\Device\\", "\\\\?\\"));
            if let Ok(canonicalised_process_path) = process_path.canonicalize() {
                if executable_path == canonicalised_process_path {
                    let _ = process.TerminateProcess(0);
                }
            }
        }
    }

    true
}
