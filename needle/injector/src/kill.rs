use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

pub fn kill_process_using_executable(executable: &String) -> bool {
    println!("Trying to kill {}", executable);

    #[cfg(target_os = "linux")]
    {
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

    true
}
