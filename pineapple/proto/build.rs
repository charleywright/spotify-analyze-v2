use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() {
    let current_dir =
        Path::new(&env::var("CARGO_MANIFEST_DIR").expect("Failed to get cargo manifest dir")).to_path_buf();
    let out_dir = Path::new(&env::var("OUT_DIR").expect("Failed to get out dir")).to_path_buf();
    let files: Vec<PathBuf> = vec![
        current_dir.join("authentication/authentication.old.proto"),
        current_dir.join("keyexchange/keyexchange.old.proto"),
        current_dir.join("mercury/mercury.old.proto"),
        current_dir.join("mercury/pubsub.old.proto"),
    ];

    fs::remove_dir_all(&out_dir).expect("Failed to clean output directory");
    fs::create_dir(&out_dir).expect("Failed to create output directory");

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(&out_dir)
        .inputs(&files)
        .include(&current_dir)
        .run()
        .expect("Failed to compile protobuf files");
}
