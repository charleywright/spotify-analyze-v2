use std::{
    env, fs,
    path::{Path, PathBuf},
};

use npm_rs::NpmEnv;

fn compile_protobuf_files(current_dir: &Path) {
    let proto_base_dir = current_dir.join("src").join("proto");
    let files: Vec<PathBuf> = vec![
        proto_base_dir.join("authentication").join("authentication.old.proto"),
        proto_base_dir.join("keyexchange").join("keyexchange.old.proto"),
        proto_base_dir.join("mercury").join("mercury.old.proto"),
        proto_base_dir.join("mercury").join("pubsub.old.proto"),
    ];

    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("protobuf")
        .inputs(&files)
        .include(&proto_base_dir)
        .run()
        .expect("Failed to compile protobuf files");
}

const SCRIPT_NAME: &str = "_redirect.js";
fn compile_frida_script(current_dir: &Path, out_dir: &Path) {
    let status_code = NpmEnv::default()
        .set_path(current_dir)
        .init_env()
        .install(None)
        .run("build")
        .exec()
        .expect("Failed to build Frida script");
    assert!(status_code.success(), "Expected Frida build script to succeed");
    let script_path = current_dir.join(SCRIPT_NAME);
    let target_script_path = out_dir.join(SCRIPT_NAME);
    fs::rename(script_path, target_script_path).expect("Failed to move Frida script to build directory");
}

fn main() {
    let current_dir =
        Path::new(&env::var("CARGO_MANIFEST_DIR").expect("Failed to get cargo manifest dir")).to_path_buf();
    let out_dir = Path::new(&env::var("OUT_DIR").expect("Failed to get out dir")).to_path_buf();

    compile_protobuf_files(&current_dir);
    compile_frida_script(&current_dir, &out_dir);
}
