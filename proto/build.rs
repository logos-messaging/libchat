use std::path::PathBuf;

use prost_build;

fn main() {
    let out_dir = PathBuf::from("src/gen/");

    prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(
            &["protos/inbox.proto", "protos/encryption.proto"],
            &["protos/"],
        )
        .unwrap();

    // println!("cargo:rerun-if-changed=protos/inbox.proto");
}
