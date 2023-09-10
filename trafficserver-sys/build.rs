use std::{
    env,
    path::PathBuf,
    process::{exit, Command},
};

use bindgen::Builder;

extern crate bindgen;

fn main() {
    let cmd = Command::new("pkg-config")
        .args(&["--cflags", "trafficserver"])
        .output()
        .expect("failed to run pkg-config");
    let output = String::from_utf8(cmd.stdout).unwrap();
    if !cmd.status.success() {
        println!("pkg-config returned an error: {}", output);
        exit(-1);
    }
    let Some(header_dir) = output.trim().strip_prefix("-I") else {
        println!("unexpected pkg-config output: {}", output);
        exit(-1);
    };
    let header_path: PathBuf = [header_dir, "ts", "ts.h"].iter().collect();
    let bindings = Builder::default()
        .header(header_path.to_string_lossy())
        .newtype_enum("TSReturnCode")
        .newtype_enum("TSEvent")
        .newtype_enum("TSCacheLookupResult")
        .newtype_enum("TSHttpHookID")
        .newtype_enum("TSHttpStatus")
        .generate()
        .expect("error generating bindings");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("error writing bindings to file");
}
