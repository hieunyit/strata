//! Links Hyperscan statically: libhs_runtime.a for the engine, libhs.a
//! (which contains the runtime too) when the `compile` feature is on.
//! HS_LIB_DIR overrides the directory; otherwise pkg-config's libdir.

use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=HS_LIB_DIR");
    let dir = env::var("HS_LIB_DIR").ok().or_else(|| {
        Command::new("pkg-config")
            .args(["--variable=libdir", "libhs"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    });
    if let Some(dir) = dir {
        println!("cargo:rustc-link-search=native={dir}");
    }
    let lib = if env::var_os("CARGO_FEATURE_COMPILE").is_some() {
        "hs"
    } else {
        "hs_runtime"
    };
    println!("cargo:rustc-link-lib=static={lib}");
    // Hyperscan is C++: the final link needs the C++ runtime.
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
