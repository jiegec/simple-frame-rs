use std::env;
use std::path::PathBuf;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let project_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let binutils_path = project_root.join("binutils-gdb");
    let libsframe_path = binutils_path.join("libsframe");
    let include_path = binutils_path.join("include");
    let libctf_path = binutils_path.join("libctf");

    // Compile libsframe sources
    let sources = [
        libsframe_path.join("sframe.c"),
        libsframe_path.join("sframe-dump.c"),
        libsframe_path.join("sframe-error.c"),
    ];

    let mut build = cc::Build::new();
    build
        .include(&project_root) // for config.h
        .include(&include_path) // for sframe.h
        .include(&libctf_path); // for swap.h

    for source in &sources {
        build.file(source);
    }

    build.compile("sframe");

    // Generate bindings with bindgen
    let bindings = bindgen::Builder::default()
        .header(include_path.join("sframe.h").to_str().unwrap())
        .header(include_path.join("sframe-api.h").to_str().unwrap())
        .clang_arg(format!("-I{}", include_path.display()))
        // Whitelist sframe-related items
        .allowlist_function(".*sframe.*")
        .allowlist_type("sframe_.*")
        .allowlist_var("SFRAME_.*")
        .generate()
        .expect("Unable to generate bindings");

    // Write bindings to output directory
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Tell cargo to link the compiled library
    println!("cargo:rustc-link-lib=static=sframe");
    println!("cargo:rustc-link-search=native={}", out_path.display());
}
