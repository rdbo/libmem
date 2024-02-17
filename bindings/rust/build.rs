use std::env;

fn main() {
    if cfg!(windows) {
        let lib_path = format!("{}{}", env::var("ProgramFiles").unwrap(), "\\libmem\\lib");
        println!("cargo:rustc-link-search={}", lib_path);
    };
}
