use std::env;

fn main() {
    if cfg!(windows) {
        if let Ok(path) = env::var("LIBMEM_DIR") {
            println!("cargo:rustc-link-search={}", path);
        }

        let lib_path = format!("{}{}", env::var("ProgramFiles").unwrap(), "\\libmem\\lib");
        println!("cargo:rustc-link-search={}", lib_path);
    };
}
