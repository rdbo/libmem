use std::env;

fn main() {
    if cfg!(windows) {
        let lib_path = env::var("LIBMEM_SEARCH_PATH").unwrap_or_else(|_| {
            format!("{}{}", env::var("ProgramFiles").unwrap(), "\\libmem\\lib")
        });

        println!("cargo:rustc-link-search={}", lib_path);
    };
}
