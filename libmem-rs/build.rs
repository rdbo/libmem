use std::env;

fn main() {
    let lib_path = if cfg!(windows) {
        format!("{}{}", env::var("ProgramFiles").unwrap(), "\\libmem\\lib")
    } else {
        String::from("/usr/lib")
    };

    println!("cargo:rustc-link-search={}", lib_path);
}
