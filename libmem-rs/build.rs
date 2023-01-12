use std::env;

fn main() {
    let mut libmem_path;

    if cfg!(windows) {
        libmem_path = String::from(env::var("ProgramFiles").unwrap());
        libmem_path.push_str("\\libmem\\lib");
    } else {
        libmem_path = String::from("/usr/lib")
    }

    println!("cargo:rustc-link-search={}", libmem_path);
}
