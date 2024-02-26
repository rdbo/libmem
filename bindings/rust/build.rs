use std::env;

#[cfg(feature = "fetch")]
fn download_libmem() {}

fn main() {
    eprintln!("TEST");
    if let Ok(path) = env::var("LIBMEM_DIR") {
        eprintln!("PATH: {}", path);
        println!("cargo:rustc-link-search={}", path);
    } else {
        #[cfg(feature = "fetch")]
        download_libmem();
    }

    // Resolve link dependencies
    let deps = if cfg!(target_os = "windows") {
        vec!["user32", "psapi", "ntdll"]
    } else if cfg!(target_os = "linux") {
        vec!["dl", "m", "stdc++"]
    } else if cfg!(target_os = "freebsd") {
        vec!["dl", "kvm", "procstat", "elf", "m", "stdc++"]
    } else {
        vec![]
    };

    for dep in deps {
        println!("cargo:rustc-link-lib={}", dep);
    }
}
