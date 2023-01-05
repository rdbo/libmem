use cmake;

fn main() {
	let mut dst = cmake::Config::new("libmem")
                                .define("CMAKE_BUILD_TYPE", "Release")
                                .define("LIBMEM_BUILD_STATIC", "ON")
                                .define("LIBMEM_BUILD_TESTS", "OFF")
                                .no_build_target(true)
                                .build();
    dst = dst.join("build");
    println!("cargo:rustc-link-search={}", dst.display());
    println!("cargo:rustc-link-lib=static=mem");
}
