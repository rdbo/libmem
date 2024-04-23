mod common;

use common::check_process;
use libmem::*;

#[test]
fn test_local_process() {
    let process = get_process().expect("Failed to get current process");
    eprintln!("Current process: {}", process);
    assert!(check_process(&process));
}

#[test]
fn test_get_bits() {
    assert!(get_bits() == (std::mem::size_of::<usize>() * 8));
}

#[test]
fn test_get_system_bits() {
    let bits = get_system_bits();
    assert!(bits == 32 || bits == 64);
}
