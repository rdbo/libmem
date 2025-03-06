mod common;

use common::{check_process, check_thread};
use libmem::*;

#[test]
fn test_get_process() {
    let process = get_process().expect("Failed to get current process");
    eprintln!("Current process: {}", process);
    assert!(check_process(&process));
}

#[test]
fn test_get_bits() {
    assert!(<Bits as Into<usize>>::into(get_bits()) == (std::mem::size_of::<usize>() * 8));
}

#[test]
fn test_get_system_bits() {
    let bits = get_system_bits();
    assert!(bits == Bits::Bits32 || bits == Bits::Bits64);
}

#[test]
fn test_enum_threads() {
    let threads = enum_threads().expect("Failed to enumerate threads in the current process");
    assert!(threads.len() > 0);
}

#[test]
fn test_get_thread() {
    let thread = get_thread().expect("Failed to get current thread");
    assert!(check_thread(&thread));
}
