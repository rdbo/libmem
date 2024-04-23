mod common;

use common::check_process;
use libmem::*;

#[test]
fn test_remote_process() {
    let process = find_process("cargo").expect("Failed to find remote process");
    eprintln!("Found process: {}", process);
    assert!(check_process(&process));

    assert!(is_process_alive(&process));
}
