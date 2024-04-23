mod common;

use common::check_process;
use libmem::*;

use crate::common::check_thread;

#[test]
fn test_remote_process() {
    let process = find_process("cargo").expect("Failed to find remote process");
    eprintln!("Found process: {}", process);
    assert!(check_process(&process));

    assert!(is_process_alive(&process));

    assert_eq!(
        process,
        get_process_ex(process.pid).expect("Failed to get process by PID")
    );

    let threads =
        enum_threads_ex(&process).expect("Failed to enumerate threads in the current process");
    assert!(threads.len() > 0);

    let thread = get_thread_ex(&process).expect("Failed to get remote process thread");
    assert!(check_thread(&thread));

    assert_eq!(
        get_thread_process(&thread).expect("Failed to get thread's owner process"),
        process
    );
}
