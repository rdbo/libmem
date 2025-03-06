use libmem::{Bits, Process, Thread};
use libmem_sys::{LM_PID_BAD, LM_TID_BAD};

pub fn check_process(process: &Process) -> bool {
    process.pid != LM_PID_BAD
        && process.ppid != LM_PID_BAD
        && (process.bits == Bits::Bits64 || process.bits == Bits::Bits32)
        && process.start_time > 0
        && process.path.len() > 0
        && process.name.len() > 0
}

pub fn check_thread(thread: &Thread) -> bool {
    thread.tid != LM_TID_BAD && thread.owner_pid != LM_PID_BAD
}
