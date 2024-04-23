use libmem::Process;
use libmem_sys::LM_PID_BAD;

pub fn check_process(process: &Process) -> bool {
    process.pid != LM_PID_BAD
        && process.ppid != LM_PID_BAD
        && (process.bits == 64 || process.bits == 32)
        && process.start_time > 0
        && process.path.len() > 0
        && process.name.len() > 0
}
