use libmem_sys::{lm_bool_t, lm_process_t, lm_thread_t, lm_void_t, LM_TRUE};

use crate::{Pid, Process, Tid};

#[derive(Debug, Clone, PartialEq)]
pub struct Thread {
    pub tid: Tid,
    pub owner_pid: Pid,
}

impl From<lm_thread_t> for Thread {
    fn from(value: lm_thread_t) -> Self {
        Self {
            tid: value.tid,
            owner_pid: value.owner_pid,
        }
    }
}

impl Into<lm_thread_t> for Thread {
    fn into(self) -> lm_thread_t {
        lm_thread_t {
            tid: self.tid,
            owner_pid: self.owner_pid,
        }
    }
}

unsafe extern "C" fn enum_threads_callback(
    thread: *mut lm_thread_t,
    arg: *mut lm_void_t,
) -> lm_bool_t {
    let threads = arg as *mut Vec<Thread>;
    unsafe { (*threads).push((*thread).into()) };
    LM_TRUE
}

/// Enumerates the threads on the current process
pub fn enum_threads() -> Option<Vec<Thread>> {
    let mut threads = Vec::new();
    unsafe {
        if libmem_sys::LM_EnumThreads(
            enum_threads_callback,
            &mut threads as *mut Vec<Thread> as *mut lm_void_t,
        ) == LM_TRUE
        {
            Some(threads)
        } else {
            None
        }
    }
}

/// Enumerates the threads on a remote process
pub fn enum_threads_ex(process: &Process) -> Option<Vec<Thread>> {
    let mut threads = Vec::new();
    let raw_process: lm_process_t = process.to_owned().into();
    unsafe {
        if libmem_sys::LM_EnumThreadsEx(
            &raw_process as *const lm_process_t,
            enum_threads_callback,
            &mut threads as *mut Vec<Thread> as *mut lm_void_t,
        ) == LM_TRUE
        {
            Some(threads)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_threads() {
        let threads = enum_threads().expect("Failed to enumerate threads in the current process");
        assert!(threads.len() > 0);
    }

    #[test]
    fn test_enum_threads_ex() {
        let threads = enum_threads().expect("Failed to enumerate threads in the current process");
        assert!(threads.len() > 0);
    }
}
