use crate::{Pid, Process, Tid};
use libmem_sys::{lm_bool_t, lm_process_t, lm_thread_t, lm_void_t, LM_TRUE};
use std::{fmt, mem::MaybeUninit};

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

impl fmt::Display for Thread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Thread {{ tid: {}, owner_pid: {} }}",
            self.tid, self.owner_pid
        )
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

/// Gets the current thread it's running from
pub fn get_thread() -> Option<Thread> {
    let mut raw_thread: MaybeUninit<lm_thread_t> = MaybeUninit::uninit();
    unsafe {
        if libmem_sys::LM_GetThread(raw_thread.as_mut_ptr() as *mut lm_thread_t) == LM_TRUE {
            Some(raw_thread.assume_init().into())
        } else {
            None
        }
    }
}

/// Gets a thread from a specified remote process
pub fn get_thread_ex(process: &Process) -> Option<Thread> {
    let mut raw_thread: MaybeUninit<lm_thread_t> = MaybeUninit::uninit();
    let raw_process: lm_process_t = process.to_owned().into();
    unsafe {
        if libmem_sys::LM_GetThreadEx(
            &raw_process as *const lm_process_t,
            raw_thread.as_mut_ptr() as *mut lm_thread_t,
        ) == LM_TRUE
        {
            Some(raw_thread.assume_init().into())
        } else {
            None
        }
    }
}

/// Gets the process that owns a specified thread
pub fn get_thread_process(thread: &Thread) -> Option<Process> {
    let mut raw_process: MaybeUninit<lm_process_t> = MaybeUninit::uninit();
    let raw_thread: lm_thread_t = thread.to_owned().into();
    unsafe {
        if libmem_sys::LM_GetThreadProcess(
            &raw_thread as *const lm_thread_t,
            raw_process.as_mut_ptr() as *mut lm_process_t,
        ) == LM_TRUE
        {
            Some(raw_process.assume_init().into())
        } else {
            None
        }
    }
}
