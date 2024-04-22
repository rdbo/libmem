use crate::{Pid, Time};
use libmem_sys::{lm_process_t, LM_TRUE};
use std::{ffi::CStr, fmt, mem::MaybeUninit};

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: Pid,
    pub ppid: Pid,
    pub bits: usize,
    pub start_time: Time,
    pub path: String,
    pub name: String,
}

impl From<lm_process_t> for Process {
    fn from(raw_process: lm_process_t) -> Self {
        let path_ptr = &raw_process.path as *const i8;
        let name_ptr = &raw_process.name as *const i8;

        Self {
            pid: raw_process.pid,
            ppid: raw_process.ppid,
            bits: raw_process.bits,
            start_time: raw_process.start_time,
            // NOTE: libmem strings are always UTF-8, you can unwrap right away
            path: unsafe { CStr::from_ptr(path_ptr).to_str().unwrap().to_owned() },
            name: unsafe { CStr::from_ptr(name_ptr).to_str().unwrap().to_owned() },
        }
    }
}

impl fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Process {{ pid: {}, ppid: {}, bits: {}, start_time: {}, path: {}, name: {} }}",
            self.pid, self.ppid, self.bits, self.start_time, self.path, self.name
        )
    }
}

pub fn get_process() -> Option<Process> {
    let mut process: MaybeUninit<lm_process_t> = MaybeUninit::uninit();
    unsafe {
        if libmem_sys::LM_GetProcess(process.as_mut_ptr()) == LM_TRUE {
            Some(process.assume_init().into())
        } else {
            None
        }
    }
}
