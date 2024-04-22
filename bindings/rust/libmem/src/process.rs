use crate::{Pid, Time};
use libmem_sys::{lm_bool_t, lm_char_t, lm_process_t, lm_void_t, LM_PATH_MAX, LM_TRUE};
use std::{
    ffi::{CStr, CString},
    fmt,
    mem::MaybeUninit,
};

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

impl Into<lm_process_t> for Process {
    fn into(self) -> lm_process_t {
        let path_c = CString::new(self.path).unwrap();
        let name_c = CString::new(self.name).unwrap();
        let mut path: [lm_char_t; LM_PATH_MAX] = [0; LM_PATH_MAX];
        let mut name: [lm_char_t; LM_PATH_MAX] = [0; LM_PATH_MAX];
        let pathlen = path.len().min(LM_PATH_MAX - 1);
        let namelen = name.len().min(LM_PATH_MAX - 1);

        for i in 0..pathlen {
            path[i] = path_c.as_bytes()[i] as lm_char_t;
        }

        for i in 0..namelen {
            name[i] = name_c.as_bytes()[i] as lm_char_t;
        }

        lm_process_t {
            pid: self.pid,
            ppid: self.ppid,
            bits: self.bits,
            start_time: self.start_time,
            path,
            name,
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

unsafe extern "C" fn enum_processes_callback(
    process: *mut lm_process_t,
    arg: *mut lm_void_t,
) -> lm_bool_t {
    let processes = arg as *mut Vec<Process>;
    unsafe { (*processes).push((*process).into()) };
    LM_TRUE
}

/// Enumerates processes on the system
pub fn enum_processes() -> Option<Vec<Process>> {
    let mut processes = Vec::new();
    unsafe {
        if libmem_sys::LM_EnumProcesses(
            enum_processes_callback,
            &mut processes as *mut Vec<Process> as *mut lm_void_t,
        ) == LM_TRUE
        {
            Some(processes)
        } else {
            None
        }
    }
}

/// Retrieves information about the current process
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

/// Retrieves information about a specific process identified by its process ID
pub fn get_process_ex(pid: Pid) -> Option<Process> {
    let mut process: MaybeUninit<lm_process_t> = MaybeUninit::uninit();
    unsafe {
        if libmem_sys::LM_GetProcessEx(pid, process.as_mut_ptr()) == LM_TRUE {
            Some(process.assume_init().into())
        } else {
            None
        }
    }
}

/// Searches for a process by its name
pub fn find_process(name: &str) -> Option<Process> {
    let mut process: MaybeUninit<lm_process_t> = MaybeUninit::uninit();
    let process_name = CString::new(name).ok()?;
    unsafe {
        if libmem_sys::LM_FindProcess(process_name.as_ptr(), process.as_mut_ptr()) == LM_TRUE {
            Some(process.assume_init().into())
        } else {
            None
        }
    }
}

pub fn is_process_alive(process: &Process) -> bool {
    let raw_process: lm_process_t = process.to_owned().into();
    unsafe { libmem_sys::LM_IsProcessAlive(&raw_process as *const lm_process_t) == LM_TRUE }
}

#[cfg(test)]
mod tests {
    use libmem_sys::LM_PID_BAD;

    use super::*;

    fn check_process(process: &Process) -> bool {
        process.pid != LM_PID_BAD
            && process.ppid != LM_PID_BAD
            && (process.bits == 64 || process.bits == 32)
            && process.start_time > 0
            && process.path.len() > 0
            && process.name.len() > 0
    }

    #[test]
    fn test_get_process() {
        let process = get_process().expect("Failed to get current process");
        assert!(check_process(&process));
    }

    #[test]
    fn test_get_process_ex() {
        let cur_process = get_process().expect("Failed to get current process");
        let process = get_process_ex(cur_process.pid).expect("Failed to get process by PID");
        assert!(check_process(&process));
    }

    #[test]
    fn test_find_process() {
        let process = find_process("cargo").expect("Failed to find remote process");
        eprintln!("find_process(): {}", process);
        assert!(check_process(&process));
    }

    #[test]
    fn test_is_process_alive() {}
}
