use crate::Address;
use libmem_sys::{lm_module_t, LM_TRUE};
use std::{
    ffi::{CStr, CString},
    fmt,
    mem::MaybeUninit,
};

pub struct Module {
    pub base: Address,
    pub end: Address,
    pub size: usize,
    pub path: String,
    pub name: String,
}

impl From<lm_module_t> for Module {
    fn from(raw_module: lm_module_t) -> Self {
        let path_ptr = &raw_module.path as *const i8;
        let name_ptr = &raw_module.name as *const i8;

        Self {
            base: raw_module.base,
            end: raw_module.end,
            size: raw_module.size,
            path: unsafe { CStr::from_ptr(path_ptr).to_str().unwrap().to_owned() },
            name: unsafe { CStr::from_ptr(name_ptr).to_str().unwrap().to_owned() },
        }
    }
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Module {{ base: {:#x}, end: {:#x}, size: {:#x}, path: {}, name: {} }}",
            self.base, self.end, self.size, self.path, self.name
        )
    }
}

pub fn find_module(name: &str) -> Option<Module> {
    let mut module: MaybeUninit<lm_module_t> = MaybeUninit::uninit();
    let module_name = CString::new(name).ok()?;
    unsafe {
        if libmem_sys::LM_FindModule(module_name.as_ptr(), module.as_mut_ptr()) == LM_TRUE {
            Some(module.assume_init().into())
        } else {
            None
        }
    }
}
