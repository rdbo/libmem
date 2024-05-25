use crate::{Address, Process};
use libmem_sys::{lm_bool_t, lm_module_t, lm_process_t, lm_void_t, LM_TRUE};
use std::{
    ffi::{CStr, CString},
    fmt,
    mem::MaybeUninit,
};

#[derive(Debug, Clone, PartialEq)]
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

unsafe extern "C" fn enum_modules_callback(
    raw_module: *mut lm_module_t,
    arg: *mut lm_void_t,
) -> lm_bool_t {
    let modules = arg as *mut Vec<Module>;
    unsafe { (*modules).push((*raw_module).into()) };
    LM_TRUE
}

/// Enumerates modules on the current process
pub fn enum_modules() -> Option<Vec<Module>> {
    let mut modules = Vec::new();
    unsafe {
        if libmem_sys::LM_EnumModules(
            enum_modules_callback,
            &mut modules as *mut Vec<Module> as *mut lm_void_t,
        ) == LM_TRUE
        {
            Some(modules)
        } else {
            None
        }
    }
}

/// Enumerates modules on a remote process
pub fn enum_modules_ex(process: &Process) -> Option<Vec<Module>> {
    let raw_process: lm_process_t = process.to_owned().into();
    let mut modules = Vec::new();
    unsafe {
        if libmem_sys::LM_EnumModulesEx(
            &raw_process as *const lm_process_t,
            enum_modules_callback,
            &mut modules as *mut Vec<Module> as *mut lm_void_t,
        ) == LM_TRUE
        {
            Some(modules)
        } else {
            None
        }
    }
}

/// Searches for a module by its name in the current process
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

/// Searches for a module by its name in a remote process
pub fn find_module_ex(process: &Process, name: &str) -> Option<Module> {
    let raw_process: lm_process_t = process.to_owned().into();
    let mut module: MaybeUninit<lm_module_t> = MaybeUninit::uninit();
    let module_name = CString::new(name).ok()?;
    unsafe {
        if libmem_sys::LM_FindModuleEx(
            &raw_process as *const lm_process_t,
            module_name.as_ptr(),
            module.as_mut_ptr(),
        ) == LM_TRUE
        {
            Some(module.assume_init().into())
        } else {
            None
        }
    }
}
