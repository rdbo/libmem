/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* Disable warnings for libmem compatibility */
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::fmt;
use std::ffi::{CStr, CString};
use std::mem;

/* Note: the types and structures must be
 * the same size and aligned with their C variations.
 * They can have member parameters after the C fields. */
type lm_bool_t = i32;
type lm_char_t = u8;
type lm_cchar_t = u8;
type lm_string_t = *const lm_char_t;
type lm_cstring_t = *const lm_cchar_t;

pub type lm_pid_t = u32;
pub type lm_tid_t = u32;
pub type lm_size_t = usize;
pub type lm_address_t = usize;
pub type lm_prot_t = u32;
pub type lm_byte_t = u8;

const LM_FALSE : lm_bool_t = 0;
const LM_TRUE : lm_bool_t = 1;
const LM_ADDRESS_BAD : lm_address_t = 0;
const LM_PATH_MAX : lm_size_t = 512;
pub const LM_PROT_NONE : lm_prot_t = 0;
pub const LM_PROT_X : lm_prot_t = 1 << 0;
pub const LM_PROT_R : lm_prot_t = 1 << 1;
pub const LM_PROT_W : lm_prot_t = 1 << 2;
pub const LM_PROT_XR : lm_prot_t = LM_PROT_X | LM_PROT_R;
pub const LM_PROT_XW : lm_prot_t = LM_PROT_X | LM_PROT_W;
pub const LM_PROT_RW : lm_prot_t = LM_PROT_R | LM_PROT_W;
pub const LM_PROT_XRW : lm_prot_t = LM_PROT_X | LM_PROT_R | LM_PROT_W;

fn string_from_cstring(cstring : &[u8]) -> String {
    // This function finds the null terminator from
    // a vector and deletes everything after that
    let mut cstring = cstring.to_vec();
    let mut null_index = 0;

    for i in 0..cstring.len() {
        if cstring[i] == 0 {
            null_index = i;
            break;
        }
    }

    if null_index == 0 {
        cstring.clear();
    } else {
        cstring = cstring[0..null_index].to_vec();
    }

    String::from_utf8_lossy(&cstring).to_string()
}

fn protection_string(prot : lm_prot_t) -> &'static str {
    match prot {
        LM_PROT_X => "LM_PROT_X",
        LM_PROT_R => "LM_PROT_R",
        LM_PROT_W => "LM_PROT_W",
        LM_PROT_XR => "LM_PROT_XR",
        LM_PROT_XW => "LM_PROT_XW",
        LM_PROT_RW => "LM_PROT_RW",
        LM_PROT_XRW => "LM_PROT_XRW",
        _ => "LM_PROT_NONE"
    }
}

#[repr(C)]
#[derive(Clone)]
#[derive(Copy)]
pub struct lm_process_t {
    pid : lm_pid_t,
    ppid : lm_pid_t,
    bits : lm_size_t,
    // OBS: if lm_char_t is a wchar_t, these variables won't work. Use Multibyte
    path : [lm_char_t; LM_PATH_MAX],
    name : [lm_char_t; LM_PATH_MAX]
}

impl lm_process_t {
    pub fn new() -> Self {
        Self { pid: 0, ppid: 0, bits: 0, name: [0;LM_PATH_MAX], path: [0;LM_PATH_MAX] }
    }

    pub fn get_pid(&self) -> lm_pid_t {
        self.pid
    }

    pub fn get_ppid(&self) -> lm_pid_t {
        self.ppid
    }

    pub fn get_bits(&self) -> lm_size_t {
        self.bits
    }

    pub fn get_path(&self) -> String {
        string_from_cstring(&self.path)
    }

    pub fn get_name(&self) -> String {
        string_from_cstring(&self.name)
    }
}

impl fmt::Display for lm_process_t {
    fn fmt(&self, f : &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lm_process_t {{ pid: {}, ppid: {}, bits: {}, path: {}, name: {} }}", self.get_pid(), self.get_ppid(), self.get_bits(), self.get_path(), self.get_name())
    }
}

#[repr(C)]
#[derive(Clone)]
#[derive(Copy)]
pub struct lm_module_t {
    base : lm_address_t,
    end : lm_address_t,
    size : lm_size_t,
    path : [lm_char_t;LM_PATH_MAX],
    name : [lm_char_t;LM_PATH_MAX]
}

impl lm_module_t {
    pub fn new() -> Self {
        Self { base: 0, end: 0, size: 0, path: [0;LM_PATH_MAX], name: [0;LM_PATH_MAX] }
    }

    pub fn get_base(&self) -> lm_address_t {
        self.base
    }

    pub fn get_end(&self) -> lm_address_t {
        self.end
    }

    pub fn get_size(&self) -> lm_address_t {
        self.size
    }

    pub fn get_path(&self) -> String {
        string_from_cstring(&self.path)
    }

    pub fn get_name(&self) -> String {
        string_from_cstring(&self.name)
    }
}

impl fmt::Display for lm_module_t {
    fn fmt(&self, f : &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lm_module_t {{ base: {:#x}, end: {:#x}, size: {:#x}, path: {}, name: {} }}", self.get_base(), self.get_end(), self.get_size(), self.get_path(), self.get_name())
    }
}

#[repr(C)]
#[allow(improper_ctypes)] // Permit String
pub struct lm_symbol_t {
    name : lm_cstring_t,
    address : lm_address_t,
    name_str : String // The 'name' field data is deleted after the callback returns. This field will contain a copy of it when it was still there
}

impl lm_symbol_t {
    pub fn new() -> Self {
        Self { name: 0 as lm_cstring_t, address: 0, name_str: String::new() }
    }

    pub fn get_name(&self) -> &String {
        &self.name_str
    }

    pub fn get_address(&self) -> lm_address_t {
        self.address
    }
}

impl fmt::Display for lm_symbol_t {
    fn fmt(&self, f : &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lm_symbol_t {{ name: {}, address: {:#x} }}", self.get_name(), self.get_address())
    }
}

#[repr(C)]
#[derive(Clone)]
#[derive(Copy)]
pub struct lm_page_t {
    base : lm_address_t,
    end : lm_address_t,
    size : lm_size_t,
    prot : lm_prot_t
}

impl lm_page_t {
    pub fn new() -> Self {
        Self { base: LM_ADDRESS_BAD, end: LM_ADDRESS_BAD, size: 0, prot: LM_PROT_NONE }
    }

    pub fn get_base(&self) -> lm_address_t {
        self.base
    }

    pub fn get_end(&self) -> lm_address_t {
        self.end
    }

    pub fn get_size(&self) -> lm_size_t {
        self.size
    }

    pub fn get_prot(&self) -> lm_prot_t {
        self.prot
    }
}

impl fmt::Display for lm_page_t {
    fn fmt(&self, f : &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lm_page_t {{ base: {:#x}, end: {:#x}, size: {:#x}, prot: {} }}", self.get_base(), self.get_end(), self.get_size(), protection_string(self.get_prot()))
    }
}

// Raw libmem calls
mod libmem_c {
    use crate::*;

    // link against 'mem' (the lib prefix is appended automatically)
    #[link(name = "mem")]
    extern "C" {
        pub(super) fn LM_EnumProcesses(callback : extern "C" fn(*const lm_process_t, *mut ()) -> i32, arg : *mut ()) -> lm_bool_t;
        pub(super) fn LM_GetProcess(procbuf : *mut lm_process_t) -> lm_bool_t;
        pub(super) fn LM_FindProcess(procstr : lm_string_t, procbuf : *mut lm_process_t) -> lm_bool_t;
        pub(super) fn LM_IsProcessAlive(pproc : *const lm_process_t) -> lm_bool_t;
        pub(super) fn LM_GetSystemBits() -> lm_size_t;
        /****************************************/
        pub(super) fn LM_EnumThreadIds(callback : extern "C" fn(lm_tid_t, *mut ()) -> lm_bool_t, arg : *mut ()) -> lm_bool_t;
        pub(super) fn LM_EnumThreadIdsEx(pproc : *const lm_process_t, callback : extern "C" fn(lm_tid_t, *mut ()) -> lm_bool_t, arg : *mut ()) -> lm_bool_t;
        pub(super) fn LM_GetThreadId() -> lm_tid_t;
        pub(super) fn LM_GetThreadIdEx(pproc : *const lm_process_t) -> lm_tid_t;
        /****************************************/
        pub(super) fn LM_EnumModules(callback : extern "C" fn(*const lm_module_t, *mut ()) -> lm_bool_t, arg : *mut ()) -> lm_bool_t;
        pub(super) fn LM_EnumModulesEx(pproc : *const lm_process_t, callback : extern "C" fn(*const lm_module_t, *mut ()) -> lm_bool_t, arg : *mut ()) -> lm_bool_t;
        pub(super) fn LM_FindModule(name : lm_string_t, modbuf : *mut lm_module_t) -> lm_bool_t;
        pub(super) fn LM_FindModuleEx(pproc : *const lm_process_t, name : lm_string_t, modbuf : *mut lm_module_t) -> lm_bool_t;

        pub(super) fn LM_LoadModule(modpath : lm_string_t, modbuf : *mut lm_module_t) -> lm_bool_t;
        pub(super) fn LM_LoadModuleEx(pproc : *const lm_process_t, modpath : lm_string_t, modbuf : *mut lm_module_t) -> lm_bool_t;

        pub(super) fn LM_UnloadModule(pmod : *const lm_module_t) -> lm_bool_t;
        pub(super) fn LM_UnloadModuleEx(pproc : *const lm_process_t, pmod : *const lm_module_t) -> lm_bool_t;
        /****************************************/
        #[allow(improper_ctypes)] // permit lm_symbol_t, which has a String
        pub(super) fn LM_EnumSymbols(pmod : *const lm_module_t, callback : extern "C" fn(*const lm_symbol_t, *mut ()) -> lm_bool_t, arg : *mut ()) -> lm_bool_t;
        pub(super) fn LM_FindSymbolAddress(pmod : *const lm_module_t, name : lm_cstring_t) -> lm_address_t;
        /****************************************/
        pub(super) fn LM_EnumPages(callback : extern "C" fn(*const lm_page_t, *mut ()) -> lm_bool_t, arg : *mut ()) -> lm_bool_t;
        pub(super) fn LM_EnumPagesEx(pproc : *const lm_process_t, callback : extern "C" fn(*const lm_page_t, *mut ()) -> lm_bool_t, arg : *mut ()) -> lm_bool_t;
        pub(super) fn LM_GetPage(addr : lm_address_t, pagebuf : *mut lm_page_t) -> lm_bool_t;
        pub(super) fn LM_GetPageEx(pproc : *const lm_process_t, addr : lm_address_t, pagebuf : *mut lm_page_t) -> lm_bool_t;
        /****************************************/
        pub(super) fn LM_ReadMemory(src : lm_address_t, dst : *mut u8, size : lm_size_t) -> lm_size_t;
        pub(super) fn LM_ReadMemoryEx(pproc : *const lm_process_t, src : lm_address_t, dst : *mut u8, size : lm_size_t) -> lm_size_t;
        pub(super) fn LM_WriteMemory(dst : lm_address_t, src : *const u8, size : lm_size_t) -> lm_size_t;
        pub(super) fn LM_WriteMemoryEx(pproc : *const lm_process_t, dst : lm_address_t, src : *const u8, size : lm_size_t) -> lm_size_t;
        pub(super) fn LM_SetMemory(dst : lm_address_t, byte : u8, size : lm_size_t) -> lm_size_t;
        pub(super) fn LM_SetMemoryEx(pproc : *const lm_process_t, dst : lm_address_t, byte : u8, size : lm_size_t) -> lm_size_t;
        pub(super) fn LM_ProtMemory(addr : lm_address_t, size : lm_size_t, prot : lm_prot_t, oldprot : *mut lm_prot_t) -> lm_bool_t;
        pub(super) fn LM_ProtMemoryEx(pproc : *const lm_process_t, addr : lm_address_t, size : lm_size_t, prot : lm_prot_t, oldprot : *mut lm_prot_t) -> lm_bool_t;
        pub(super) fn LM_AllocMemory(size : lm_size_t, prot : lm_prot_t) -> lm_address_t;
        pub(super) fn LM_AllocMemoryEx(pproc : *const lm_process_t, size : lm_size_t, prot : lm_prot_t) -> lm_address_t;
        pub(super) fn LM_FreeMemory(alloc : lm_address_t, size : lm_size_t) -> lm_bool_t;
        pub(super) fn LM_FreeMemoryEx(pproc : *const lm_process_t, alloc : lm_address_t, size : lm_size_t) -> lm_bool_t;
    }
}

// Rustified libmem calls
extern "C" fn _LM_EnumProcessesCallback(pproc : *const lm_process_t, arg : *mut ()) -> lm_bool_t {
    let proc_list_ptr = arg as *mut Vec<lm_process_t>;
    unsafe {
        (*proc_list_ptr).push(*pproc);
    }
    LM_TRUE
}

pub fn LM_EnumProcesses() -> Vec<lm_process_t> {
    let mut proc_list : Vec<lm_process_t> = Vec::new();
    unsafe {
        let callback = _LM_EnumProcessesCallback;
        let arg = &mut proc_list as *mut Vec<lm_process_t> as *mut ();

        if libmem_c::LM_EnumProcesses(callback, arg) == LM_FALSE {
            proc_list.clear();
        }
    }

    proc_list
}

pub fn LM_GetProcess() -> Option<lm_process_t> {
    let mut proc = lm_process_t::new();

    unsafe {
        let procbuf = &mut proc as *mut lm_process_t;
        if libmem_c::LM_GetProcess(procbuf) != LM_FALSE {
            Some(proc)
        } else {
            None
        }
    }
}

pub fn LM_FindProcess(procstr : &str) -> Option<lm_process_t> {
    let mut proc = lm_process_t::new(); 
    let procstr = match CString::new(procstr.as_bytes()) {
        // this will add the null terminator if needed
        Ok(s) => s,
        Err(_e) => return None
    };

    unsafe {
        let procstr : lm_string_t = procstr.as_ptr().cast();
        let procbuf = &mut proc as *mut lm_process_t;

        if libmem_c::LM_FindProcess(procstr, procbuf) != LM_FALSE {
            Some(proc)
        } else {
            None
        }
    }
}

pub fn LM_IsProcessAlive(pproc : &lm_process_t) -> bool {
    unsafe {
        let pproc = pproc as *const lm_process_t;
        match libmem_c::LM_IsProcessAlive(pproc) {
            LM_FALSE => false,
            _ => true
        }
    }
}

pub fn LM_GetSystemBits() -> lm_size_t {
    unsafe {
        libmem_c::LM_GetSystemBits()
    }
}

/****************************************/

extern "C" fn LM_EnumThreadIdsCallback(tid : lm_tid_t, arg : *mut ()) -> lm_bool_t {
    let thread_list_ptr = arg as *mut Vec<lm_tid_t>;
    unsafe {
        (*thread_list_ptr).push(tid);
    }
    LM_TRUE
}

pub fn LM_EnumThreadIds() -> Vec<lm_tid_t> {
    let mut thread_list : Vec<lm_tid_t> = Vec::new();
    unsafe {
        let callback = LM_EnumThreadIdsCallback;
        let arg = &mut thread_list as *mut Vec<lm_tid_t> as *mut ();
        if libmem_c::LM_EnumThreadIds(callback, arg) == LM_FALSE {
            thread_list.clear();
        }
    }

    thread_list
}

pub fn LM_EnumThreadIdsEx(pproc : &lm_process_t) -> Vec<lm_tid_t> {
    let mut thread_list : Vec<lm_tid_t> = Vec::new();
    unsafe {
        let pproc = pproc as *const lm_process_t;
        let callback = LM_EnumThreadIdsCallback;
        let arg = &mut thread_list as *mut Vec<lm_tid_t> as *mut ();
        if libmem_c::LM_EnumThreadIdsEx(pproc, callback, arg) == LM_FALSE {
            thread_list.clear();
        }
    }

    thread_list
}

pub fn LM_GetThreadId() -> lm_tid_t {
    unsafe {
        libmem_c::LM_GetThreadId()
    }
}

pub fn LM_GetThreadIdEx(pproc : &lm_process_t) -> lm_tid_t {
    unsafe {
        let pproc = pproc as *const lm_process_t;
        libmem_c::LM_GetThreadIdEx(pproc)
    }
}

/****************************************/

extern "C" fn LM_EnumModulesCallback(pmod : *const lm_module_t, arg : *mut ()) -> lm_bool_t {
    let module_list_ptr = arg as *mut Vec<lm_module_t>;
    unsafe {
        (*module_list_ptr).push(*pmod);
    }
    LM_TRUE
}

pub fn LM_EnumModules() -> Vec<lm_module_t> {
    let mut module_list : Vec<lm_module_t> = Vec::new();
    unsafe {
        let callback = LM_EnumModulesCallback;
        let arg = &mut module_list as *mut Vec<lm_module_t> as *mut ();
        if libmem_c::LM_EnumModules(callback, arg) == LM_FALSE {
            module_list.clear();
        }
    }

    module_list
}

pub fn LM_EnumModulesEx(pproc : &lm_process_t) -> Vec<lm_module_t> {
    let mut module_list : Vec<lm_module_t> = Vec::new();
    unsafe {
        let pproc = pproc as *const lm_process_t;
        let callback = LM_EnumModulesCallback;
        let arg = &mut module_list as *mut Vec<lm_module_t> as *mut ();
        if libmem_c::LM_EnumModulesEx(pproc, callback, arg) == LM_FALSE {
            module_list.clear();
        }
    }

    module_list
}

pub fn LM_FindModule(name : &str) -> Option<lm_module_t> {
    let mut module = lm_module_t::new(); 
    let name = match CString::new(name.as_bytes()) {
        // this will add the null terminator if needed
        Ok(s) => s,
        Err(_e) => return None
    };

    unsafe {
        let name : lm_string_t = name.as_ptr().cast();
        let modbuf = &mut module as *mut lm_module_t;

        if libmem_c::LM_FindModule(name, modbuf) != LM_FALSE {
            Some(module)
        } else {
            None
        }
    }
}

pub fn LM_FindModuleEx(pproc : &lm_process_t, name : &str) -> Option<lm_module_t> {
    let mut module = lm_module_t::new(); 
    let name = match CString::new(name.as_bytes()) {
        // this will add the null terminator if needed
        Ok(s) => s,
        Err(_e) => return None
    };

    unsafe {
        let pproc = pproc as *const lm_process_t;
        let name : lm_string_t = name.as_ptr().cast();
        let modbuf = &mut module as *mut lm_module_t;

        if libmem_c::LM_FindModuleEx(pproc, name, modbuf) != LM_FALSE {
            Some(module)
        } else {
            None
        }
    }
}

pub fn LM_LoadModule(modpath : &str) -> Option<lm_module_t> {
    let mut module = lm_module_t::new();
    let modpath = match CString::new(modpath.as_bytes()) {
        // this will add the null terminator if needed
        Ok(s) => s,
        Err(_e) => return None
    };

    unsafe {
        let modpath : lm_string_t = modpath.as_ptr().cast();
        let modbuf = &mut module as *mut lm_module_t;

        if libmem_c::LM_LoadModule(modpath, modbuf) != LM_FALSE {
            Some(module)
        } else {
            None
        }
    }
}

pub fn LM_LoadModuleEx(pproc : &lm_process_t, modpath : &str) -> Option<lm_module_t> {
    let mut module = lm_module_t::new();
    let modpath = match CString::new(modpath.as_bytes()) {
        // this will add the null terminator if needed
        Ok(s) => s,
        Err(_e) => return None
    };

    unsafe {
        let pproc = pproc as *const lm_process_t;
        let modpath : lm_string_t = modpath.as_ptr().cast();
        let modbuf = &mut module as *mut lm_module_t;

        if libmem_c::LM_LoadModuleEx(pproc, modpath, modbuf) != LM_FALSE {
            Some(module)
        } else {
            None
        }
    }
}

pub fn LM_UnloadModule(pmod : &lm_module_t) -> Result<(), &'static str>{
    unsafe {
        let pmod = pmod as *const lm_module_t;
        if libmem_c::LM_UnloadModule(pmod) != LM_FALSE {
            Ok(())
        } else {
            Err("LM_UnloadModule failed internally")
        }
    }
}

pub fn LM_UnloadModuleEx(pproc : &lm_process_t, pmod : &lm_module_t) -> Result<(), &'static str>{
    unsafe {
        let pproc = pproc as *const lm_process_t;
        let pmod = pmod as *const lm_module_t;
        if libmem_c::LM_UnloadModuleEx(pproc, pmod) != LM_FALSE {
            Ok(())
        } else {
            Err("LM_UnloadModuleEx failed internally")
        }
    }
}

/****************************************/

extern "C" fn LM_EnumSymbolsCallback(psymbol : *const lm_symbol_t, arg : *mut ()) -> lm_bool_t {
    let symbol_list_ptr = arg as *mut Vec<lm_symbol_t>;
    unsafe {
        let name_str = match CStr::from_ptr((*psymbol).name.cast()).to_str() {
            Ok(s) => s,
            Err(_e) => return LM_TRUE
        };

        let mut new_symbol = lm_symbol_t::new();
        new_symbol.name_str = String::from(name_str).to_string();
        new_symbol.address = (*psymbol).address; 
        (*symbol_list_ptr).push(new_symbol);
    }
    LM_TRUE
}

pub fn LM_EnumSymbols(pmod : &lm_module_t) -> Vec<lm_symbol_t> {
    let mut symbol_list : Vec<lm_symbol_t> = Vec::new();
    unsafe {
        let pmod = pmod as *const lm_module_t;
        let callback = LM_EnumSymbolsCallback;
        let arg = &mut symbol_list as *mut Vec<lm_symbol_t> as *mut ();
        if libmem_c::LM_EnumSymbols(pmod, callback, arg) == LM_FALSE {
            symbol_list.clear();
        }
    }

    symbol_list
}

pub fn LM_FindSymbolAddress(pmod : &lm_module_t, name : &str) -> Option<lm_address_t> {
    let name = match CString::new(name.as_bytes()) {
        Ok(s) => s,
        Err(_e) => return None
    };

    unsafe {
        let pmod = pmod as *const lm_module_t;
        let name : lm_cstring_t = name.as_ptr().cast();

        match libmem_c::LM_FindSymbolAddress(pmod, name) {
            LM_ADDRESS_BAD => None,
            val => Some(val)
        }
    }
}

/****************************************/

extern "C" fn LM_EnumPagesCallback(ppage : *const lm_page_t, arg : *mut ()) -> lm_bool_t {
    let page_list_ptr = arg as *mut Vec<lm_page_t>;
    unsafe {
        (*page_list_ptr).push(*ppage);
    }
    LM_TRUE
}

pub fn LM_EnumPages() -> Vec<lm_page_t> {
    let mut page_list : Vec<lm_page_t> = Vec::new();
    unsafe {
        let callback = LM_EnumPagesCallback;
        let arg = &mut page_list as *mut Vec<lm_page_t> as *mut ();
        if libmem_c::LM_EnumPages(callback, arg) == LM_FALSE {
            page_list.clear();
        }
    }

    page_list
}

pub fn LM_EnumPagesEx(pproc : &lm_process_t) -> Vec<lm_page_t> {
    let mut page_list : Vec<lm_page_t> = Vec::new();
    unsafe {
        let pproc = pproc as *const lm_process_t;
        let callback = LM_EnumPagesCallback;
        let arg = &mut page_list as *mut Vec<lm_page_t> as *mut ();
        if libmem_c::LM_EnumPagesEx(pproc, callback, arg) == LM_FALSE {
            page_list.clear();
        }
    }

    page_list
}

pub fn LM_GetPage(addr : lm_address_t) -> Option<lm_page_t> {
    let mut page = lm_page_t::new(); 

    unsafe {
        let pagebuf = &mut page as *mut lm_page_t;

        if libmem_c::LM_GetPage(addr, pagebuf) != LM_FALSE {
            Some(page)
        } else {
            None
        }
    }
}

pub fn LM_GetPageEx(pproc : &lm_process_t, addr : lm_address_t) -> Option<lm_page_t> {
    let mut page = lm_page_t::new(); 

    unsafe {
        let pproc = pproc as *const lm_process_t;
        let pagebuf = &mut page as *mut lm_page_t;

        if libmem_c::LM_GetPageEx(pproc, addr, pagebuf) != LM_FALSE {
            Some(page)
        } else {
            None
        }
    }
}

/****************************************/

pub fn LM_ReadMemory<T>(src : lm_address_t) -> Option<T> {
    let mut read_data : mem::MaybeUninit::<T> = mem::MaybeUninit::uninit();

    unsafe {
        let src = src as lm_address_t;
        let dst = read_data.as_mut_ptr() as *mut u8;
        let size = mem::size_of::<T>() as lm_size_t;

        if libmem_c::LM_ReadMemory(src, dst, size) == size {
            Some(read_data.assume_init_read())
        } else {
            None
        }
    }
}

pub fn LM_ReadMemoryEx<T>(pproc : &lm_process_t, src : lm_address_t) -> Option<T> {
    let mut read_data : mem::MaybeUninit::<T> = mem::MaybeUninit::uninit();

    unsafe {
        let pproc = pproc as *const lm_process_t;
        let src = src as lm_address_t;
        let dst = read_data.as_mut_ptr() as *mut u8;
        let size = mem::size_of::<T>() as lm_size_t;

        if libmem_c::LM_ReadMemoryEx(pproc, src, dst, size) == size {
            Some(read_data.assume_init_read())
        } else {
            None
        }
    }
}

pub fn LM_WriteMemory<T>(dst : lm_address_t, value : &T) -> Result<(), &'static str> {
    unsafe {
        let dst = dst as lm_address_t;
        let src = value as *const T as *const u8;
        let size = mem::size_of::<T>() as lm_size_t;

        if libmem_c::LM_WriteMemory(dst, src, size) == size {
            Ok(())
        } else {
            Err("LM_WriteMemory failed internally")
        }
    }
}

pub fn LM_WriteMemoryEx<T>(pproc : &lm_process_t, dst : lm_address_t, value : &T) -> Result<(), &'static str> {
    unsafe {
        let pproc = pproc as *const lm_process_t;
        let src = value as *const T as *const u8;
        let size = mem::size_of::<T>() as lm_size_t;

        if libmem_c::LM_WriteMemoryEx(pproc, dst, src, size) == size {
            Ok(())
        } else {
            Err("LM_WriteMemoryEx failed internally")
        }
    }
}

pub fn LM_SetMemory(dst : lm_address_t, byte : lm_byte_t, size : lm_size_t) -> Result<(), &'static str> {
    unsafe {
        if libmem_c::LM_SetMemory(dst, byte, size) == size {
            Ok(())
        } else {
            Err("LM_SetMemory failed internally")
        }
    }
}

pub fn LM_SetMemoryEx(pproc : &lm_process_t, dst : lm_address_t, byte : lm_byte_t, size : lm_size_t) -> Result<(), &'static str> {
    unsafe {
        let pproc = pproc as *const lm_process_t;
        if libmem_c::LM_SetMemoryEx(pproc, dst, byte, size) == size {
            Ok(())
        } else {
            Err("LM_SetMemoryEx failed internally")
        }
    }
}

pub fn LM_ProtMemory(addr : lm_address_t, size : lm_size_t, prot : lm_prot_t) -> Option<lm_prot_t> {
    let mut oldprot = LM_PROT_NONE;
    unsafe {
        let poldprot = &mut oldprot as *mut lm_prot_t;
        if libmem_c::LM_ProtMemory(addr, size, prot, poldprot) != LM_FALSE {
            Some(oldprot)
        } else {
            None
        }
    }
}

pub fn LM_ProtMemoryEx(pproc : &lm_process_t, addr : lm_address_t, size : lm_size_t, prot : lm_prot_t) -> Option<lm_prot_t> {
    let mut oldprot = LM_PROT_NONE;
    unsafe {
        let pproc = pproc as *const lm_process_t;
        let poldprot = &mut oldprot as *mut lm_prot_t;
        if libmem_c::LM_ProtMemoryEx(pproc, addr, size, prot, poldprot) != LM_FALSE {
            Some(oldprot)
        } else {
            None
        }
    }
}

pub fn LM_AllocMemory(size : lm_size_t, prot : lm_prot_t) -> Option<usize> {
    unsafe {
        let alloc = libmem_c::LM_AllocMemory(size, prot);
        if alloc != LM_ADDRESS_BAD {
            Some(alloc)
        } else {
            None
        }
    }
}

pub fn LM_AllocMemoryEx(pproc : &lm_process_t, size : lm_size_t, prot : lm_prot_t) -> Option<lm_address_t> {
    unsafe {
        let pproc = pproc as *const lm_process_t;
        let alloc = libmem_c::LM_AllocMemoryEx(pproc, size, prot);
        if alloc != LM_ADDRESS_BAD {
            Some(alloc)
        } else {
            None
        }
    }
}

pub fn LM_FreeMemory(alloc : lm_address_t, size : lm_size_t) -> Result<(), &'static str> {
    unsafe {
        if libmem_c::LM_FreeMemory(alloc, size) != LM_FALSE {
            Ok(())
        } else {
            Err("LM_FreeMemory failed internally")
        }
    }
}

pub fn LM_FreeMemoryEx(pproc : &lm_process_t, alloc : lm_address_t, size : lm_size_t) -> Result<(), &'static str> {
    unsafe {
        let pproc = pproc as *const lm_process_t;
        if libmem_c::LM_FreeMemoryEx(pproc, alloc, size) != LM_FALSE {
            Ok(())
        } else {
            Err("LM_FreeMemory failed internally")
        }
    }
}

