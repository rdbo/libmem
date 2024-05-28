use std::mem::{transmute_copy, MaybeUninit};

use libmem_sys::{lm_address_t, lm_vmt_t};

use crate::Address;

/// Represents a Virtual Method Table (VMT) manager
/// Can be used for VMT hooking and management
pub struct Vmt {
    internal_vmt: lm_vmt_t,
}

impl Vmt {
    pub fn new(vtable: Address) -> Self {
        let mut internal_vmt: MaybeUninit<lm_vmt_t> = MaybeUninit::uninit();
        unsafe { libmem_sys::LM_VmtNew(vtable as *mut lm_address_t, internal_vmt.as_mut_ptr()) };
        Self {
            internal_vmt: unsafe { internal_vmt.assume_init() },
        }
    }

    /// Hooks a VMT entry
    pub unsafe fn hook(&mut self, from_fn_index: usize, to: Address) {
        libmem_sys::LM_VmtHook(&mut self.internal_vmt as *mut lm_vmt_t, from_fn_index, to);
    }

    /// Unhooks a VMT entry
    pub unsafe fn unhook(&mut self, fn_index: usize) {
        libmem_sys::LM_VmtUnhook(&mut self.internal_vmt as *mut lm_vmt_t, fn_index);
    }

    /// Gets the original address of a VMT entry that may have been hooked already
    pub unsafe fn get_original<T>(&self, fn_index: usize) -> T {
        let orig = libmem_sys::LM_VmtGetOriginal(&self.internal_vmt as *const lm_vmt_t, fn_index);
        transmute_copy(&orig)
    }

    /// Resets the whole VMT to its original indices
    pub unsafe fn reset(&mut self) {
        libmem_sys::LM_VmtReset(&mut self.internal_vmt as *mut lm_vmt_t)
    }
}

impl Drop for Vmt {
    fn drop(&mut self) {
        unsafe { libmem_sys::LM_VmtFree(&mut self.internal_vmt as *mut lm_vmt_t) }
    }
}
