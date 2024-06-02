use crate::{Address, Process};
use libmem_sys::{lm_address_t, lm_process_t, LM_TRUE};
use std::mem::{transmute_copy, MaybeUninit};

#[derive(Debug)]
pub struct Trampoline {
    pub address: Address,
    pub size: usize,
}

impl Trampoline {
    pub unsafe fn callable<T>(&self) -> T {
        transmute_copy(&self.address)
    }
}

#[derive(Debug)]
pub struct RemoteTrampoline {
    pub address: Address,
    pub size: usize,
}

pub unsafe fn hook_code(from: Address, to: Address) -> Option<Trampoline> {
    let mut tramp_addr: MaybeUninit<lm_address_t> = MaybeUninit::uninit();
    let size = libmem_sys::LM_HookCode(from, to, tramp_addr.as_mut_ptr());

    (size > 0).then_some(Trampoline {
        address: tramp_addr.assume_init(),
        size,
    })
}

pub fn hook_code_ex(process: &Process, from: Address, to: Address) -> Option<RemoteTrampoline> {
    let raw_process: lm_process_t = process.to_owned().into();
    let mut tramp_addr: MaybeUninit<lm_address_t> = MaybeUninit::uninit();
    let size = unsafe {
        libmem_sys::LM_HookCodeEx(
            &raw_process as *const lm_process_t,
            from,
            to,
            tramp_addr.as_mut_ptr(),
        )
    };

    (size > 0).then_some(RemoteTrampoline {
        address: unsafe { tramp_addr.assume_init() },
        size,
    })
}

pub unsafe fn unhook_code(from: Address, trampoline: Trampoline) -> Option<()> {
    (libmem_sys::LM_UnhookCode(from, trampoline.address, trampoline.size) == LM_TRUE).then_some(())
}

pub fn unhook_code_ex(
    process: &Process,
    from: Address,
    trampoline: RemoteTrampoline,
) -> Option<()> {
    let raw_process: lm_process_t = process.to_owned().into();

    (unsafe {
        libmem_sys::LM_UnhookCodeEx(
            &raw_process as *const lm_process_t,
            from,
            trampoline.address,
            trampoline.size,
        )
    } == LM_TRUE)
        .then_some(())
}
