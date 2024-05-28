use std::{
    ffi::{CStr, CString},
    fmt,
    mem::MaybeUninit,
    slice,
};

use libmem_sys::{lm_byte_t, lm_inst_t, LM_TRUE};

use crate::{Address, Arch, Bits};

/// An assembled/disassembled instruction
#[derive(Debug, Clone, PartialEq)]
pub struct Inst {
    pub address: Address,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
}

impl From<lm_inst_t> for Inst {
    fn from(value: lm_inst_t) -> Self {
        let bytes = Vec::from(&value.bytes[0..value.size]);
        Self {
            address: value.address,
            bytes,
            mnemonic: unsafe {
                CStr::from_ptr(value.mnemonic.as_ptr())
                    .to_str()
                    .unwrap()
                    .to_owned()
            },
            op_str: unsafe {
                CStr::from_ptr(value.op_str.as_ptr())
                    .to_str()
                    .unwrap()
                    .to_owned()
            },
        }
    }
}

impl fmt::Display for Inst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} @ {:#x} -> {:x?}",
            self.mnemonic, self.op_str, self.address, self.bytes
        )
    }
}

/// Gets the current architecture
pub fn get_architecture() -> Arch {
    // This unwrap should NEVER fail. If it does, either:
    // - there is a problem with the `Arch` type itself,
    // - there is a problem with the C API.
    // - the architecture is not supported
    unsafe { libmem_sys::LM_GetArchitecture().try_into().unwrap() }
}

/// Assembles a single instruction in the current architecture
pub fn assemble(code: &str) -> Option<Inst> {
    let c_code = CString::new(code).ok()?;
    let mut raw_instruction: MaybeUninit<lm_inst_t> = MaybeUninit::uninit();
    let result = unsafe { libmem_sys::LM_Assemble(c_code.as_ptr(), raw_instruction.as_mut_ptr()) };

    (result == LM_TRUE).then_some(unsafe { raw_instruction.assume_init() }.into())
}

/// Assembles one or more instructions with customizable parameters (arch, bits, runtime address)
/// into machine code
pub fn assemble_ex(
    code: &str,
    arch: Arch,
    bits: Bits,
    runtime_address: Address,
) -> Option<Vec<u8>> {
    let c_code = CString::new(code).ok()?;
    let mut raw_payload: *mut lm_byte_t = std::ptr::null_mut();
    let payload_size = unsafe {
        libmem_sys::LM_AssembleEx(
            c_code.as_ptr(),
            arch.into(),
            bits.into(),
            runtime_address,
            &mut raw_payload as *mut *mut lm_byte_t,
        )
    };

    if payload_size > 0 {
        let mut payload = vec![];

        let payload_slice = unsafe { slice::from_raw_parts(raw_payload, payload_size) };

        payload.extend_from_slice(payload_slice);

        unsafe { libmem_sys::LM_FreePayload(raw_payload) };

        Some(payload)
    } else {
        None
    }
}
