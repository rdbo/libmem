use libmem_sys::lm_process_t;

use crate::{Address, Process};
use std::mem::{self, MaybeUninit};

/// Reads a type <T> for a memory address
/// Example:
/// ```
/// let number = read_memory::<u32>(0xdeadbeef);
/// ```
pub unsafe fn read_memory<T>(source: Address) -> T {
    let size = std::mem::size_of::<T>();
    let mut value: MaybeUninit<T> = MaybeUninit::uninit();
    unsafe {
        // This function can't actually fail, no need for extra checking.
        // If it fails, the program will crash anyways.
        libmem_sys::LM_ReadMemory(source, value.as_mut_ptr() as *mut u8, size);

        value.assume_init()
    }
}

/// Reads a type <T> for a memory address in a remote process
/// Example:
/// ```
/// let number = read_memory_ex::<u32>(&process, 0xdeadbeef);
/// ```
pub fn read_memory_ex<T>(process: &Process, source: Address) -> Option<T> {
    let raw_process: lm_process_t = process.to_owned().into();
    let size = mem::size_of::<T>();
    let mut value: MaybeUninit<T> = MaybeUninit::uninit();
    let rdsize = unsafe {
        libmem_sys::LM_ReadMemoryEx(
            &raw_process as *const lm_process_t,
            source,
            value.as_mut_ptr() as *mut u8,
            size,
        )
    };

    (rdsize == size).then_some(unsafe { value.assume_init() })
}

/// Writes a value of type <T> into a memory address
/// Example:
/// ```
/// let value_to_write: u32 = 1337;
/// write_memory(0xdeadbeef, &value_to_write);
/// ```
pub unsafe fn write_memory<T>(dest: Address, value: &T) {
    let size = mem::size_of::<T>();
    unsafe {
        // This function can't actually fail, no need for extra checking.
        // If it fails, the program will crash anyways.
        libmem_sys::LM_WriteMemory(dest, value as *const T as *const u8, size);
    }
}

/// Writes a value of type <T> into a memory address
/// Example:
/// ```
/// let value_to_write: u32 = 1337;
/// write_memory_ex(&process, 0xdeadbeef, &value_to_write);
/// ```
pub fn write_memory_ex<T>(process: &Process, dest: Address, value: &T) -> usize {
    let raw_process: lm_process_t = process.to_owned().into();
    let size = mem::size_of::<T>();
    unsafe {
        libmem_sys::LM_WriteMemoryEx(
            &raw_process as *const lm_process_t,
            dest,
            value as *const T as *const u8,
            size,
        )
    }
}

/// Set a memory region to a specific byte
/// Example (sets all bytes from `dest` to `dest + size` to the `42`)
/// ```
/// set_memory(0xdeadbeef, 42, 1024);
/// ```
pub unsafe fn set_memory(dest: Address, byte: u8, size: usize) {
    unsafe {
        // This function can't actually fail, no need for extra checking.
        // If it fails, the program will crash anyways.
        libmem_sys::LM_SetMemory(dest, byte, size);
    }
}

/// Set a memory region to a specific byte
/// Example (sets all bytes from `dest` to `dest + size` to the `42`)
/// ```
/// set_memory_ex(0xdeadbeef, 42, 1024);
/// ```
pub unsafe fn set_memory_ex(process: &Process, dest: Address, byte: u8, size: usize) -> usize {
    let raw_process: lm_process_t = process.to_owned().into();
    unsafe { libmem_sys::LM_SetMemoryEx(&raw_process as *const lm_process_t, dest, byte, size) }
}
