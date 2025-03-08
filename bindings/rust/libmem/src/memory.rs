use libmem_sys::{lm_process_t, LM_ADDRESS_BAD, LM_TRUE};

use crate::{Address, Process, Prot};
use std::mem::{self, MaybeUninit};

/// Reads a type <T> for a memory address
/// Example:
/// ```
/// let number = read_memory::<u32>(0xdeadbeef);
/// ```
pub unsafe fn read_memory<T>(source: Address) -> T {
    let size = std::mem::size_of::<T>();
    let mut value: MaybeUninit<T> = MaybeUninit::uninit();

    // This function can't actually fail, no need for extra checking.
    // If it fails, the program will crash anyways.
    libmem_sys::LM_ReadMemory(source, value.as_mut_ptr() as *mut u8, size);

    value.assume_init()
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

/// Reads a buffer from a memory address
/// Example:
/// ```
/// let mut buffer = vec![0; 1024];
/// read_memory_buf(0xdeadbeef, &mut buffer);
/// ```
#[inline(always)]
pub unsafe fn read_memory_buf(source: Address, buffer: &mut [u8]) {
    // This function can't actually fail, no need for extra checking.
    // If it fails, the program will crash anyways.
    libmem_sys::LM_ReadMemory(source, buffer.as_mut_ptr(), buffer.len());
}

/// Reads a buffer from a memory address in a remote process
/// Example:
/// ```
/// let mut buffer = vec![0; 1024];
/// read_memory_buf_ex(&process, 0xdeadbeef, &mut buffer);
/// ```
pub fn read_memory_buf_ex(process: &Process, source: Address, buffer: &mut [u8]) -> Option<usize> {
    let raw_process: lm_process_t = process.to_owned().into();
    let result = unsafe {
        libmem_sys::LM_ReadMemoryEx(
            &raw_process as *const lm_process_t,
            source,
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };

    (result == buffer.len()).then_some(result)
}

/// Writes a value of type <T> into a memory address
/// Example:
/// ```
/// let value_to_write: u32 = 1337;
/// write_memory(0xdeadbeef, &value_to_write);
/// ```
#[inline(always)]
pub unsafe fn write_memory<T: ?Sized>(dest: Address, value: &T) {
    // This function can't actually fail, no need for extra checking.
    // If it fails, the program will crash anyways.
    libmem_sys::LM_WriteMemory(
        dest,
        value as *const T as *const u8,
        mem::size_of_val(value),
    );
}

/// Writes a value of type <T> into a memory address
/// Example:
/// ```
/// let value_to_write: u32 = 1337;
/// write_memory_ex(&process, 0xdeadbeef, &value_to_write);
/// ```
pub fn write_memory_ex<T: ?Sized>(process: &Process, dest: Address, value: &T) -> Option<()> {
    let raw_process: lm_process_t = process.to_owned().into();
    let size = mem::size_of_val(value);
    let result = unsafe {
        libmem_sys::LM_WriteMemoryEx(
            &raw_process as *const lm_process_t,
            dest,
            value as *const T as *const u8,
            size,
        )
    };

    (result == size).then_some(())
}

/// Writes a buffer to a memory address
/// Example:
/// ```
/// let buffer = vec![0; 1024];
/// write_memory_buf(0xdeadbeef, &buffer);
/// ```
#[inline(always)]
pub unsafe fn write_memory_buf(dest: Address, buffer: &[u8]) {
    // This function can't actually fail, no need for extra checking.
    // If it fails, the program will crash anyways.
    libmem_sys::LM_WriteMemory(dest, buffer.as_ptr(), buffer.len());
}

/// Writes a buffer to a memory address in a remote process
/// Example:
/// ```
/// let buffer = vec![0; 1024];
/// write_memory_buf_ex(&process, 0xdeadbeef, &buffer);
/// ```
pub fn write_memory_buf_ex(process: &Process, dest: Address, buffer: &[u8]) -> Option<usize> {
    let raw_process: lm_process_t = process.to_owned().into();
    let result = unsafe {
        libmem_sys::LM_WriteMemoryEx(
            &raw_process as *const lm_process_t,
            dest,
            buffer.as_ptr(),
            buffer.len(),
        )
    };

    (result == buffer.len()).then_some(result)
}

/// Sets a memory region to a specific byte
/// Example (sets all bytes from `dest` to `dest + size` to the `42`)
/// ```
/// set_memory(0xdeadbeef, 42, 1024);
/// ```
#[inline(always)]
pub unsafe fn set_memory(dest: Address, byte: u8, size: usize) {
    // This function can't actually fail, no need for extra checking.
    // If it fails, the program will crash anyways.
    libmem_sys::LM_SetMemory(dest, byte, size);
}

/// Sets a memory region to a specific byte
/// Example (sets all bytes from `dest` to `dest + size` to the `42`)
/// ```
/// set_memory_ex(0xdeadbeef, 42, 1024);
/// ```
pub fn set_memory_ex(process: &Process, dest: Address, byte: u8, size: usize) -> Option<()> {
    let raw_process: lm_process_t = process.to_owned().into();
    let result = unsafe {
        libmem_sys::LM_SetMemoryEx(&raw_process as *const lm_process_t, dest, byte, size)
    };

    (result == size).then_some(())
}

/// Changes the protection flags of a page-aligned memory region
/// Returns the previous protection of the first page on success
pub unsafe fn prot_memory(address: Address, size: usize, prot: Prot) -> Option<Prot> {
    let mut oldprot: MaybeUninit<u32> = MaybeUninit::uninit();
    let result = libmem_sys::LM_ProtMemory(address, size, prot.bits(), oldprot.as_mut_ptr());

    (result == LM_TRUE).then_some(unsafe { oldprot.assume_init() }.into())
}

/// Changes the protection flags of a page-aligned memory region in a remote process.
/// Returns the previous protection of the first page on success
pub fn prot_memory_ex(
    process: &Process,
    address: Address,
    size: usize,
    prot: Prot,
) -> Option<Prot> {
    let raw_process: lm_process_t = process.to_owned().into();
    let mut oldprot: MaybeUninit<u32> = MaybeUninit::uninit();
    let result = unsafe {
        libmem_sys::LM_ProtMemoryEx(
            &raw_process as *const lm_process_t,
            address,
            size,
            prot.bits(),
            oldprot.as_mut_ptr(),
        )
    };

    (result == LM_TRUE).then_some(unsafe { oldprot.assume_init() }.into())
}

/// Allocates page-aligned memory in the current process
pub fn alloc_memory(size: usize, prot: Prot) -> Option<Address> {
    let alloc = unsafe { libmem_sys::LM_AllocMemory(size, prot.bits()) };
    (alloc != LM_ADDRESS_BAD).then_some(alloc)
}

/// Allocates page-aligned memory in a remote process
pub fn alloc_memory_ex(process: &Process, size: usize, prot: Prot) -> Option<Address> {
    let raw_process: lm_process_t = process.to_owned().into();
    let alloc = unsafe {
        libmem_sys::LM_AllocMemoryEx(&raw_process as *const lm_process_t, size, prot.bits())
    };
    (alloc != LM_ADDRESS_BAD).then_some(alloc)
}

/// Frees memory previously allocated with `alloc_memory`
pub unsafe fn free_memory(alloc: Address, size: usize) -> Option<()> {
    let result = libmem_sys::LM_FreeMemory(alloc, size);
    (result == LM_TRUE).then_some(())
}

/// Frees memory previously allocated with `alloc_memory_ex`
pub fn free_memory_ex(process: &Process, alloc: Address, size: usize) -> Option<()> {
    let raw_process: lm_process_t = process.to_owned().into();
    let result =
        unsafe { libmem_sys::LM_FreeMemoryEx(&raw_process as *const lm_process_t, alloc, size) };
    (result == LM_TRUE).then_some(())
}

/// Resolves a deep pointer based on its base address and recursing offsets
/// Example:
/// ```
/// let pointer_scan_result = deep_pointer(program.base + 0xdeadbeef, vec![0xFA, 0xA0, 0xF0]);
/// ```
#[inline(always)]
pub unsafe fn deep_pointer<T>(base: Address, offsets: &[Address]) -> *mut T {
    // This function cannot fail
    libmem_sys::LM_DeepPointer(base, offsets.as_ptr(), offsets.len()) as *mut T
}

/// Resolves a deep pointer of a remote process based on its base address and recursing offsets
/// Example:
/// ```
/// let pointer_scan_result = deep_pointer_ex(
///     &process,
///     program.base + 0xdeadbeef,
///     vec![0xFA, 0xA0, 0xF0]
/// ).unwrap();
/// ```
pub fn deep_pointer_ex(process: &Process, base: Address, offsets: &[Address]) -> Option<Address> {
    let raw_process: lm_process_t = process.to_owned().into();
    let result = unsafe {
        libmem_sys::LM_DeepPointerEx(
            &raw_process as *const lm_process_t,
            base,
            offsets.as_ptr(),
            offsets.len(),
        )
    };

    (result != LM_ADDRESS_BAD).then_some(result)
}
