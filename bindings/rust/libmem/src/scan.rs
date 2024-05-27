use crate::{Address, Process};
use libmem_sys::{lm_bytearray_t, lm_process_t, LM_ADDRESS_BAD};
use std::{ffi::CString, mem};

/// Scans for specific data in a memory region
pub unsafe fn data_scan<T>(data: &T, address: Address, scan_size: usize) -> Option<*mut T> {
    let data_ptr = data as *const T as lm_bytearray_t;
    let data_size = mem::size_of::<T>();
    let scan = libmem_sys::LM_DataScan(data_ptr, data_size, address, scan_size);

    (scan != LM_ADDRESS_BAD).then_some(scan as *mut T)
}

/// Scans for specific data in a memory region of a remote process
pub fn data_scan_ex<T>(
    process: &Process,
    data: &T,
    address: Address,
    scan_size: usize,
) -> Option<Address> {
    let raw_process: lm_process_t = process.to_owned().into();
    let data_ptr = data as *const T as lm_bytearray_t;
    let data_size = mem::size_of::<T>();
    let scan = unsafe {
        libmem_sys::LM_DataScanEx(
            &raw_process as *const lm_process_t,
            data_ptr,
            data_size,
            address,
            scan_size,
        )
    };

    (scan != LM_ADDRESS_BAD).then_some(scan)
}

/// Scans for a pattern with a byte mask in a memory region
// TODO: Ensure some sort of type safety between the pattern and the mask.
//       For example, the mask and the pattern must always have the same
//       size, and the mask has a really restricted character set.
pub unsafe fn pattern_scan(
    pattern: &[u8],
    mask: &str,
    address: Address,
    scan_size: usize,
) -> Option<Address> {
    let pattern_ptr = pattern.as_ptr() as lm_bytearray_t;
    let c_mask = CString::new(mask).ok()?;
    let scan = libmem_sys::LM_PatternScan(pattern_ptr, c_mask.as_ptr(), address, scan_size);

    (scan != LM_ADDRESS_BAD).then_some(scan)
}

/// Scans for a pattern with a byte mask in a memory region of a remote process
// TODO: Ensure some sort of type safety between the pattern and the mask.
//       For example, the mask and the pattern must always have the same
//       size, and the mask has a really restricted character set.
pub fn pattern_scan_ex(
    process: &Process,
    pattern: &[u8],
    mask: &str,
    address: Address,
    scan_size: usize,
) -> Option<Address> {
    let raw_process: lm_process_t = process.to_owned().into();
    let pattern_ptr = pattern.as_ptr() as lm_bytearray_t;
    let c_mask = CString::new(mask).ok()?;
    let scan = unsafe {
        libmem_sys::LM_PatternScanEx(
            &raw_process as *const lm_process_t,
            pattern_ptr,
            c_mask.as_ptr(),
            address,
            scan_size,
        )
    };

    (scan != LM_ADDRESS_BAD).then_some(scan)
}

/// Scans for a byte signature in a memory region
pub unsafe fn sig_scan(signature: &str, address: Address, scan_size: usize) -> Option<Address> {
    let c_signature = CString::new(signature).ok()?;
    let scan = libmem_sys::LM_SigScan(c_signature.as_ptr(), address, scan_size);

    (scan != LM_ADDRESS_BAD).then_some(scan)
}

/// Scans for a byte signature in a memory region of a remote process
pub fn sig_scan_ex(
    process: &Process,
    signature: &str,
    address: Address,
    scan_size: usize,
) -> Option<Address> {
    let raw_process: lm_process_t = process.to_owned().into();
    let c_signature = CString::new(signature).ok()?;
    let scan = unsafe {
        libmem_sys::LM_SigScanEx(
            &raw_process as *const lm_process_t,
            c_signature.as_ptr(),
            address,
            scan_size,
        )
    };

    (scan != LM_ADDRESS_BAD).then_some(scan)
}
