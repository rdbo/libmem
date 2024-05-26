use libmem_sys::{lm_bool_t, lm_process_t, lm_segment_t, lm_void_t, LM_TRUE};
use std::{fmt, mem::MaybeUninit};

use crate::{Address, Process, Prot};

#[derive(Debug, Clone, PartialEq)]
pub struct Segment {
    pub base: Address,
    pub end: Address,
    pub size: usize,
    pub prot: Prot,
}

impl From<lm_segment_t> for Segment {
    fn from(value: lm_segment_t) -> Self {
        Segment {
            base: value.base,
            end: value.end,
            size: value.size,
            prot: value.prot.into(),
        }
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Segment {{ base: {:#x}, end: {:#x}, size: {:#x}, prot: {} }}",
            self.base, self.end, self.size, self.prot
        )
    }
}

unsafe extern "C" fn enum_segments_callback(
    raw_segment: *mut lm_segment_t,
    arg: *mut lm_void_t,
) -> lm_bool_t {
    let segments = arg as *mut Vec<Segment>;
    unsafe { (*segments).push((*raw_segment).into()) };
    LM_TRUE
}

/// Enumerates the consecutive memory segments in the current process
pub fn enum_segments() -> Option<Vec<Segment>> {
    let mut segments: Vec<Segment> = Vec::new();
    let result = unsafe {
        libmem_sys::LM_EnumSegments(
            enum_segments_callback,
            &mut segments as *mut Vec<Segment> as *mut lm_void_t,
        )
    };

    (result == LM_TRUE).then_some(segments)
}

/// Enumerates the consecutive memory segments in the current process
pub fn enum_segments_ex(process: &Process) -> Option<Vec<Segment>> {
    let raw_process: lm_process_t = process.to_owned().into();
    let mut segments: Vec<Segment> = Vec::new();
    let result = unsafe {
        libmem_sys::LM_EnumSegmentsEx(
            &raw_process as *const lm_process_t,
            enum_segments_callback,
            &mut segments as *mut Vec<Segment> as *mut lm_void_t,
        )
    };

    (result == LM_TRUE).then_some(segments)
}

/// Finds the segment where a specific memory address is located in
pub fn find_segment(address: Address) -> Option<Segment> {
    let mut segment: MaybeUninit<lm_segment_t> = MaybeUninit::uninit();
    let result = unsafe { libmem_sys::LM_FindSegment(address, segment.as_mut_ptr()) };

    (result == LM_TRUE).then_some(unsafe { segment.assume_init() }.into())
}

/// Finds the segment where a specific memory address is located in
pub fn find_segment_ex(process: &Process, address: Address) -> Option<Segment> {
    let raw_process: lm_process_t = process.to_owned().into();
    let mut segment: MaybeUninit<lm_segment_t> = MaybeUninit::uninit();
    let result = unsafe {
        libmem_sys::LM_FindSegmentEx(
            &raw_process as *const lm_process_t,
            address,
            segment.as_mut_ptr(),
        )
    };

    (result == LM_TRUE).then_some(unsafe { segment.assume_init() }.into())
}
