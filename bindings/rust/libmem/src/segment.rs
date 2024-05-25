use libmem_sys::{lm_bool_t, lm_segment_t, lm_void_t, LM_TRUE};

use crate::{Address, Prot};

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
