/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

pub mod module;
pub mod process;
pub mod segment;
pub mod symbol;
pub mod thread;
use bitflags::bitflags;

use libmem_sys::{lm_address_t, lm_pid_t, lm_tid_t, lm_time_t};

pub type Pid = lm_pid_t;
pub type Tid = lm_tid_t;
pub type Time = lm_time_t;
pub type Address = lm_address_t;

bitflags! {
    pub struct Prot: u32 {
        /// Execute
        const X = (1 << 0);
        /// Read
        const R = (1 << 1);
        /// Write
        const W = (1 << 2);
        /// Execute and Read
        const XR = (Self::X.bits() | Self::R.bits());
        /// Execute and Write
        const XW = (Self::X.bits() | Self::W.bits());
        /// Read and Write
        const RW = (Self::R.bits() | Self::W.bits());
        /// Execute, Read and Write
        const XRW = (Self::X.bits() | Self::R.bits() | Self::W.bits());
    }
}

impl From<u32> for Prot {
    fn from(value: u32) -> Self {
        Self::from_bits(value & Self::XRW.bits()).unwrap()
    }
}

pub use module::*;
pub use process::*;
pub use segment::*;
pub use symbol::*;
pub use thread::*;
