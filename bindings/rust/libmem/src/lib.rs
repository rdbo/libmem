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

pub mod asm;
pub mod memory;
pub mod module;
pub mod process;
pub mod scan;
pub mod segment;
pub mod symbol;
pub mod thread;
use std::fmt;

use bitflags::bitflags;

use libmem_sys::{
    lm_address_t, lm_arch_t, lm_pid_t, lm_tid_t, lm_time_t, LM_ARCH_ARM, LM_ARCH_ARM64,
    LM_ARCH_EVM, LM_ARCH_MIPS, LM_ARCH_PPC, LM_ARCH_SPARC, LM_ARCH_SYSZ, LM_ARCH_X86,
};

pub type Pid = lm_pid_t;
pub type Tid = lm_tid_t;
pub type Time = lm_time_t;
pub type Address = lm_address_t;

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Prot: u32 {
        const None = 0;
        /// Execute
        const R = (1 << 0);
        /// Read
        const W = (1 << 1);
        /// Write
        const X = (1 << 2);
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

impl fmt::Display for Prot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flag_str = String::new();

        if *self & Prot::X == Prot::X {
            flag_str.push('X');
        }

        if *self & Prot::R == Prot::R {
            flag_str.push('R');
        }

        if *self & Prot::W == Prot::W {
            flag_str.push('W');
        }

        if flag_str.len() == 0 {
            flag_str.push_str("None");
        }

        write!(f, "Prot::{}", flag_str)
    }
}

pub enum Arch {
    ARM,
    ARM64,
    MIPS,
    X86,
    PPC,
    SPARC,
    SYSZ,
    EVM,
}

impl TryFrom<lm_arch_t> for Arch {
    type Error = ();
    fn try_from(value: lm_arch_t) -> Result<Self, Self::Error> {
        match value {
            LM_ARCH_ARM => Ok(Self::ARM),
            LM_ARCH_ARM64 => Ok(Self::ARM64),
            LM_ARCH_MIPS => Ok(Self::MIPS),
            LM_ARCH_X86 => Ok(Self::X86),
            LM_ARCH_PPC => Ok(Self::PPC),
            LM_ARCH_SPARC => Ok(Self::SPARC),
            LM_ARCH_SYSZ => Ok(Self::SYSZ),
            LM_ARCH_EVM => Ok(Self::EVM),
            _ => Err(()),
        }
    }
}

impl Into<lm_arch_t> for Arch {
    fn into(self) -> lm_arch_t {
        match self {
            Self::ARM => LM_ARCH_ARM,
            Self::ARM64 => LM_ARCH_ARM64,
            Self::MIPS => LM_ARCH_MIPS,
            Self::X86 => LM_ARCH_X86,
            Self::PPC => LM_ARCH_PPC,
            Self::SPARC => LM_ARCH_SPARC,
            Self::SYSZ => LM_ARCH_SYSZ,
            Self::EVM => LM_ARCH_EVM,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Bits {
    Bits32,
    Bits64,
}

impl Into<usize> for Bits {
    fn into(self) -> usize {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

impl TryFrom<usize> for Bits {
    type Error = ();
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            32 => Ok(Self::Bits32),
            64 => Ok(Self::Bits64),
            _ => Err(()),
        }
    }
}

impl fmt::Display for Bits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bits", Into::<usize>::into(*self))
    }
}

pub use asm::*;
pub use memory::*;
pub use module::*;
pub use process::*;
pub use scan::*;
pub use segment::*;
pub use symbol::*;
pub use thread::*;
