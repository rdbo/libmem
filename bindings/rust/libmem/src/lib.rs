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
pub mod hook;
pub mod memory;
pub mod module;
pub mod process;
pub mod scan;
pub mod segment;
pub mod symbol;
pub mod thread;
pub mod vmt;
use std::fmt;

use bitflags::bitflags;

use libmem_sys::*;

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Arch {
    GENERIC,
    ARMV7,
    ARMV8,
    THUMBV7,
    THUMBV8,
    ARMV7EB,
    THUMBV7EB,
    ARMV8EB,
    THUMBV8EB,
    AARCH64,
    MIPS,
    MIPS64,
    MIPSEL,
    MIPSEL64,
    X86_16,
    X86,
    X64,
    PPC32,
    PPC64,
    PPC64LE,
    SPARC,
    SPARC64,
    SPARCEL,
    SYSZ,
}

impl TryFrom<lm_arch_t> for Arch {
    type Error = ();
    fn try_from(value: lm_arch_t) -> Result<Self, Self::Error> {
        match value {
            LM_ARCH_GENERIC => Ok(Self::GENERIC),
            LM_ARCH_ARMV7 => Ok(Self::ARMV7),
            LM_ARCH_ARMV8 => Ok(Self::ARMV8),
            LM_ARCH_THUMBV7 => Ok(Self::THUMBV7),
            LM_ARCH_THUMBV8 => Ok(Self::THUMBV8),
            LM_ARCH_ARMV7EB => Ok(Self::ARMV7EB),
            LM_ARCH_THUMBV7EB => Ok(Self::THUMBV7EB),
            LM_ARCH_ARMV8EB => Ok(Self::ARMV8EB),
            LM_ARCH_THUMBV8EB => Ok(Self::THUMBV8EB),
            LM_ARCH_AARCH64 => Ok(Self::AARCH64),
            LM_ARCH_MIPS => Ok(Self::MIPS),
            LM_ARCH_MIPS64 => Ok(Self::MIPS64),
            LM_ARCH_MIPSEL => Ok(Self::MIPSEL),
            LM_ARCH_MIPSEL64 => Ok(Self::MIPSEL64),
            LM_ARCH_X86_16 => Ok(Self::X86_16),
            LM_ARCH_X86 => Ok(Self::X86),
            LM_ARCH_X64 => Ok(Self::X64),
            LM_ARCH_PPC32 => Ok(Self::PPC32),
            LM_ARCH_PPC64 => Ok(Self::PPC64),
            LM_ARCH_PPC64LE => Ok(Self::PPC64LE),
            LM_ARCH_SPARC => Ok(Self::SPARC),
            LM_ARCH_SPARC64 => Ok(Self::SPARC64),
            LM_ARCH_SPARCEL => Ok(Self::SPARCEL),
            LM_ARCH_SYSZ => Ok(Self::SYSZ),
            _ => Err(()),
        }
    }
}

impl Into<lm_arch_t> for Arch {
    fn into(self) -> lm_arch_t {
        match self {
            Self::GENERIC => LM_ARCH_GENERIC,
            Self::ARMV7 => LM_ARCH_ARMV7,
            Self::ARMV8 => LM_ARCH_ARMV8,
            Self::THUMBV7 => LM_ARCH_THUMBV7,
            Self::THUMBV8 => LM_ARCH_THUMBV8,
            Self::ARMV7EB => LM_ARCH_ARMV7EB,
            Self::THUMBV7EB => LM_ARCH_THUMBV7EB,
            Self::ARMV8EB => LM_ARCH_ARMV8EB,
            Self::THUMBV8EB => LM_ARCH_THUMBV8EB,
            Self::AARCH64 => LM_ARCH_AARCH64,
            Self::MIPS => LM_ARCH_MIPS,
            Self::MIPS64 => LM_ARCH_MIPS64,
            Self::MIPSEL => LM_ARCH_MIPSEL,
            Self::MIPSEL64 => LM_ARCH_MIPSEL64,
            Self::X86_16 => LM_ARCH_X86_16,
            Self::X86 => LM_ARCH_X86,
            Self::X64 => LM_ARCH_X64,
            Self::PPC32 => LM_ARCH_PPC32,
            Self::PPC64 => LM_ARCH_PPC64,
            Self::PPC64LE => LM_ARCH_PPC64LE,
            Self::SPARC => LM_ARCH_SPARC,
            Self::SPARC64 => LM_ARCH_SPARC64,
            Self::SPARCEL => LM_ARCH_SPARCEL,
            Self::SYSZ => LM_ARCH_SYSZ,
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
pub use hook::*;
pub use memory::*;
pub use module::*;
pub use process::*;
pub use scan::*;
pub use segment::*;
pub use symbol::*;
pub use thread::*;
pub use vmt::*;
