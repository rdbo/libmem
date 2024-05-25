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
pub mod symbol;
pub mod thread;

use libmem_sys::{lm_address_t, lm_pid_t, lm_tid_t, lm_time_t};

pub type Pid = lm_pid_t;
pub type Tid = lm_tid_t;
pub type Time = lm_time_t;
pub type Address = lm_address_t;

pub use module::*;
pub use process::*;
pub use symbol::*;
pub use thread::*;
