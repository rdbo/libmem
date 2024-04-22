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

use libmem_sys::{self, lm_process_t, LM_TRUE};
use std::mem::MaybeUninit;

pub fn get_process() -> Option<lm_process_t> {
    let mut process: MaybeUninit<lm_process_t> = MaybeUninit::uninit();
    unsafe {
        if libmem_sys::LM_GetProcess(process.as_mut_ptr()) == LM_TRUE {
            Some(process.assume_init())
        } else {
            None
        }
    }
}
