/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2022    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <ntstatus.h>

LM_PRIVATE lm_bool_t
_LM_OpenProc(lm_pid_t pid,
	     HANDLE  *hProcess);

LM_PRIVATE lm_void_t
_LM_CloseProc(HANDLE *handle);

LM_PRIVATE lm_size_t
_LM_GetProcessBitsEx(lm_pid_t pid);

LM_PRIVATE lm_bool_t
_LM_OpenThr(lm_tid_t tid,
	    HANDLE  *hThread);

LM_PRIVATE lm_void_t
_LM_CloseThr(HANDLE *hThread);
