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

#include <libmem/libmem.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

LM_API lm_bool_t LM_CALL
LM_EnumThreadsEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					       lm_void_t   *arg),
		 lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	HANDLE hsnap;
	THREADENTRY32 entry;
	lm_thread_t thread;

	if (!process || !callback)
		return result;

	/*
	 * NOTE: You can't use the 'th32ProcessID' parameter to get only
	 *       threads from a specific process:
	 * From: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	 *
	 * "To identify the threads that belong to a specific process, compare its process identifier
	 *  to the th32OwnerProcessID member of the THREADENTRY32 structure when enumerating the threads."
	 *
	 * "[in] th32ProcessID
	 * ...
	 * This parameter is used when the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE,
	 * TH32CS_SNAPMODULE32, or TH32CS_SNAPALL value is specified. Otherwise,
	 * it is ignored and all processes are included in the snapshot."
	 */

	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hsnap == INVALID_HANDLE_VALUE)
		return result;

	entry.dwSize = sizeof(entry);
	if (!Thread32First(hsnap, &entry))
		goto CLOSE_EXIT;

	thread.owner_pid = process->pid;
	do {
		if (entry.th32OwnerProcessID != process->pid)
			continue;

		thread.tid = (lm_tid_t)entry.th32ThreadID;

		if (callback(&thread, arg) == LM_FALSE)
			break;
	} while (Thread32Next(hsnap, &entry));

	result = LM_TRUE;
CLOSE_EXIT:
	CloseHandle(hsnap);
	return result;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetThread(lm_thread_t *thread_out)
{
	if (!thread_out)
		return LM_FALSE;

	thread_out->tid = (lm_tid_t)GetCurrentThreadId();
	thread_out->owner_pid = (lm_pid_t)GetCurrentProcessId();

	return LM_TRUE;
}
