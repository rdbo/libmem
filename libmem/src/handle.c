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

#include "internal.h"

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_OpenProc(lm_pid_t      pid,
	     HANDLE       *hProcess)
{
	DWORD exit_code;

	LM_ASSERT(pid != LM_PID_BAD && hProcess != LM_NULLPTR);

	if (pid == GetCurrentProcessId()) {
		*hProcess = GetCurrentProcess();
		return LM_TRUE
	} else {
		*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

		/* the process is dead, but can still open handles */
		if (*hProcess && GetExitCodeProcess(*hProcess) && exit_code != STILL_ACTIVE) {
			CloseHandle(*hProcess);
			*hProcess = NULL;
		}
	}

	return hProcess ? LM_TRUE : LM_FALSE;
}

LM_PRIVATE lm_void_t
_LM_CloseProc(HANDLE *hProcess)
{
	LM_ASSERT(hProcess != LM_NULLPTR);

	if (*hProcess)
		CloseHandle(*hProcess);

	*hProcess = NULL;
}
#endif
