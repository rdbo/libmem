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
#include <winutils/winutils.h>

LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *process,
					       lm_void_t    *arg),
		 lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	HANDLE hsnap;
	PROCESSENTRY32W entry;
	lm_process_t process;
	HANDLE hproc;
	WCHAR path[MAX_PATH + 1] = { 0 };

	if (!callback)
		return result;

	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnap == INVALID_HANDLE_VALUE)
		return result;

	entry.dwSize = sizeof(entry);
	if (!Process32FirstW(hsnap, &entry))
		goto CLEAN_EXIT;

	do {
		process.pid = (lm_pid_t)entry.th32ProcessID;
		process.ppid = (lm_pid_t)entry.th32ParentProcessID;

		hproc = open_process(process.pid, PROCESS_QUERY_LIMITED_INFORMATION);
		if (!hproc)
			continue;

		if (!wcstoutf8(entry.szExeFile, process.name, sizeof(process.name)))
			goto CLOSE_CONTINUE;

		if (!QueryFullProcessImageNameW(hproc, path, LM_ARRLEN(path)))
			goto CLOSE_CONTINUE;

		if (!wcstoutf8(path, process.path, sizeof(process.path)))
			goto CLOSE_CONTINUE;

		if (!get_process_start_time(hproc, &process.start_time))
			goto CLOSE_CONTINUE;

		process.bits = get_process_bits(hproc);

		if (!callback(&process, arg))
			break;

	CLOSE_CONTINUE:
		close_handle(hproc);
	} while (Process32NextW(hsnap, &entry));

	ret = LM_TRUE;
CLEAN_EXIT:
	CloseHandle(hsnap);

	return ret;
}

/********************************/

