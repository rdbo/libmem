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

typedef lm_bool_t (LM_CALL *lm_enum_processes_cb_t)(lm_process_t *process, lm_void_t *arg);

typedef struct {
	lm_enum_processes_cb_t callback;
	lm_void_t *arg;
} enum_processes_t;

BOOL
enum_processes_callback(PROCESSENTRY32W *entry, void *arg)
{
	lm_process_t process;
	WCHAR path[MAX_PATH + 1] = { 0 };

	enum_processes_t *parg = (enum_processes_t *)arg;

	process.pid = (lm_pid_t)entry->th32ProcessID;
	process.ppid = (lm_pid_t)entry->th32ParentProcessID;

	hproc = open_process(process.pid, PROCESS_QUERY_LIMITED_INFORMATION);
	if (!hproc)
		return TRUE;

	if (!wcstoutf8(entry->szExeFile, process.name, sizeof(process.name)))
		goto CLOSE_CONTINUE;

	if (!QueryFullProcessImageNameW(hproc, path, LM_ARRLEN(path)))
		goto CLOSE_CONTINUE;

	if (!wcstoutf8(path, process.path, sizeof(process.path)))
		goto CLOSE_CONTINUE;

	if (!get_process_start_time(hproc, &process.start_time))
		goto CLOSE_CONTINUE;

	process.bits = get_process_bits(hproc);

	if (!parg->callback(&process, parg->arg))
		return FALSE;

CLOSE_CONTINUE:
	close_handle(hproc);
	return TRUE;
}

LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *process,
					       lm_void_t    *arg),
		 lm_void_t          *arg)
{
	enum_processes_t parg;

	parg.callback = callback;
	parg.arg = arg;

	return enum_process_entries(enum_processes_callback, (void *)&parg) ? LM_TRUE : LM_FALSE;
}

/********************************/

typedef struct {
	lm_pid_t pid;
	PROCESSENTRY32W *entry;
} get_process_entry_t;

BOOL
get_process_entry_callback(PROCESSENTRY32W *entry, void *arg)
{
	get_process_entry_t *parg = (get_process_entry_t *)arg;

	if ((lm_pid_t)entry->th32ProcessID != parg->pid)
		return TRUE;

	*parg->entry = entry;

	return FALSE;
}

lm_bool_t
get_process_entry(lm_pid_t pid, PROCESSENTRY32W *entry)
{
	get_process_entry_t *parg;

	assert(pid != LM_PID_BAD && entry != NULL);

	parg.pid = pid;
	parg->entry = entry;
	parg->entry->th32ProcessID = LM_PID_BAD;

	enum_process_entries(get_process_entry_callback, (void *)&parg);

	return entry->th32ProcessID == pid ? LM_TRUE : LM_FALSE;
}

LM_API lm_bool_t LM_CALL
LM_GetProcess(lm_process_t *process_out)
{
	WCHAR path[MAX_PATH + 1] = { 0 };
	DWORD dwlen;
	PROCESSENTRY32W entry;
	
	process_out->pid = (lm_pid_t)GetCurrentProcessId();

	if (!get_process_entry(process_out->pid, &entry))
		return LM_FALSE;

	process_out->ppid = (lm_pid_t)entry.th32ParentProcessID;

	if (!wcstoutf8(entry.szExeFile, process.name, sizeof(process.name)))
		return LM_FALSE;

	dwlen = GetModuleFileNameW(NULL, path, LM_ARRLEN(path));
	if (dwlen == 0)
		return LM_FALSE;

	if (!wcstoutf8(path, process.path, sizeof(process.path)))
		return LM_FALSE;

	if (!get_process_start_time(GetCurrentProcess(), &process.start_time))
		return LM_FALSE;

	process.bits = sizeof(void *); /* Assume process bits == size of pointer */
}
