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

/* TODO: Perhaps make abstraction for getting a 'lm_process_t' with a PROCESSENTRY32W,
 *       since that happens pretty often */

#include <libmem/libmem.h>
#include <winutils/winutils.h>
#include <arch/arch.h>
#include <assert.h>

typedef struct {
	lm_bool_t (LM_CALL *callback)(lm_process_t *, lm_void_t *);
	lm_void_t *arg;
} enum_processes_t;

BOOL
enum_processes_callback(PROCESSENTRY32W *entry, void *arg)
{
	lm_process_t process;
	HANDLE hproc;
	WCHAR path[MAX_PATH + 1] = { 0 };
	DWORD path_len = LM_ARRLEN(path);
	enum_processes_t *parg = (enum_processes_t *)arg;

	assert(entry != NULL && parg != NULL);

	process.pid = (lm_pid_t)entry->th32ProcessID;
	process.ppid = (lm_pid_t)entry->th32ParentProcessID;

	hproc = open_process(process.pid, PROCESS_QUERY_LIMITED_INFORMATION);
	if (!hproc)
		return TRUE;

	if (!wcstoutf8(entry->szExeFile, process.name, sizeof(process.name)))
		goto CLOSE_CONTINUE;

	if (!QueryFullProcessImageNameW(hproc, 0, path, &path_len))
		goto CLOSE_CONTINUE;

	if (!wcstoutf8(path, process.path, sizeof(process.path)))
		goto CLOSE_CONTINUE;

	if (!get_process_start_time(hproc, &process.start_time))
		goto CLOSE_CONTINUE;

	process.bits = get_process_bits(hproc);
	process.arch = get_architecture_from_bits(process.bits);

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

	if (!callback)
		return LM_FALSE;

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

	assert(entry != NULL && parg != NULL);

	if ((lm_pid_t)entry->th32ProcessID != parg->pid)
		return TRUE;

	*parg->entry = *entry;

	return FALSE;
}

lm_bool_t
get_process_entry(lm_pid_t pid, PROCESSENTRY32W *entry)
{
	get_process_entry_t parg;

	assert(pid != LM_PID_BAD && entry != NULL);

	parg.pid = pid;
	parg.entry = entry;
	parg.entry->th32ProcessID = LM_PID_BAD;

	enum_process_entries(get_process_entry_callback, (void *)&parg);

	return entry->th32ProcessID == pid ? LM_TRUE : LM_FALSE;
}

LM_API lm_bool_t LM_CALL
LM_GetProcess(lm_process_t *process_out)
{
	WCHAR path[MAX_PATH + 1] = { 0 };
	PROCESSENTRY32W entry;

	if (!process_out)
		return LM_FALSE;
	
	process_out->pid = (lm_pid_t)GetCurrentProcessId();

	if (!get_process_entry(process_out->pid, &entry))
		return LM_FALSE;

	process_out->ppid = (lm_pid_t)entry.th32ParentProcessID;

	if (!wcstoutf8(entry.szExeFile, process_out->name, sizeof(process_out->name)))
		return LM_FALSE;

	if (GetModuleFileNameW(NULL, path, LM_ARRLEN(path)) == 0)
		return LM_FALSE;

	if (!wcstoutf8(path, process_out->path, sizeof(process_out->path)))
		return LM_FALSE;

	if (!get_process_start_time(GetCurrentProcess(), &process_out->start_time))
		return LM_FALSE;

	process_out->bits = LM_GetBits(); /* Assume process bits == size of pointer */
	process_out->arch = get_architecture_from_bits(process_out->bits);

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *process_out)
{
	lm_bool_t result = LM_FALSE;
	WCHAR path[MAX_PATH + 1] = { 0 };
	DWORD path_len = LM_ARRLEN(path);
	PROCESSENTRY32W entry;
	HANDLE hproc;

	if (pid == LM_PID_BAD || !process_out)
		return LM_FALSE;
	
	process_out->pid = pid;

	hproc = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION);
	if (!hproc)
		return LM_FALSE;

	if (!get_process_entry(process_out->pid, &entry))
		goto CLEAN_EXIT;

	process_out->ppid = (lm_pid_t)entry.th32ParentProcessID;

	if (!wcstoutf8(entry.szExeFile, process_out->name, sizeof(process_out->name)))
		goto CLEAN_EXIT;

	if (!QueryFullProcessImageNameW(hproc, 0, path, &path_len))
		goto CLEAN_EXIT;

	if (!wcstoutf8(path, process_out->path, sizeof(process_out->path)))
		goto CLEAN_EXIT;

	if (!get_process_start_time(GetCurrentProcess(), &process_out->start_time))
		goto CLEAN_EXIT;

	process_out->bits = get_process_bits(hproc);
	process_out->arch = get_architecture_from_bits(process_out->bits);

	result = LM_TRUE;
CLEAN_EXIT:
	close_handle(hproc);
	return result;
}

/********************************/

LM_API lm_char_t ** LM_CALL
LM_GetCommandLine(lm_process_t *process)
{
	LPWSTR wcmdline;
	LPWSTR *wcmdargs;
	int argc;
	size_t len = 0;
	size_t cmdlen = 0;
	lm_char_t *cmdline;
	lm_void_t *ptr;
	lm_char_t **cmdargs = NULL;
	int i;

	if (process->pid = (lm_pid_t)GetCurrentProcessId()) {
		wcmdline = GetCommandLineW();
	} else {
		return NULL; // Unsupported for now. May be possible by running
		             // GetCommandLineW on the target process through
		             // CreateRemoteThread and then reading 8191 bytes
		             // from there (maximum command line length).
		             // NOTE: If this is to be supported, one should
		             //       not forget to free the wcmdline buffer
		             //       *only* for external processes.
	}

	wcmdargs = CommandLineToArgvW(wcmdline, &argc);
	if (!wcmdargs)
		return NULL;

	cmdargs = calloc((size_t)argc + 1, sizeof(lm_char_t *));
	if (!cmdargs)
		goto FREE_EXIT;

	for (i = 0; i < argc; ++i) {
		len = wcslen(wcmdargs[i]) + 1; // we will include the null terminator in the length
		ptr = cmdline;
		cmdline = realloc(cmdline, (cmdlen + len) * sizeof(lm_char_t));
		if (!cmdline) {
			if (ptr) free(ptr);
			goto FREE_EXIT2;
		}

		if (!wcstoutf8(wcmdargs[i], &cmdline[cmdlen], len)) {
			free(cmdline);
			goto FREE_EXIT2;
		}

		cmdargs[i] = &cmdline[cmdlen];

		cmdlen += len;
	}

	cmdargs[i] = NULL;

	if (cmdlen == 0) {
		free(cmdline);
		goto FREE_EXIT2;
	}

	goto FREE_EXIT;
FREE_EXIT2:
	free(cmdargs);
	cmdargs = NULL;
FREE_EXIT:
	LocalFree(wcmdargs);
	return cmdargs;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_GetSystemBits()
{
	return (lm_size_t)get_system_bits();
}
