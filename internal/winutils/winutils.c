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

#include "winutils.h"
#include <assert.h>

/* NOTE: If 'utf8buf' is NULL, the function will allocate the
 *       string dynamically. It must be 'free'd by the caller. */
char *
wcstoutf8(WCHAR *widestr, char *utf8buf, size_t buflen)
{
	int is_allocated = 0;
	
	/* Either the UTF-8 buffer is NULL (string will be allocated), or it's not NULL and buflen > 0 */
	assert(widestr != NULL && (utf8buf == NULL || buflen > 0));

	if (utf8buf == NULL) {
		/*
		 * NOTE: When the 'cbMultiByte' is set to 0, the function will calculate
		 *       the required size in bytes to convert the string.
		 */
		buflen = WideCharToMultiByte(CP_UTF8, 0, widestr, -1, NULL, 0, NULL, NULL);
		utf8buf = malloc(buflen);
		is_allocated = 1;
	}

	/* This function automatically inserts the NULL terminator when passing -1 to 'cchWideChar' */
	if (WideCharToMultiByte(CP_UTF8, 0, widestr, -1, utf8buf, buflen, NULL, NULL) == 0) {
		if (is_allocated)
			free(utf8buf);
		return NULL;
	}

	return utf8buf;
}


/* NOTE: If 'utf8buf' is NULL, the function will allocate the
 *       string dynamically. It must be 'free'd by the caller. */
WCHAR *
utf8towcs(char *utf8str, WCHAR *wcsbuf, size_t buflen)
{
	int is_allocated = 0;

	/* Either the UTF-8 buffer is NULL (string will be allocated), or it's not NULL and buflen > 0 */
	assert(utf8str != NULL && (wcsbuf == NULL || buflen > 0));

	if (wcsbuf == NULL) {
		/*
		 * NOTE: When the 'cchWideChar' is set to 0, the function will calculate
		 *       the required size in characters to convert the string.
		 */
		buflen = MultiByteToWideChar(CP_UTF8, 0, utf8str, -1, NULL, 0);
		wcsbuf = malloc(buflen * 2); /* We need to multiply by 2 because the wchars are UTF-16 (2 bytes per wchar) */
		is_allocated = 1;
	}

	/* This function automatically inserts the NULL terminator when passing -1 to 'cchWideChar' */
	if (MultiByteToWideChar(CP_UTF8, 0, utf8str, -1, wcsbuf, buflen) == 0) {
		if (is_allocated)
			free(wcsbuf);
		return NULL;
	}

	return wcsbuf;
}

HANDLE
open_process(DWORD pid, DWORD access)
{
	if (pid == GetCurrentProcessId())
		return GetCurrentProcess();

	return OpenProcess(access, FALSE, pid);
}

void
close_handle(HANDLE handle)
{
	CloseHandle(handle);
}

size_t
get_system_bits()
{
	size_t bits = sizeof(void *); /* Assume system bits == process bits by default */
	SYSTEM_INFO sysinfo = { 0 };

	GetNativeSystemInfo(&sysinfo);
	switch (sysinfo.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_AMD64:
	case PROCESSOR_ARCHITECTURE_ARM64:
		bits = 64;
	}

	return bits;
}

size_t
get_process_bits(HANDLE hproc)
{
	BOOL is_wow64;
	size_t bits;

	assert(hproc != NULL);

	bits = get_system_bits();

	if (!IsWow64Process(hproc, &is_wow64))
		return bits;

	if (is_wow64)
		bits = 32;

	return bits;
}

uint64_t
filetime_to_number(FILETIME *filetime)
{
	uint64_t number = 0;

	assert(filetime != NULL);

	/* The filetime struct is not little endian, so we need to
	 * assign the low and high parts manually */
	((uint32_t *)&number)[1] = filetime->dwLowDateTime;
	((uint32_t *)&number)[0] = filetime->dwHighDateTime;

	return number;
}

BOOL
get_process_start_time(HANDLE hproc, uint64_t *timestamp_out)
{
	SYSTEM_TIMEOFDAY_INFORMATION systime;
	FILETIME creation_time;
	FILETIME tmp;
	uint64_t last_boot;
	uint64_t timestamp;

	assert(hproc != NULL && timestamp_out != NULL);

	/* Get the last boot time */
	if (NtQuerySystemInformation(SystemTimeOfDayInformation, &systime, sizeof(systime), NULL) != STATUS_SUCCESS)
		return FALSE;

	if (!GetProcessTimes(hproc, &creation_time, &tmp, &tmp, &tmp))
		return FALSE;

	last_boot = filetime_to_number((FILETIME *)&systime);
	timestamp = filetime_to_number(&creation_time) - last_boot;

	/* Convert timestamp to milliseconds */
	*timestamp_out = (uint64_t)(timestamp / 10000.0L);

	return TRUE;
}

BOOL
enum_process_entries(BOOL (*callback)(PROCESSENTRY32W *entry, void *arg), void *arg)
{
	BOOL result = FALSE;
	HANDLE hsnap;
	PROCESSENTRY32W entry;
	HANDLE hproc;

	assert(callback != NULL);

	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnap == INVALID_HANDLE_VALUE)
		return result;

	entry.dwSize = sizeof(entry);
	if (!Process32FirstW(hsnap, &entry))
		goto CLEAN_EXIT;

	do {
		if (!callback(&entry, arg))
			break;
	} while (Process32NextW(hsnap, &entry));

	result = TRUE;
CLEAN_EXIT:
	CloseHandle(hsnap);

	return result;
}
