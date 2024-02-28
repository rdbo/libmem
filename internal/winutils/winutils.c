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
	if (WideCharToMultiByte(CP_UTF8, 0, utf8str, -1, wcsbuf, buflen) == 0) {
		if (is_allocated)
			free(wcsbuf);
		return NULL;
	}

	return wcsbuf;
}

HANDLE
open_process(DWORD pid)
{
	if (pid == GetCurrentProcessId())
		return GetCurrentProcess();

	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

void
close_handle(HANDLE handle)
{
	CloseHandle(handle);
}
