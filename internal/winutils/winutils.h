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

#ifndef WINUTILS_H
#define WINUTILS_H

#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <windef.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <ntstatus.h>

char *
wcstoutf8(WCHAR *widestr, char *utf8buf, size_t buflen);

WCHAR *
utf8towcs(char *utf8str, WCHAR *wcsbuf, size_t buflen);

HANDLE
open_process(DWORD pid, DWORD access);

void
close_handle(HANDLE handle);

size_t
get_system_bits();

size_t
get_process_bits(HANDLE hproc);

BOOL
get_process_start_time(HANDLE hproc, uint64_t *timestamp_out);

BOOL
enum_process_entries(BOOL (*callback)(PROCESSENTRY32W *entry, void *arg), void *arg);

#endif
