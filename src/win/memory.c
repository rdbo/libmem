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

LM_API lm_size_t LM_CALL
LM_ReadMemoryEx(const lm_process_t *process,
		lm_address_t        source,
		lm_byte_t          *dest,
		lm_size_t           size)
{
	HANDLE hproc;
	SIZE_T bytes_read;

	if (!process || source == LM_ADDRESS_BAD || !dest || size == 0)
		return 0;

	hproc = open_process(process->pid, PROCESS_VM_READ);
	if (!hproc)
		return 0;

	if (!ReadProcessMemory(hproc, source, dest, size, &bytes_read))
		bytes_read = 0;

	close_handle(hproc);
	return (lm_size_t)bytes_read;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_WriteMemoryEx(const lm_process_t *process,
		 lm_address_t        dest,
		 lm_bytearray_t      source,
		 lm_size_t           size)
{
	HANDLE hproc;
	SIZE_T bytes_written;

	if (!process || dest == LM_ADDRESS_BAD || !source || size == 0)
		return 0;

	hproc = open_process(process->pid, PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
	if (!hproc)
		return 0;

	if (!WriteProcessMemory(hproc, dest, source, size, &bytes_written))
		bytes_written = 0;

	close_handle(hproc);
	return (lm_size_t)bytes_written;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_ProtMemory(lm_address_t address,
	      lm_size_t    size,
	      lm_prot_t    prot,
	      lm_prot_t   *oldprot_out)
{
	DWORD osprot;
	DWORD old_osprot;

	if (address == LM_ADDRESS_BAD || !LM_CHECK_PROT(prot))
		return LM_FALSE;

	osprot = get_os_prot(prot);
	if (!VirtualProtect(address, size, osprot, &old_osprot))
		return LM_FALSE;

	if (oldprot_out)
		*oldprot_out = get_prot(old_osprot);

	return LM_TRUE;
}

/********************************/

LM_API lm_address_t LM_CALL
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot)
{
	DWORD osprot;
	LPVOID alloc;
	
	if (!LM_CHECK_PROT(prot))
		return LM_ADDRESS_BAD;

	osprot = get_os_prot(prot);
	alloc = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, osprot);
	if (!alloc)
		return LM_ADDRESS_BAD;

	return (lm_address_t)alloc;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size)
{
	/*
	 * From https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree:
	 *
	 * "If the dwFreeType parameter is MEM_RELEASE, this parameter must be 0 (zero).
	 *  The function frees the entire region that is reserved in the initial
	 *  allocation call to VirtualAlloc."
	 */

	size = 0;
	return VirtualFree(alloc, size, MEM_RELEASE) ? LM_TRUE : LM_FALSE;
}
