#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumModulesEx(const lm_process_t *pproc,
		  lm_bool_t (LM_CALL *callback)(lm_module_t *pmod,
						lm_void_t   *arg),
		  lm_void_t          *arg)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	MODULEENTRY32 entry;
	lm_module_t mod;
	lm_size_t path_len;

	hSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		pproc->pid
	);

	if (hSnap == INVALID_HANDLE_VALUE)
		return ret;

	entry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &entry)) {
		do {
			mod.base = (lm_address_t)entry.modBaseAddr;
			mod.size = (lm_size_t)entry.modBaseSize;
			mod.end  = (lm_address_t)LM_OFFSET(mod.base, mod.size);
			path_len = LM_STRLEN(entry.szExePath);
			if (path_len >= LM_ARRLEN(mod.path))
				path_len = LM_ARRLEN(mod.path) - 1;

			LM_STRNCPY(mod.path, entry.szExePath, path_len);
			mod.path[path_len] = LM_STR('\x00');
			_LM_GetNameFromPath(mod.path, mod.name, LM_ARRLEN(mod.name));

			if (callback(&mod, arg) == LM_FALSE)
				break;
		} while (Module32Next(hSnap, &entry));

		ret = LM_TRUE;
	}

	CloseHandle(hSnap);

	return ret;
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_LoadModule(lm_string_t path)
{
	return LoadLibrary(path) ? LM_TRUE : LM_FALSE;
}
