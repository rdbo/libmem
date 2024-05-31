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
#include <posixutils/posixutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <libprocstat.h>
#include <dlfcn.h>

LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					       lm_void_t   *arg),
		 lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	struct procstat *ps;
	struct kinfo_proc *proc;
	struct kinfo_vmentry *vmmap;
	unsigned int count;
	unsigned int i;
	unsigned int j;
	lm_module_t module;
	
	if (!process || !callback)
		return result;

	ps = procstat_open_sysctl();
	if (!ps)
		return result;

	proc = procstat_getprocs(ps, KERN_PROC_PID, process->pid, &count);
	if (!proc)
		goto CLOSE_EXIT;

	vmmap = procstat_getvmmap(ps, proc, &count);
	procstat_freeprocs(ps, proc);
	if (!vmmap)
		goto CLOSE_EXIT;

	for (i = 0; i < count;) {
		if (strlen(vmmap[i].kve_path) == 0) {
			++i;
			continue;
		}

		module.base = (lm_address_t)vmmap[i].kve_start;
		module.end = (lm_address_t)vmmap[i].kve_end;
		snprintf(module.path, sizeof(module.path), "%s", vmmap[i].kve_path);

		/* Get maximum sequential address range for a module
		 * (similar to how the linux version of this API is done) */
		for (j = i + 1; j < count && (lm_address_t)vmmap[j].kve_start == module.end && !strcmp(vmmap[j].kve_path, module.path); ++j) {
			module.end = (lm_address_t)vmmap[j].kve_end;
		}

		module.size = module.end - module.base;
		get_name_from_path(module.path, module.name, sizeof(module.name));

		if (callback(&module, arg) == LM_FALSE)
			break;

		/* Skip to next module */
		i = j;
	}

	result = LM_TRUE;

	procstat_freevmmap(ps, vmmap);
CLOSE_EXIT:
	procstat_close(ps);
	return result;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_LoadModule(lm_string_t  path,
	      lm_module_t *module_out)
{
	if (!path)
		return LM_FALSE;
	
	if (!dlopen(path, RTLD_LAZY))
		return LM_FALSE;

	if (module_out)
		return LM_FindModule(path, module_out);

	return LM_TRUE;
}

/********************************/

lm_bool_t
find_dlfcn_module_callback(lm_module_t *module, lm_void_t *arg)
{
	static const char *name_matches[] = {
		"libc.", "libc-", "libdl.", "libdl-", "ld-musl-", "ld-musl."
	};
	size_t i;
	size_t len;

	for (i = 0; i < LM_ARRLEN(name_matches); ++i) {
		len = strlen(name_matches[i]);
		if (!strncmp(module->name, name_matches[i], len)) {
			*(lm_module_t *)arg = *module;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

lm_bool_t
find_dlopen_symbol_callback(lm_symbol_t *symbol, lm_void_t *arg)
{
	static const char *symbol_matches[] = {
		"__libc_dlopen_mode", "dlopen"
	};
	size_t i;

	for (i = 0; i < LM_ARRLEN(symbol_matches); ++i) {
		if (!strcmp(symbol->name, symbol_matches[i])) {
			*(lm_address_t *)arg = symbol->address;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_LoadModuleEx(const lm_process_t *process,
		lm_string_t         path,
		lm_module_t        *module_out)
{
	lm_bool_t ret = LM_FALSE;
	lm_module_t dlopen_mod;
	lm_address_t dlopen_addr = LM_ADDRESS_BAD;
	size_t path_size;
	lm_address_t path_addr;
	ptrace_libcall_t ptlib;
	long call_ret;

	if (!process || !path)
		return ret;

	dlopen_mod.base = LM_ADDRESS_BAD;
	LM_EnumModulesEx(process, find_dlfcn_module_callback, &dlopen_mod);
	if (dlopen_mod.base == LM_ADDRESS_BAD)
		return ret;

	LM_EnumSymbols(&dlopen_mod, find_dlopen_symbol_callback, &dlopen_addr);
	if (dlopen_addr == LM_ADDRESS_BAD)
		return ret;

	path_size = (strlen(path) + 1) * sizeof(char);
	path_addr = LM_AllocMemoryEx(process, path_size, LM_PROT_RW);
	if (path_addr == LM_ADDRESS_BAD)
		return ret;

	if (LM_WriteMemoryEx(process, path_addr, path, path_size) != path_size)
		goto FREE_EXIT;

	/* Setup arguments both on the stack and on registers to prevent possible issues */
	ptlib.address = dlopen_addr;
	ptlib.args[0] = path_addr;
	ptlib.args[1] = RTLD_LAZY;
	if (process->bits == 64) {
		*(uint64_t *)&ptlib.stack[0] = (uint64_t)path_addr;
		*(int32_t *)&ptlib.stack[8] = (int32_t)RTLD_LAZY;
	} else {
		*(uint32_t *)&ptlib.stack[0] = (uint32_t)path_addr;
		*(int32_t *)&ptlib.stack[4] = (int32_t)RTLD_LAZY;
	}

	if (ptrace_attach(process->pid))
		goto FREE_EXIT;

	call_ret = ptrace_libcall(process->pid, process->bits, &ptlib);
	if (call_ret == -1 || call_ret == 0)
		goto DETACH_EXIT;

	if (module_out) {
		lm_char_t *name;

		/* NOTE: We search by name instead of path because the path can be misleading,
		 *       having for example `../` and similar */
		name = strrchr(path, '/');
		ret = LM_FindModuleEx(process, name, module_out);
	} else {
		ret = LM_TRUE;
	}
DETACH_EXIT:
	ptrace_detach(process->pid);
FREE_EXIT:
	LM_FreeMemoryEx(process, path_addr, path_size);
	return ret;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module)
{
	void *handle;

	if (!module)
		return LM_FALSE;

	handle = dlopen(module->path, RTLD_NOLOAD); /* Increases the reference count by 1 */
	if (!handle)
		return LM_FALSE;

	/* Decrease the reference count and possibly force the module to unload */
	/* NOTE: It is not guaranteed that the module will unload after this! */
	dlclose(handle);
	dlclose(handle);

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_UnloadModuleEx(const lm_process_t *process,
		  const lm_module_t  *module)
{
	/* TODO: Implement */
	return LM_FALSE;
}
