LM_API lm_bool_t
LM_EnumModules(lm_bool_t(*callback)(lm_module_t  mod,
				    lm_tstring_t path,
				    lm_void_t   *arg),
	       lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	lm_process_t proc;

	LM_ASSERT(callback != LM_NULLPTR);

	if (LM_OpenProcess(&proc)) {
		ret = LM_EnumModulesEx(proc, callback, arg);
		LM_CloseProcess(&proc);
	}

	return ret;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumModulesEx(lm_process_t proc,
		  lm_bool_t  (*callback)(lm_module_t  mod,
					 lm_tstring_t path,
					 lm_void_t   *arg),
		  lm_void_t   *arg)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	MODULEENTRY32 entry;

	hSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		proc.pid
	);

	if (hSnap == INVALID_HANDLE_VALUE)
		return ret;

	entry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &entry)) {
		do {
			lm_module_t mod;

			mod.base = (lm_address_t)(
				entry.modBaseAddr
			);
			mod.size = (lm_size_t)(
				entry.modBaseSize
			);
			mod.end  = (lm_address_t)(
				&((lm_byte_t *)mod.base)[mod.size]
			);

			if (callback(mod, entry.szExePath, arg) == LM_FALSE)
				break;
		} while (Module32Next(hSnap, &entry));

		ret = LM_TRUE;
	}

	CloseHandle(hSnap);

	return ret;
}
#else
LM_PRIVATE lm_bool_t
_LM_EnumModulesEx(lm_process_t proc,
		  lm_bool_t  (*callback)(lm_module_t  mod,
					 lm_tstring_t path,
					 lm_void_t   *arg),
		  lm_void_t   *arg)
{
	lm_bool_t   ret = LM_FALSE;
	lm_tchar_t *maps_buf;
	lm_tchar_t *ptr;
	lm_tchar_t  maps_path[LM_PATH_MAX] = { 0 };

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/maps"), LM_PROCFS, proc.pid);
#	elif LM_OS == LM_OS_BSD
	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/map"), LM_PROCFS, proc.pid);
#	endif
		
	if (!_LM_OpenFileBuf(maps_path, &maps_buf))
		return ret;

	ret = LM_TRUE;

	for (ptr = maps_buf;
	     ptr && (ptr = LM_STRCHR(ptr, LM_STR('/')));
	     ptr = LM_STRCHR(ptr, LM_STR('\n'))) {
		lm_tchar_t *tmp;
		lm_tchar_t *holder;
		lm_tchar_t *path;
		lm_size_t   pathlen;
		lm_module_t mod;

		tmp = LM_STRCHR(ptr, LM_STR('\n'));

#		if LM_OS == LM_OS_BSD
		{
			lm_tchar_t *tmp2;
			lm_size_t i;
			holder = tmp;

			for (i = 0; i < 2; ++i) {
				for (tmp2 = ptr;
				     (lm_uintptr_t)(
				        tmp2 = LM_STRCHR(tmp2,
							 LM_STR(' '))
				     ) < (lm_uintptr_t)tmp;
				     tmp2 = &tmp2[1])
					holder = tmp2;

				tmp = holder;
			}
		}
#		endif
		pathlen = (lm_size_t)(
			((lm_uintptr_t)tmp - (lm_uintptr_t)ptr) /
			sizeof(tmp[0])
		);
		
		path = (lm_tchar_t *)LM_CALLOC(pathlen + 1,
					       sizeof(lm_tchar_t));
		if (!path) {
			ret = LM_FALSE;
			break;
		}

		LM_STRNCPY(path, ptr, pathlen);
		path[pathlen] = LM_STR('\x00');

		holder = maps_buf;
		for (tmp = maps_buf;
		     (lm_uintptr_t)(
			     tmp = LM_STRCHR(tmp, LM_STR('\n'))
		     ) < (lm_uintptr_t)ptr;
		     tmp = &tmp[1])
			holder = &tmp[1];
		
		mod.base = (lm_address_t)LM_STRTOP(holder, NULL, 16);

		holder = ptr;
		for (tmp = ptr;
		     (tmp = LM_STRCHR(tmp, LM_STR('\n'))) &&
		     (tmp = LM_STRCHR(tmp, LM_STR('/')));
		     tmp = &tmp[1]) {
			if (LM_STRNCMP(tmp, path, pathlen))
				break;
			holder = tmp;
		}
		
		ptr = holder;

		holder = maps_buf;
		for (tmp = maps_buf;
		     (lm_uintptr_t)(
			     tmp = LM_STRCHR(tmp, LM_STR('\n'))
		     ) < (lm_uintptr_t)ptr;
		     tmp = &tmp[1])
			holder = &tmp[1];

#		if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
		holder = LM_STRCHR(holder, LM_STR('-'));
#		elif LM_OS == LM_OS_BSD
		holder = LM_STRSTR(holder, LM_STR(" 0x"));
#		endif
		holder = &holder[1];

		mod.end = (lm_address_t)LM_STRTOP(holder, NULL, 16);
		mod.size = (
			(lm_uintptr_t)mod.end - (lm_uintptr_t)mod.base
		);

		{
			lm_bool_t cbret;

			cbret = callback(mod, path, arg);
			LM_FREE(path);

			if (cbret == LM_FALSE)
				break;
		}
	}

	_LM_CloseFileBuf(&maps_buf);

	return ret;
}
#endif

LM_API lm_bool_t
LM_EnumModulesEx(lm_process_t proc,
		 lm_bool_t  (*callback)(lm_module_t  mod,
					lm_tstring_t path,
					lm_void_t   *arg),
		 lm_void_t   *arg)
{
	LM_ASSERT(_LM_ValidProcess(proc) && callback != LM_NULLPTR);

	return _LM_EnumModulesEx(proc, callback, arg);
}

/********************************/

typedef struct {
	lm_module_t *modbuf;
	lm_void_t   *modarg;
	lm_size_t    len;
	lm_int_t     flags;
} _lm_get_mod_t;

LM_PRIVATE lm_bool_t
_LM_GetModuleCallback(lm_module_t  mod,
		      lm_tstring_t path,
		      lm_void_t   *arg)
{
	_lm_get_mod_t *parg = (_lm_get_mod_t *)arg;

	switch (parg->flags) {
	case LM_MOD_BY_STR:
		{
			lm_tstring_t modstr = (lm_tstring_t)parg->modarg;
			lm_size_t pathlen;

			pathlen = LM_STRLEN(path);

			if (pathlen >= parg->len) {
				if (!LM_STRCMP(&path[pathlen - parg->len],
					       modstr)) {
					*(parg->modbuf) = mod;
					return LM_FALSE;
				}
			}

			break;
		}

	case LM_MOD_BY_ADDR:
		{
			lm_address_t addr = (lm_address_t)parg->modarg;

			if ((lm_uintptr_t)addr >= (lm_uintptr_t)mod.base &&
			    (lm_uintptr_t)addr < (lm_uintptr_t)mod.end) {
				*(parg->modbuf) = mod;
				return LM_FALSE;
			}

			break;
		}
	default:
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_bool_t
LM_GetModule(lm_int_t     flags,
	     lm_void_t   *modarg,
	     lm_module_t *modbuf)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_mod_t arg;

	LM_ASSERT(modarg != LM_NULLPTR && modbuf != LM_NULLPTR);

	arg.modbuf = modbuf;
	arg.modbuf->base = LM_ADDRESS_BAD;
	arg.modbuf->size = 0;
	arg.modbuf->end  = LM_ADDRESS_BAD;
	arg.modarg = modarg;
	arg.flags  = flags;

	if (flags == LM_MOD_BY_STR)
		arg.len = LM_STRLEN((lm_tstring_t)arg.modarg);

	ret = LM_EnumModules(_LM_GetModuleCallback, (lm_void_t *)&arg);
	if (ret && arg.modbuf->size == 0)
		ret = LM_FALSE;

	return ret;
}

/********************************/

LM_API lm_bool_t
LM_GetModuleEx(lm_process_t proc,
	       lm_int_t     flags,
	       lm_void_t   *modarg,
	       lm_module_t *modbuf)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_mod_t arg;

	LM_ASSERT(modarg != LM_NULLPTR && modbuf != LM_NULLPTR);

	arg.modbuf = modbuf;
	arg.modbuf->base = LM_ADDRESS_BAD;
	arg.modbuf->size = 0;
	arg.modbuf->end  = LM_ADDRESS_BAD;
	arg.modarg = modarg;
	arg.flags  = flags;

	if (flags == LM_MOD_BY_STR)
		arg.len = LM_STRLEN((lm_tstring_t)arg.modarg);

	ret = LM_EnumModulesEx(proc, _LM_GetModuleCallback, (lm_void_t *)&arg);
	if (ret && arg.modbuf->size == 0)
		ret = LM_FALSE;

	return ret;
}


/********************************/

typedef struct {
	lm_module_t  mod;
	lm_tstring_t pathbuf;
	lm_size_t    maxlen;
	lm_size_t    len;
} _lm_get_mod_path_t;

LM_PRIVATE lm_bool_t
_LM_GetModulePathCallback(lm_module_t  mod,
			  lm_tstring_t path,
			  lm_void_t   *arg)
{
	_lm_get_mod_path_t *parg = (_lm_get_mod_path_t *)arg;
	
	if (parg->mod.base == mod.base) {
		parg->len = LM_STRLEN(path);
		if (parg->len >= parg->maxlen)
			parg->len = parg->maxlen - 1;
		LM_STRNCPY(parg->pathbuf, path, parg->len);
		parg->pathbuf[parg->len] = LM_STR('\x00');
	}

	return LM_TRUE;
}

LM_API lm_size_t
LM_GetModulePath(lm_module_t mod,
		 lm_tchar_t *pathbuf,
		 lm_size_t   maxlen)
{
	_lm_get_mod_path_t arg;

	LM_ASSERT(pathbuf != LM_NULLPTR && maxlen > 0);

	arg.mod     = mod;
	arg.pathbuf = pathbuf;
	arg.maxlen  = maxlen;
	arg.len     = 0;

	LM_EnumModules(_LM_GetModulePathCallback, (lm_void_t *)&arg);

	return arg.len;
}

/********************************/

LM_API lm_size_t
LM_GetModulePathEx(lm_process_t proc,
		   lm_module_t  mod,
		   lm_tchar_t  *pathbuf,
		   lm_size_t    maxlen)
{
	_lm_get_mod_path_t arg;

	LM_ASSERT(pathbuf != LM_NULLPTR && maxlen > 0);
	
	arg.mod     = mod;
	arg.pathbuf = pathbuf;
	arg.maxlen  = maxlen;
	arg.len     = 0;

	LM_EnumModulesEx(proc, _LM_GetModulePathCallback, (lm_void_t *)&arg);

	return arg.len;
}

/********************************/

LM_API lm_size_t
LM_GetModuleName(lm_module_t mod,
		 lm_tchar_t *namebuf,
		 lm_size_t   maxlen)
{
	lm_size_t   len = 0;
	lm_tchar_t  path[LM_PATH_MAX];
	lm_tchar_t *holder;

	LM_ASSERT(namebuf != LM_NULLPTR && maxlen > 0);

	if (!LM_GetModulePath(mod, path, LM_PATH_MAX))
		return len;

	holder = LM_STRRCHR(path, LM_PATH_SEP);

	len = LM_STRLEN(holder);
	if (len >= maxlen)
		len = maxlen - 1;

	LM_STRNCPY(namebuf, holder, len);
	namebuf[len] = LM_STR('\x00');

	return len;
}

/********************************/

LM_API lm_size_t
LM_GetModuleNameEx(lm_process_t proc,
		   lm_module_t  mod,
		   lm_tchar_t  *namebuf,
		   lm_size_t    maxlen)
{
	lm_size_t   len = 0;
	lm_tchar_t  path[LM_PATH_MAX];
	lm_tchar_t *holder;

	LM_ASSERT(_LM_ValidProcess(proc) &&
		  namebuf != LM_NULLPTR &&
		  maxlen > 0);

	if (!LM_GetModulePathEx(proc, mod, path, LM_PATH_MAX))
		return len;

	holder = LM_STRRCHR(path, LM_PATH_SEP);

	len = LM_STRLEN(holder);
	if (len >= maxlen)
		len = maxlen - 1;

	LM_STRNCPY(namebuf, holder, len);
	namebuf[len] = LM_STR('\x00');

	return len;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_LoadModule(lm_tstring_t path,
	       lm_module_t *modbuf)
{
	if (!LoadLibrary(path))
		return LM_FALSE;

	if (modbuf && !LM_GetModule(LM_MOD_BY_STR, path, modbuf))
		return LM_FALSE;

	return LM_TRUE;
}
#else
LM_PRIVATE lm_bool_t
_LM_LoadModule(lm_tstring_t path,
	       lm_module_t *modbuf)
{
	if (!dlopen(path, RTLD_LAZY))
		return LM_FALSE;

	if (modbuf && !LM_GetModule(LM_MOD_BY_STR, path, modbuf))
		return LM_FALSE;

	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_LoadModule(lm_tstring_t path,
	      lm_module_t *modbuf)
{
	/* modbuf can be NULL. in that case, the module info won't be saved */
	LM_ASSERT(path != LM_NULLPTR);

	return _LM_LoadModule(path, modbuf);
}

/********************************/

LM_API lm_bool_t
LM_LoadModuleEx(lm_process_t proc,
		lm_tstring_t path,
		lm_module_t *modbuf)
{
	/* TODO: Reimplement */
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_UnloadModule(lm_module_t mod)
{
	HMODULE hModule;

	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
			  (LPTSTR)mod.base, &hModule);

	if (!hModule)
		return LM_FALSE:

	FreeLibrary(hModule);
	return LM_TRUE;
}
#else
LM_PRIVATE lm_bool_t
_LM_UnloadModule(lm_module_t mod)
{
	lm_tchar_t libpath[LM_PATH_MAX];
	void *libhandle;

	if (!LM_GetModulePath(mod, libpath, LM_PATH_MAX))
		return LM_FALSE;

	/* reopen the library without loading, which gives us the
	   handle that we can use to decrease the reference count
	   and unload the library */
	libhandle = dlopen(libpath, RTLD_NOLOAD);

	if (!libhandle)
		return LM_FALSE;

	dlclose(libhandle);
	dlclose(libhandle);

	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_UnloadModule(lm_module_t mod)
{
	return _LM_UnloadModule(mod);
}

/********************************/

LM_API lm_bool_t
LM_UnloadModuleEx(lm_process_t proc,
		  lm_module_t  mod)
{
	/* TODO: Implement */
}

