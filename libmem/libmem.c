/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

#include "libmem.h"

#if LM_COMPATIBLE
/* Additional Types */
typedef struct {
	lm_pid_t     pid;
	lm_tstring_t procstr;
	lm_size_t    len;
} _lm_get_pid_t;

typedef struct {
	lm_module_t *modbuf;
	lm_void_t   *modarg;
	lm_size_t    len;
	lm_int_t     flags;
} _lm_get_mod_t;

typedef struct {
	lm_module_t  mod;
	lm_tstring_t pathbuf;
	lm_size_t    maxlen;
	lm_size_t    len;
} _lm_get_mod_path_t;

typedef struct {
	lm_address_t addr;
	lm_page_t   *pagebuf;
} _lm_get_page_t;

typedef struct {
	lm_cstring_t symbol;
	lm_address_t addr;
} _lm_get_symbol_t;

typedef struct {
	lm_pid_t  pid;
	lm_bool_t check;
} _lm_check_process_t;

/* Helpers */
static lm_bool_t
_LM_ValidProcess(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

	if (proc.pid == (lm_pid_t)LM_BAD)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (proc.pid != LM_GetProcessId() && !proc.handle)
			return ret;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		
	}
#	endif

	ret = LM_TRUE;

	return ret;
}

static lm_bool_t
_LM_ParseSig(lm_tstring_t  sig,
	     lm_bstring_t *ppattern,
	     lm_tstring_t *pmask)
{
	lm_bool_t    ret = LM_FALSE;
	lm_byte_t   *pattern = (lm_byte_t *)LM_NULL;
	lm_tchar_t  *mask = (lm_tchar_t *)LM_NULL;
	lm_size_t    len = 0;
	lm_tchar_t  *ptr;
	
	for (ptr = sig; ptr; ptr = LM_STRCHR(ptr, LM_STR(' '))) {
		lm_byte_t  *old_pattern = pattern;
		lm_tchar_t *old_mask = mask;
		lm_byte_t   curbyte = 0;
		lm_tchar_t  curchar = LM_MASK_UNKNOWN;

		pattern = LM_CALLOC(len + 1, sizeof(lm_byte_t));
		if (old_pattern) {
			if (pattern)
				LM_MEMCPY(pattern, old_pattern, len * sizeof(lm_byte_t));
			LM_FREE(old_pattern);
		}

		if (!pattern) {
			if (mask)
				LM_FREE(mask);
			return ret;
		}

		mask = LM_CALLOC(len + 2, sizeof(lm_tchar_t));
		if (old_mask) {
			if (mask)
				LM_STRNCPY(mask, old_mask, len);
			
			LM_FREE(old_mask);
		}

		if (!mask) {
			LM_FREE(pattern);
			return ret;
		}

		if (ptr != sig)
			ptr = &ptr[1];
		
		if (!LM_RCHKMASK(*ptr)) {
			curbyte = (lm_byte_t)LM_STRTOP(ptr, NULL, 16);
			curchar = LM_MASK_KNOWN;
		}

		pattern[len] = curbyte;
		mask[len++] = curchar;
		mask[len] = LM_STR('\x00');
	}

	*ppattern = pattern;
	*pmask = mask;
	ret = LM_TRUE;
	
	return ret;
}

static lm_size_t
_LM_DetourPayload(lm_address_t src,
		  lm_address_t dst,
		  lm_detour_t  detour,
		  lm_size_t    bits,
		  lm_byte_t  **buf)
{
	lm_size_t  size = 0;

	if (!buf)
		return size;

#	if LM_ARCH == LM_ARCH_X86
	switch (detour) {
	case LM_DETOUR_JMP32:
	{
		lm_byte_t payload[] = {
			0xE9, 0x0, 0x0, 0x0, 0x0 /* jmp 0x0 */
		};

		size = sizeof(payload);

		*(lm_uint32_t *)&payload[1] = (lm_uint32_t)(
			(lm_uintptr_t)dst - (lm_uintptr_t)src - size
		);

		*buf = LM_MALLOC(size);
		LM_MEMCPY(*buf, payload, size);
		break;
	}
	case LM_DETOUR_JMP64:
	{
		if (bits == 64) {
			lm_byte_t payload[] = {
			     0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, /* jmp [rip] */
			     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uintptr_t *)&payload[6] = (lm_uintptr_t)dst;

			*buf = LM_MALLOC(size);
			LM_MEMCPY(*buf, payload, size);	
		} else {
			lm_byte_t payload[] = {
				0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, /* jmp [eip] */
				0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uint32_t *)&payload[6] = (lm_uint32_t)(
				(lm_uintptr_t)dst
			);

			*buf = LM_MALLOC(size);
			LM_MEMCPY(*buf, payload, size);	
		}
		break;
	}
	case LM_DETOUR_CALL32:
	{
		lm_byte_t payload[] = {
			0xE8, 0x0, 0x0, 0x0, 0x0 /* call 0x0 */
		};

		size = sizeof(payload);

		*(lm_uint32_t *)&payload[1] = (lm_uint32_t)(
			(lm_uintptr_t)dst - (lm_uintptr_t)src - size
		);

		*buf = LM_MALLOC(size);
		LM_MEMCPY(*buf, payload, size);
		break;
	}
	case LM_DETOUR_CALL64:
	{
		if (bits == 64) {
			lm_byte_t payload[] = {
			     0xFF, 0x15, 0x0, 0x0, 0x0, 0x0, /* call [rip] */
			     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uintptr_t *)&payload[6] = (lm_uintptr_t)dst;

			*buf = LM_MALLOC(size);
			LM_MEMCPY(*buf, payload, size);	
		} else {
			lm_byte_t payload[] = {
			       0xFF, 0x15, 0x0, 0x0, 0x0, 0x0, /* call [eip] */
			       0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uint32_t *)&payload[6] = (lm_uint32_t)(
				(lm_uintptr_t)dst
			);

			*buf = LM_MALLOC(size);
			LM_MEMCPY(*buf, payload, size);	
		}
		break;
	}
	case LM_DETOUR_RET32:
	{
		break;
	}
	case LM_DETOUR_RET64:
	{
		break;
	}
	}
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	return size;
}

static lm_void_t
_LM_ParseDatArgsIn(lm_process_t proc,
		   lm_datio_t  *datargs,
		   lm_size_t    nargs,
		   lm_size_t    stack_align,
		   lm_regs_t   *regsbuf)
{
	lm_size_t i;

	for (i = 0; i < nargs; ++i) {
#		if LM_ARCH == LM_ARCH_X86
		if (datargs[i].datloc != LM_DATLOC_STACK) {
			lm_void_t *reg;

			reg = LM_DebugPickReg(datargs[i].datloc, regsbuf);
			if (reg) {
#				if LM_OS == LM_OS_WIN
				if (LM_GetProcessBitsEx(proc) == 64) {
					*(lm_uintptr_t *)reg = (
						*(lm_uintptr_t *)(
							datargs[i].data
						)
					);
				} else {
					*(lm_uint32_t *)reg = (
						*(lm_uint32_t *)(
							datargs[i].data
						)
					);
				}
#				else
				*(lm_uintptr_t *)reg = (
					*(lm_uintptr_t *)(
						datargs[i].data
					)
				);
#				endif
			}
		} else {
			lm_void_t   *stack_ptr;
			lm_address_t dst;

#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64)
				stack_ptr = LM_DebugPickReg(LM_DATLOC_RSP, regsbuf);
			else
				stack_ptr = LM_DebugPickReg(LM_DATLOC_ESP, regsbuf);
#			else
			stack_ptr = LM_DebugPickReg(LM_DATLOC_ESP, regsbuf);
#			endif

#			if LM_OS == LM_OS_WIN
			if (LM_GetProcessBitsEx(proc) == 64) {
				*(lm_uintptr_t *)stack_ptr -= datargs[i].size;
				*(lm_uintptr_t *)stack_ptr &= stack_align;
				dst = (lm_address_t)(
					*(lm_uintptr_t *)stack_ptr
				);
			} else {
				*(lm_uint32_t *)stack_ptr -= datargs[i].size;
				*(lm_uint32_t *)stack_ptr &= stack_align;
				dst = (lm_address_t)(
					*(lm_uint32_t *)stack_ptr
				);
			}
#			else
			*(lm_uintptr_t *)stack_ptr -= datargs[i].size;
			*(lm_uintptr_t *)stack_ptr &= stack_align;
			dst = (lm_address_t)(
				*(lm_uintptr_t *)stack_ptr
			);
#			endif

			LM_DebugWrite(proc, dst,
				      datargs[i].data, datargs[i].size);
		}
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
}

static lm_void_t
_LM_ParseDatArgsOut(lm_process_t proc,
		    lm_datio_t  *datargs,
		    lm_size_t    nargs,
		    lm_size_t    stack_align,
		    lm_regs_t    regs)
{
	lm_size_t i;

	for (i = 0; i < nargs; ++i) {
#		if LM_ARCH == LM_ARCH_X86
		if (datargs[i].datloc != LM_DATLOC_STACK) {
			lm_void_t *reg;

			reg = LM_DebugPickReg(datargs[i].datloc, &regs);
			if (reg) {
#				if LM_OS == LM_OS_WIN
				if (LM_GetProcessBitsEx(proc) == 64) {
					*(lm_uintptr_t *)datargs[i].data = (
						*(lm_uintptr_t *)reg
					);
				} else {
					*(lm_uintptr_t *)datargs[i].data = (
						(lm_uintptr_t)(
							*(lm_uint32_t *)reg
						)
					);
				}
#				else
				*(lm_uintptr_t *)datargs[i].data = (
					*(lm_uintptr_t *)reg
				);
#				endif
			}
		} else {
			lm_void_t   *stack_ptr;
			lm_address_t src;

#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64)
				stack_ptr = LM_DebugPickReg(LM_DATLOC_RSP, &regs);
			else
				stack_ptr = LM_DebugPickReg(LM_DATLOC_ESP, &regs);
#			else
			stack_ptr = LM_DebugPickReg(LM_DATLOC_ESP, &regs);
#			endif

#			if LM_OS == LM_OS_WIN
			if (LM_GetProcessBitsEx(proc) == 64) {
				src = (lm_address_t)(
					*(lm_uintptr_t *)stack_ptr
				);

				*(lm_uintptr_t *)stack_ptr += datargs[i].size;
				*(lm_uintptr_t *)stack_ptr += (
					datargs[i].size - 
					       (datargs[i].size & stack_align)
				);
			} else {
				src = (lm_address_t)(
					*(lm_uintptr_t *)stack_ptr
				);

				*(lm_uint32_t *)stack_ptr += datargs[i].size;
				*(lm_uint32_t *)stack_ptr += (
					datargs[i].size - 
					       (datargs[i].size & stack_align)
				);
			}
#			else
			src = (lm_address_t)(
				*(lm_uintptr_t *)stack_ptr
			);

			*(lm_uintptr_t *)stack_ptr += datargs[i].size;
			*(lm_uintptr_t *)stack_ptr += (
				datargs[i].size - 
					(datargs[i].size & stack_align)
			);
#			endif

			LM_DebugRead(proc, src,
				     datargs[i].data, datargs[i].size);
		}
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
}

LM_API lm_bool_t
_LM_DebugInject(lm_process_t proc,
		lm_bstring_t payload,
		lm_size_t    size,
		lm_regs_t    regs,
		lm_regs_t   *post_regs,
		lm_bool_t  (*run_func)(lm_process_t proc))
{
	lm_bool_t    ret = LM_FALSE;
	lm_address_t inj_addr;
	lm_byte_t   *old_code = (lm_byte_t *)LM_NULL;
	lm_regs_t    old_regs;

	old_code = (lm_byte_t *)LM_MALLOC(size);
	if (!old_code)
		return ret;

	LM_DebugGetRegs(proc, &old_regs);

#	if LM_ARCH == LM_ARCH_X86
#	if LM_BITS == 64
	if (LM_GetProcessBitsEx(proc) == 64) {
		inj_addr = (lm_address_t)LM_DebugReadReg(LM_DATLOC_RIP, regs);
	} else {
		inj_addr = (lm_address_t)LM_DebugReadReg(LM_DATLOC_EIP, regs);
	}
#	else
	inj_addr = (lm_address_t)LM_DebugReadReg(LM_DATLOC_EIP, regs);
#	endif
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	LM_DebugRead(proc, inj_addr, old_code, size);	
	LM_DebugWrite(proc, inj_addr, payload, size);
	LM_DebugSetRegs(proc, regs);
	run_func(proc);
	LM_DebugWaitProcess(proc);
	if (post_regs)
		LM_DebugGetRegs(proc, post_regs);
	LM_DebugWrite(proc, inj_addr, old_code, size);
	LM_DebugSetRegs(proc, old_regs);

	ret = LM_TRUE;
	LM_FREE(old_code);

	return ret;
}

#if LM_OS == LM_OS_WIN
static lm_bool_t
_LM_EnumSymbolsPE(lm_size_t    bits,
		  lm_address_t modbase,
		  lm_bool_t  (*callback)(lm_cstring_t symbol,
					 lm_address_t addr,
					 lm_void_t   *arg),
		  lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	PIMAGE_DOS_HEADER pdoshdr;
	
	pdoshdr = (PIMAGE_DOS_HEADER)modbase;
	if (pdoshdr->e_magic != IMAGE_DOS_SIGNATURE)
		return ret;

	if (bits == 64) {
		PIMAGE_NT_HEADERS64     pnthdr;
		PIMAGE_EXPORT_DIRECTORY pexpdir;
		DWORD                  *pnames;
		DWORD                  *pfuncs;
		DWORD                   i;

		pnthdr = (PIMAGE_NT_HEADERS64)LM_OFFSET(modbase,
							pdoshdr->e_lfanew);
		if (pnthdr->Signature != IMAGE_NT_SIGNATURE)
			return ret;
		
		pexpdir = (PIMAGE_EXPORT_DIRECTORY)(
			LM_OFFSET(modbase, pnthdr->OptionalHeader.DataDirectory[
					IMAGE_DIRECTORY_ENTRY_EXPORT
				].VirtualAddress
			)
		);
		
		if (!pexpdir->AddressOfNames || !pexpdir->AddressOfFunctions)
			return ret;
		
		pnames = (DWORD *)LM_OFFSET(modbase,
					    pexpdir->AddressOfNames);
		pfuncs = (DWORD *)LM_OFFSET(modbase,
					    pexpdir->AddressOfFunctions);
		
		for (i = 0;
		     i < pexpdir->NumberOfNames &&
		     i < pexpdir->NumberOfFunctions;
		     ++i) {
			if (!callback((lm_cstring_t)LM_OFFSET(modbase,
							      pnames[i]),
				      (lm_address_t)LM_OFFSET(modbase,
				      			      pfuncs[i]),
				      arg))
				break;
		}

		ret = LM_TRUE;
	} else {
		PIMAGE_NT_HEADERS32     pnthdr;
		PIMAGE_EXPORT_DIRECTORY pexpdir;
		DWORD                  *pnames;
		DWORD                  *pfuncs;
		DWORD                   i;

		pnthdr = (PIMAGE_NT_HEADERS32)LM_OFFSET(modbase,
							pdoshdr->e_lfanew);
		if (pnthdr->Signature != IMAGE_NT_SIGNATURE)
			return ret;
		
		pexpdir = (PIMAGE_EXPORT_DIRECTORY)(
			LM_OFFSET(modbase, pnthdr->OptionalHeader.DataDirectory[
					IMAGE_DIRECTORY_ENTRY_EXPORT
				].VirtualAddress
			)
		);
		
		if (!pexpdir->AddressOfNames || !pexpdir->AddressOfFunctions)
			return ret;
		
		pnames = (DWORD *)LM_OFFSET(modbase,
					    pexpdir->AddressOfNames);
		pfuncs = (DWORD *)LM_OFFSET(modbase,
					    pexpdir->AddressOfFunctions);
		
		for (i = 0;
		     i < pexpdir->NumberOfNames &&
		     i < pexpdir->NumberOfFunctions;
		     ++i) {
			if (!callback((lm_cstring_t)LM_OFFSET(modbase,
							      pnames[i]),
				      (lm_address_t)LM_OFFSET(modbase,
				      			      pfuncs[i]),
				      arg))
				break;
		}

		ret = LM_TRUE;
	}

	return ret;
}

#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
static lm_size_t
_LM_OpenFileBuf(lm_tstring_t path, 
		lm_tchar_t **pfilebuf)
{
	int         fd;
	lm_size_t   total = 0;
	lm_tchar_t  c;
	ssize_t     rdsize;
	lm_tchar_t *filebuf = (lm_tchar_t *)LM_NULL;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return total;
	
	while ((rdsize = read(fd, &c, sizeof(c)) > 0)) {
		lm_tchar_t *old_filebuf;

		old_filebuf = filebuf;
		filebuf = LM_CALLOC(total + 2, sizeof(c));
		if (old_filebuf) {
			if (filebuf)
				LM_STRNCPY(filebuf, old_filebuf, total);
			LM_FREE(old_filebuf);
		}

		if (!filebuf) {
			total = 0;
			break;
		}

		filebuf[total++] = c;
		filebuf[total] = LM_STR('\x00');
	}

	if (filebuf) {
		filebuf[total] = LM_STR('\x00');
		*pfilebuf = filebuf;
	}

	close(fd);
	return total;
}

static lm_void_t
_LM_CloseFileBuf(lm_tchar_t **pfilebuf)
{
	if (pfilebuf && *pfilebuf) {
		LM_FREE(*pfilebuf);
		*pfilebuf = (lm_tchar_t *)LM_NULL;
	}
}

static lm_bool_t
_LM_PtraceRead(lm_process_t proc,
	       lm_address_t src,
	       lm_byte_t   *dst,
	       lm_size_t    size)
{
	lm_bool_t   ret = LM_FALSE;
	lm_size_t   i;

	if (!dst || !size)
		return ret;

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	for (i = 0; i < size; ++i) {
		dst[i] = (lm_byte_t)ptrace(PTRACE_PEEKDATA,
					   proc.pid,
					   (void *)(
						   &((lm_byte_t *)src)[i]
					   ),
					   NULL);
	}
#	elif LM_OS == LM_OS_BSD
	for (i = 0; i < size; ++i) {
		dst[i] = (lm_byte_t)ptrace(PT_READ_D,
					   proc.pid,
					   (caddr_t)(
						   &((lm_byte_t *)src)[i]
					   ),
					   0);
	}
#	endif
	
	ret = LM_TRUE;
	return ret;
}

static lm_bool_t
_LM_PtraceWrite(lm_process_t proc,
		lm_address_t dst,
		lm_byte_t   *src,
		lm_size_t    size)
{
	lm_bool_t   ret = LM_FALSE;
	lm_size_t   i;
	lm_size_t   aligned_size = size;
	lm_byte_t  *buf;

	if (!src || !size)
		return ret;
	
	aligned_size += aligned_size > sizeof(lm_uintptr_t) ?
		aligned_size % sizeof(lm_uintptr_t) :
		sizeof(lm_uintptr_t) - aligned_size;
	
	buf = LM_CALLOC(aligned_size, sizeof(lm_byte_t));
	if (!buf)
		return ret;
	
	_LM_PtraceRead(proc, dst, buf, aligned_size);
	LM_MEMCPY(buf, src, size);

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	for (i = 0; i < aligned_size; i += sizeof(lm_uintptr_t)) {
		ptrace(PTRACE_POKEDATA,
		       proc.pid,
		       (void *)(&((lm_byte_t *)dst)[i]),
		       *(lm_uintptr_t *)(&buf[i]));
	}
#	elif LM_OS == LM_OS_BSD
	for (i = 0; i < aligned_size; i += sizeof(lm_uintptr_t)) {
		ptrace(PT_WRITE_D,
		       proc.pid,
		       (caddr_t)(&((lm_byte_t *)dst)[i]),
		       *(lm_uintptr_t *)(&buf[i]));
	}
#	endif
	
	LM_FREE(buf);
	ret = LM_TRUE;
	return ret;
}

static lm_bool_t
_LM_GetLibcMod(lm_module_t  mod,
	       lm_tstring_t path,
	       lm_void_t   *arg)
{
	lm_module_t *pmod = (lm_module_t *)arg;
	lm_tchar_t  *modname = (lm_tchar_t *)LM_NULL;

	{
		lm_tchar_t *tmp;

		for (tmp = path;
		     (tmp = LM_STRCHR(tmp, LM_STR('/')));
		     tmp = &tmp[1])
			modname = &tmp[1];
	}

	if (modname) {
		if (!LM_STRNCMP(modname, LM_STR("libc."), 5) ||
		    !LM_STRNCMP(modname, LM_STR("libc-"), 5)) {
			*pmod = mod;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}
#endif

/* libmem */
LM_API lm_bool_t
LM_EnumProcesses(lm_bool_t(*callback)(lm_pid_t   pid,
				      lm_void_t *arg),
		 lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		HANDLE hSnap;
		
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 entry;

			entry.dwSize = sizeof(PROCESSENTRY32);
			if (Process32First(hSnap, &entry)) {
				do {
					lm_pid_t pid = (lm_pid_t)(
						entry.th32ProcessID
					);

					if (callback(pid, arg) == LM_FALSE)
						break;
				} while (Process32Next(hSnap, &entry));

				ret = LM_TRUE;
			}
		}

		CloseHandle(hSnap);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		struct dirent *pdirent;
		DIR *dir;

		dir = opendir(LM_PROCFS);

		if (!dir)
			return ret;
		
		while ((pdirent = readdir(dir))) {
			lm_pid_t pid = LM_ATOI(pdirent->d_name);

			if (pid || (!pid && !LM_STRCMP(pdirent->d_name,
						       LM_STR("0")))) {
				if (callback(pid, arg) == LM_FALSE)
					break;
			}
		}

		ret = LM_TRUE;
		
		closedir(dir);
	}
#	elif LM_OS == LM_OS_BSD
	{
		struct procstat *ps;
		
		ps = procstat_open_sysctl();
		if (ps) {
			unsigned int nprocs = 0;
			struct kinfo_proc *procs = procstat_getprocs(
				ps, KERN_PROC_PROC, 
				0, &nprocs
			);

			if (procs) {
				unsigned int i;

				for (i = 0; i < nprocs; ++i) {
					lm_pid_t pid = (lm_pid_t)(
						procs[i].ki_pid
					);

					if (callback(pid, arg) == LM_FALSE)
						break;
				}

				procstat_freeprocs(ps, procs);

				ret = LM_TRUE;
			}

			procstat_close(ps);
		}
	}
#	endif
	return ret;
}

static lm_bool_t
_LM_GetProcessIdCallback(lm_pid_t   pid,
			 lm_void_t *arg)
{
	lm_bool_t      ret = LM_TRUE;
	lm_process_t   proc;
	_lm_get_pid_t *parg = (_lm_get_pid_t *)arg;
	lm_tchar_t    *path;

	path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));

	if (!path)
		return LM_FALSE;

	if (LM_OpenProcessEx(pid, &proc)) {
		lm_size_t len;

		len = LM_GetProcessPathEx(proc,	path, LM_PATH_MAX - 1);
		if (len && len >= parg->len) {
			path[len] = LM_STR('\x00');

			if (!LM_STRCMP(&path[len - parg->len], 
				       parg->procstr)) {
				parg->pid = pid;
				ret = LM_FALSE;
			}
		}

		LM_CloseProcess(&proc);
	}

	LM_FREE(path);

	return ret;
}

LM_API lm_pid_t
LM_GetProcessId(lm_void_t)
{
	lm_pid_t pid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		pid = GetCurrentProcessId();
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		pid = getpid();
	}
#	endif

	return pid;
}

LM_API lm_pid_t
LM_GetProcessIdEx(lm_tstring_t procstr)
{
	_lm_get_pid_t arg;

	arg.pid = (lm_pid_t)LM_BAD;
	arg.procstr = procstr;
	arg.len = LM_STRLEN(arg.procstr);

	LM_EnumProcesses(_LM_GetProcessIdCallback, (lm_void_t *)&arg);
	return arg.pid;
}

LM_API lm_pid_t
LM_GetParentId(lm_void_t)
{
	lm_pid_t ppid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		ppid = LM_GetParentIdEx(LM_GetProcessId());
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		ppid = getppid();
	}
#	endif

	if (!ppid)
		ppid = (lm_pid_t)LM_BAD;

	return ppid;
}

LM_API lm_pid_t
LM_GetParentIdEx(lm_pid_t pid)
{
	lm_pid_t ppid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		HANDLE hSnap;
		
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 entry;

			entry.dwSize = sizeof(PROCESSENTRY32);
			if (Process32First(hSnap, &entry)) {
				do {
					lm_pid_t curpid = (lm_pid_t)(
						entry.th32ProcessID
					);

					if (curpid == pid) {
						ppid = (lm_pid_t)(
						      entry.th32ParentProcessID
						);

						break;
					}
				} while (Process32Next(hSnap, &entry));
			}
		}

		CloseHandle(hSnap);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t *status_buf;
		lm_tchar_t  status_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
		lm_tchar_t *ptr;

		LM_SNPRINTF(status_path, LM_ARRLEN(status_path) - 1,
			    LM_STR("%s/%d/status"), LM_PROCFS, pid);
		
		if (!_LM_OpenFileBuf(status_path, &status_buf))
			return ppid;

		ptr = LM_STRSTR(status_buf, LM_STR("\nPPid:\t"));

		if (ptr) {
			ptr = LM_STRCHR(ptr, LM_STR('\t'));
			ptr = &ptr[1];
			ppid = (lm_pid_t)LM_ATOI(ptr);
		}

		_LM_CloseFileBuf(&status_buf);
	}
#	endif

	return ppid;
}

static lm_bool_t
_LM_CheckProcessCallback(lm_pid_t   pid,
			 lm_void_t *arg)
{
	_lm_check_process_t *parg = (_lm_check_process_t *)arg;

	if (parg->pid == pid) {
		parg->check = LM_TRUE;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_bool_t
LM_CheckProcess(lm_pid_t pid)
{
	_lm_check_process_t arg;
	arg.pid   = pid;
	arg.check = LM_FALSE;

	LM_EnumProcesses(_LM_CheckProcessCallback, (lm_void_t *)&arg);

	return arg.check;
}

LM_API lm_bool_t
LM_OpenProcess(lm_process_t *procbuf)
{
	lm_bool_t ret = LM_FALSE;

	if (!procbuf)
		return ret;

	procbuf->pid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		procbuf->handle = GetCurrentProcess();
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		
	}
#	endif

	procbuf->pid = LM_GetProcessId();
	ret = LM_TRUE;

	return ret;
}

LM_API lm_bool_t
LM_OpenProcessEx(lm_pid_t      pid,
		 lm_process_t *procbuf)
{
	lm_bool_t ret = LM_FALSE;

	if (!procbuf)
		return ret;
	
	procbuf->pid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		if (pid != LM_GetProcessId()) {
			procbuf->handle = OpenProcess(LM_PROCESS_ACCESS,
					      FALSE,
					      pid);
		
			if (!procbuf->handle)
				return ret;
		} else {
			procbuf->handle = GetCurrentProcess();
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		if (!LM_CheckProcess(pid))
			return ret;
	}
#	endif

	procbuf->pid = pid;
	ret = LM_TRUE;

	return ret;
}

LM_API lm_void_t
LM_CloseProcess(lm_process_t *procbuf)
{
	if (!procbuf)
		return;
	
#	if LM_OS == LM_OS_WIN
	{
		if (procbuf->handle && procbuf->pid != LM_GetProcessId()) {
			CloseHandle(procbuf->handle);
			procbuf->handle = (HANDLE)NULL;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{

	}
#	endif

	procbuf->pid = (lm_pid_t)LM_BAD;
}

LM_API lm_size_t
LM_GetProcessPath(lm_tchar_t *pathbuf,
		  lm_size_t   maxlen)
{
	lm_size_t len = 0;

	if (!pathbuf || !maxlen)
		return len;

#	if LM_OS == LM_OS_WIN
	{
		HMODULE hModule = GetModuleHandle(NULL);
		if (!hModule)
			return len;

		len = (lm_size_t)GetModuleFileName(hModule, pathbuf, maxlen - 1);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_process_t proc;

		if (LM_OpenProcess(&proc)) {
			len = LM_GetProcessPathEx(proc, pathbuf, maxlen - 1);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	if (len)
		pathbuf[len] = LM_STR('\x00');

	return len;
}

LM_API lm_size_t
LM_GetProcessPathEx(lm_process_t proc,
		    lm_tchar_t  *pathbuf,
		    lm_size_t    maxlen)
{
	lm_size_t len = 0;

	if (!_LM_ValidProcess(proc) || !pathbuf || !maxlen)
		return len;
	
#	if LM_OS == LM_OS_WIN
	{
		len = (lm_size_t)GetModuleFileNameEx(proc.handle, NULL,
						     pathbuf, maxlen - 1);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t exe_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
		LM_SNPRINTF(exe_path, LM_ARRLEN(exe_path) - 1,
			    LM_STR("%s/%d/exe"), LM_PROCFS, proc.pid);
		
		len = (lm_size_t)readlink(exe_path, pathbuf, maxlen - 1);
		if (len == (lm_size_t)-1)
			len = 0;
	}
#	elif LM_OS == LM_OS_BSD
	{
		struct procstat *ps;
		
		ps = procstat_open_sysctl();
		if (ps) {
			unsigned int nprocs = 0;
			struct kinfo_proc *procs = procstat_getprocs(
				ps, KERN_PROC_PID,
				proc.pid, &nprocs
			);

			if (procs && nprocs) {
				if (!procstat_getpathname(ps, procs,
							  pathbuf, maxlen - 1))
					len = LM_STRLEN(pathbuf);

				procstat_freeprocs(ps, procs);
			}

			procstat_close(ps);
		}
	}
#	endif

	if (len)
		pathbuf[len] = LM_STR('\x00');

	return len;
}

LM_API lm_size_t
LM_GetProcessName(lm_tchar_t *namebuf,
		  lm_size_t   maxlen)
{
	lm_size_t len = 0;

#	if LM_OS == LM_OS_WIN
	{
		lm_tchar_t *path;

		path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));

		if (!path)
			return len;
		
		if (LM_GetProcessPath(path, LM_PATH_MAX)) {
			lm_tchar_t *tmp;
			lm_tchar_t *ptr = (lm_tchar_t *)LM_NULL;

			for (tmp = path;
			     tmp = LM_STRCHR(tmp, LM_STR('\\'));
			     tmp = &tmp[1])
				ptr = tmp;
			
			if (ptr) {
				ptr = &ptr[1];
				len = LM_STRLEN(ptr);
				if (len >= maxlen)
					len = maxlen - 1;
				
				LM_STRNCPY(namebuf, ptr, len);
				namebuf[len] = LM_STR('\x00');
			}
		}

		LM_FREE(path);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_process_t proc;
		if (LM_OpenProcess(&proc)) {
			len = LM_GetProcessNameEx(proc, namebuf, maxlen);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	return len;
}

LM_API lm_size_t
LM_GetProcessNameEx(lm_process_t proc,
		    lm_tchar_t  *namebuf,
		    lm_size_t    maxlen)
{
	lm_size_t len = 0;

	if (!_LM_ValidProcess(proc) || !namebuf || !maxlen)
		return len;

#	if LM_OS == LM_OS_WIN
	{
		len = (lm_size_t)GetModuleBaseName(proc.handle, NULL, namebuf, maxlen - 1);
		if (len)
			namebuf[len] = LM_STR('\x00');
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t *filebuf;
		lm_tchar_t comm_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

		LM_SNPRINTF(comm_path, LM_ARRLEN(comm_path) - 1,
			    LM_STR("%s/%d/comm"), LM_PROCFS, proc.pid);
		
		len = _LM_OpenFileBuf(comm_path, &filebuf);

		if (len) {
			--len;

			if (len >= maxlen)
				len = maxlen - 1;
			
			LM_STRNCPY(namebuf, filebuf, len);
			namebuf[len] = LM_STR('\x00');

			_LM_CloseFileBuf(&filebuf);
		}
	}
#	elif LM_OS == LM_OS_BSD
	{
		struct procstat *ps;
		
		ps = procstat_open_sysctl();
		if (ps) {
			unsigned int nprocs = 0;
			struct kinfo_proc *procs = procstat_getprocs(
				ps, KERN_PROC_PID,
				proc.pid, &nprocs
			);

			if (procs && nprocs) {
				len = LM_STRLEN(procs->ki_comm);
				if (len > maxlen)
					len = maxlen - 1;
				
				LM_STRNCPY(namebuf, procs->ki_comm, len);
				namebuf[len] = LM_STR('\x00');

				procstat_freeprocs(ps, procs);
			}

			procstat_close(ps);
		}
	}
#	endif

	return len;
}

LM_API lm_size_t
LM_GetSystemBits(lm_void_t)
{
	lm_size_t bits = LM_BITS;

#	if LM_OS == LM_OS_WIN
	{
		SYSTEM_INFO sysinfo = { 0 };

		GetNativeSystemInfo(&sysinfo);
		switch (sysinfo.wProcessorArchitecture)
		{
		case PROCESSOR_ARCHITECTURE_AMD64:
			bits = 64;
			break;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		struct utsname utsbuf;

		if (uname(&utsbuf))
			return bits;
		
		if (!LM_STRCMP(utsbuf.machine, LM_STR("x86_64")) ||
		    !LM_STRCMP(utsbuf.machine, LM_STR("amd64")) ||
		    !LM_STRCMP(utsbuf.machine, LM_STR("aarch64")))
			bits = 64;
	}
#	endif

	return bits;
}

LM_API lm_size_t
LM_GetProcessBits(lm_void_t)
{
	return (lm_size_t)LM_BITS;
}

LM_API lm_size_t
LM_GetProcessBitsEx(lm_process_t proc)
{
	lm_size_t bits = 0;

	if (!_LM_ValidProcess(proc))
		return bits;

#	if LM_OS == LM_OS_WIN
	{
		BOOL IsWow64;
		lm_size_t sysbits;

		if (!IsWow64Process(proc.handle, &IsWow64))
			return bits;

		sysbits = LM_GetSystemBits();

		if (sysbits == 32 || IsWow64)
			bits = 32;
		else if (sysbits == 64)
			bits = 64;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t *path;

		path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
		if (!path)
			return bits;
		
		if (LM_GetProcessPathEx(proc, path, LM_PATH_MAX)) {
			int fd;

			fd = open(path, O_RDONLY);
			if (fd != -1) {
				unsigned char elf_num;

				/*
				 * 32 bits: 0x7F, ELF, 1
				 * 64 bits: 0x7F, ELF, 2
				 */

				lseek(fd, EI_MAG3 + 1, SEEK_SET);
				if (read(fd, &elf_num, sizeof(elf_num)) > 0 &&
				    (elf_num == 1 || elf_num == 2))
					bits = elf_num * 32;
				
				close(fd);
			}
		}

		LM_FREE(path);
		
	}
#	endif

	return bits;
}

/****************************************/

LM_API lm_bool_t
LM_EnumThreads(lm_bool_t(*callback)(lm_tid_t   tid,
				    lm_void_t *arg),
	       lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	lm_process_t proc;

	if (LM_OpenProcess(&proc)) {
		ret = LM_EnumThreadsEx(proc, callback, arg);
		LM_CloseProcess(&proc);
	}

	return ret;
}

LM_API lm_bool_t
LM_EnumThreadsEx(lm_process_t proc,
		 lm_bool_t  (*callback)(lm_tid_t   tid,
					lm_void_t *arg),
		 lm_void_t   *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc) || !callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		HANDLE hSnap;

		hSnap = CreateToolhelp32Snapshot(
			TH32CS_SNAPTHREAD,
			0
		);

		if (hSnap != INVALID_HANDLE_VALUE) {
			THREADENTRY32 entry;
			entry.dwSize = sizeof(THREADENTRY32);

			if (Thread32First(hSnap, &entry)) {
				do {
					lm_tid_t tid;

					if (entry.th32OwnerProcessID !=
					    proc.pid)
						continue;
					
					tid = (lm_tid_t)entry.th32ThreadID;

					if (callback(tid, arg) == LM_FALSE)
						break;
				} while (Thread32Next(hSnap, &entry));

				ret = LM_TRUE;
			}

			CloseHandle(hSnap);
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		DIR *pdir;
		struct dirent *pdirent;
		lm_tchar_t task_path[64] = { 0 };

		LM_SNPRINTF(task_path, LM_ARRLEN(task_path) - 1,
			    LM_STR("/proc/%d/task"), proc.pid);
		
		pdir = opendir(task_path);
		if (!pdir)
			return ret;
		
		while ((pdirent = readdir(pdir))) {
			lm_tid_t tid = LM_ATOI(pdirent->d_name);

			if (!tid && LM_STRCMP(pdirent->d_name, "0"))
				continue;

			if (callback(tid, arg) == LM_FALSE)
				break;
		}
		
		closedir(pdir);
		ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		/* NOTE: Improve thread enumeration */

		callback((lm_tid_t)proc.pid, arg);
		ret = LM_TRUE;
	}
#	endif

	return ret;
}

static lm_bool_t
_LM_GetThreadIdCallback(lm_tid_t   tid,
			lm_void_t *arg)
{
	*(lm_tid_t *)arg = tid;
	return LM_FALSE;
}

LM_API lm_tid_t
LM_GetThreadId(lm_void_t)
{
	lm_tid_t tid = (lm_tid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		tid = (lm_tid_t)GetCurrentThreadId();
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		/* tid = (lm_tid_t)gettid(); */
		tid = (lm_tid_t)getpid();
	}
#	elif LM_OS == LM_OS_BSD
	{
		tid = (lm_tid_t)LM_GetProcessId();
	}
#	endif

	return tid;
}

LM_API lm_tid_t
LM_GetThreadIdEx(lm_process_t proc)
{
	lm_tid_t tid = (lm_tid_t)LM_BAD;

	if (!_LM_ValidProcess(proc))
		return tid;

	LM_EnumThreadsEx(proc, _LM_GetThreadIdCallback, (lm_void_t *)&tid);

	return tid;
}

/****************************************/

LM_API lm_bool_t
LM_EnumModules(lm_bool_t(*callback)(lm_module_t  mod,
				    lm_tstring_t path,
				    lm_void_t   *arg),
	       lm_void_t *arg)
{
	lm_byte_t ret = LM_FALSE;
	lm_process_t proc;

	if (!callback)
		return ret;

	LM_OpenProcess(&proc);
	ret = LM_EnumModulesEx(proc, callback, arg);
	LM_CloseProcess(&proc);

	return ret;
}

LM_API lm_bool_t
LM_EnumModulesEx(lm_process_t proc,
		 lm_bool_t  (*callback)(lm_module_t  mod,
					lm_tstring_t path,
					lm_void_t   *arg),
		 lm_void_t   *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc) || !callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		HANDLE hSnap;

		hSnap = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			proc.pid
		);

		if (hSnap != INVALID_HANDLE_VALUE) {
			MODULEENTRY32 entry;
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
						&((lm_byte_t *)mod.base)[
							mod.size
						]
					);

					if (callback(mod,
						     entry.szExePath,
						     arg) == LM_FALSE)
						break;
				} while (Module32Next(hSnap, &entry));

				ret = LM_TRUE;
			}

			CloseHandle(hSnap);
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t *maps_buf;
		lm_tchar_t *ptr;
		lm_tchar_t maps_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

#		if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path) - 1,
			    LM_STR("%s/%d/maps"), LM_PROCFS, proc.pid);
#		elif LM_OS == LM_OS_BSD
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path) - 1,
			    LM_STR("%s/%d/map"), LM_PROCFS, proc.pid);
#		endif
		
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

#			if LM_OS == LM_OS_BSD
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
#			endif
			pathlen = (lm_size_t)(
				((lm_uintptr_t)tmp - (lm_uintptr_t)ptr) /
				sizeof(tmp[0])
			);
			
			path = LM_CALLOC(pathlen + 1, sizeof(lm_tchar_t));
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

#			if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
			holder = LM_STRCHR(holder, LM_STR('-'));
#			elif LM_OS == LM_OS_BSD
			holder = LM_STRSTR(holder, LM_STR(" 0x"));
#			endif
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
	}
#	endif

	return ret;
}

static lm_bool_t
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

	if (!modarg || !modbuf)
		return ret;

	arg.modbuf = modbuf;
	arg.modbuf->base = (lm_address_t)LM_BAD;
	arg.modbuf->size = 0;
	arg.modbuf->end  = (lm_address_t)LM_BAD;
	arg.modarg = modarg;
	arg.flags  = flags;

	if (flags == LM_MOD_BY_STR)
		arg.len = LM_STRLEN((lm_tstring_t)arg.modarg);

	ret = LM_EnumModules(_LM_GetModuleCallback, (lm_void_t *)&arg);

	return ret;
}

LM_API lm_bool_t
LM_GetModuleEx(lm_process_t proc,
	       lm_int_t     flags,
	       lm_void_t   *modarg,
	       lm_module_t *modbuf)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_mod_t arg;

	if (!modarg || !modbuf)
		return ret;

	arg.modbuf = modbuf;
	arg.modbuf->base = (lm_address_t)LM_BAD;
	arg.modbuf->size = 0;
	arg.modbuf->end  = (lm_address_t)LM_BAD;
	arg.modarg = modarg;
	arg.flags  = flags;

	if (flags == LM_MOD_BY_STR)
		arg.len = LM_STRLEN((lm_tstring_t)arg.modarg);

	ret = LM_EnumModulesEx(proc, _LM_GetModuleCallback, (lm_void_t *)&arg);

	return ret;
}

static lm_bool_t
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

	arg.mod     = mod;
	arg.pathbuf = pathbuf;
	arg.maxlen  = maxlen;
	arg.len     = 0;

	if (!arg.pathbuf || !arg.maxlen)
		return arg.len;

	LM_EnumModules(_LM_GetModulePathCallback, (lm_void_t *)&arg);

	return arg.len;
}

LM_API lm_size_t
LM_GetModulePathEx(lm_process_t proc,
		   lm_module_t  mod,
		   lm_tchar_t  *pathbuf,
		   lm_size_t    maxlen)
{
	_lm_get_mod_path_t arg;
	
	arg.mod     = mod;
	arg.pathbuf = pathbuf;
	arg.maxlen  = maxlen;
	arg.len     = 0;

	if (!arg.pathbuf || !arg.maxlen)
		return arg.len;

	LM_EnumModulesEx(proc, _LM_GetModulePathCallback, (lm_void_t *)&arg);

	return arg.len;
}

LM_API lm_size_t
LM_GetModuleName(lm_module_t mod,
		 lm_tchar_t *namebuf,
		 lm_size_t   maxlen)
{
	lm_size_t   len = 0;
	lm_tchar_t *path;

	if (!namebuf || !maxlen)
		return len;

	path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!path)
		return len;

	if (LM_GetModulePath(mod, path, LM_PATH_MAX)) {
		lm_tchar_t  sep;
		lm_tchar_t *ptr;
		lm_tchar_t *holder;

#		if LM_OS == LM_OS_WIN
		sep = LM_STR('\\');
#		elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
		sep = LM_STR('/');
#		endif

		holder = path;

		for (ptr = path; (ptr = LM_STRCHR(ptr, sep)); ptr = &ptr[1])
			holder = &ptr[1];
		
		len = LM_STRLEN(holder);
		if (len >= maxlen)
			len = maxlen - 1;
		
		LM_STRNCPY(namebuf, holder, len);
		namebuf[len] = LM_STR('\x00');
	}

	LM_FREE(path);
	return len;
}

LM_API lm_size_t
LM_GetModuleNameEx(lm_process_t proc,
		   lm_module_t  mod,
		   lm_tchar_t  *namebuf,
		   lm_size_t    maxlen)
{
	lm_size_t   len = 0;
	lm_tchar_t *path;

	if (!namebuf || !maxlen)
		return len;

	path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!path)
		return len;

	if (LM_GetModulePathEx(proc, mod, path, LM_PATH_MAX)) {
		lm_tchar_t  sep;
		lm_tchar_t *ptr;
		lm_tchar_t *holder;

#		if LM_OS == LM_OS_WIN
		sep = LM_STR('\\');
#		elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
		sep = LM_STR('/');
#		endif

		holder = path;

		for (ptr = path; (ptr = LM_STRCHR(ptr, sep)); ptr = &ptr[1])
			holder = &ptr[1];
		
		len = LM_STRLEN(holder);
		if (len >= maxlen)
			len = maxlen - 1;
		
		LM_STRNCPY(namebuf, holder, len);
		namebuf[len] = LM_STR('\x00');
	}

	LM_FREE(path);
	return len;
}

LM_API lm_bool_t
LM_LoadModule(lm_tstring_t path,
	      lm_module_t *modbuf)
{
	lm_bool_t ret = LM_FALSE;

	if (!path)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (LoadLibrary(path)) {
			if (!modbuf ||
			    LM_GetModule(LM_MOD_BY_STR, path, modbuf))
				ret = LM_TRUE;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		if (dlopen(path, RTLD_LAZY)) {
			if (!modbuf ||
			    LM_GetModule(LM_MOD_BY_STR, path, modbuf))
				ret = LM_TRUE;
		}
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_LoadModuleEx(lm_process_t proc,
		lm_tstring_t path,
		lm_module_t *modbuf)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc) || !path)
		return ret;

#	if LM_OS == LM_OS_WIN
	{

	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_address_t dlopen_addr = (lm_address_t)LM_NULL;
		lm_module_t  libc_mod = { 0 };

		LM_EnumModulesEx(proc, _LM_GetLibcMod, (lm_void_t *)&libc_mod);

		if (!libc_mod.size)
			return ret;
		
#		if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
		dlopen_addr = LM_GetSymbolEx(proc, libc_mod,
					     "__libc_dlopen_mode");
#		else
		dlopen_addr = LM_GetSymbolEx(proc, libc_mod, "dlopen");
#		endif

		if (dlopen_addr) {
			lm_datio_t   arg0;
			lm_datio_t   arg1;
			lm_address_t path_addr = (lm_address_t)LM_NULL;
			lm_size_t    path_size;
			lm_uintptr_t mode = RTLD_LAZY;

			path_size = (LM_STRLEN(path) + 1) * sizeof(lm_tchar_t);

			path_addr = LM_AllocMemoryEx(
				proc,
				path_size,
				LM_PROT_RW
			);

			if (!path_addr)
				return ret;
			
			LM_WriteMemoryEx(proc, path_addr,
					 (lm_bstring_t)path, path_size);

#			if LM_ARCH == LM_ARCH_X86
#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64) {
				arg0.datloc = LM_DATLOC_RDI;
				arg0.data   = (lm_byte_t *)&path_addr;

				arg1.datloc = LM_DATLOC_RSI;
				arg1.data   = (lm_byte_t *)&mode;
			} else {
				arg0.datloc = LM_DATLOC_STACK;
				arg0.data   = (lm_byte_t *)&path_addr;
				arg0.size   = path_size;

				arg1.datloc = LM_DATLOC_STACK;
				arg1.data   = (lm_byte_t *)&mode;
				arg1.size   = sizeof(mode);
			}
#			else
			arg0.datloc = LM_DATLOC_STACK;
			arg0.data   = (lm_byte_t *)&path_addr;
			arg0.size   = path_size;

			arg1.datloc = LM_DATLOC_STACK;
			arg1.data   = (lm_byte_t *)&mode;
			arg1.size   = sizeof(mode);
#			endif
#			elif LM_ARCH == LM_ARCH_ARM
#			endif

			ret = LM_FunctionCallEx(proc, -8, dlopen_addr, 2, 0,
						arg1, arg0);
			
			LM_FreeMemoryEx(proc, path_addr, path_size);
		}
	}
#	endif

	if (modbuf && ret == LM_TRUE) {
		ret = LM_GetModuleEx(proc, LM_MOD_BY_STR, path, modbuf);
	}

	return ret;
}

LM_API lm_bool_t
LM_UnloadModule(lm_module_t mod)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		HMODULE hModule;
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
				  (LPTSTR)mod.base, &hModule);
		
		if (hModule && FreeLibrary(hModule))
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t *libpath;

		libpath = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
		if (!libpath)
			return ret;
		
		if (LM_GetModulePath(mod, libpath, LM_PATH_MAX)) {
			void *libhandle;

			libhandle = dlopen(libpath, RTLD_NOLOAD);

			if (libhandle) {
				dlclose(libhandle);
				dlclose(libhandle);

				ret = LM_TRUE;
			}
		}

		LM_FREE(libpath);
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_UnloadModuleEx(lm_process_t proc,
		  lm_module_t  mod)
{
	
}

/****************************************/

LM_API lm_bool_t
LM_EnumSymbols(lm_module_t mod,
	       lm_bool_t (*callback)(lm_cstring_t symbol,
	       			     lm_address_t addr,
	       			     lm_void_t   *arg),
	       lm_void_t *arg)
{
	lm_bool_t    ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		ret = _LM_EnumSymbolsPE(LM_GetProcessBits(), mod.base, callback, arg);
	}
#	else
	{
		lm_process_t proc;

		if (LM_OpenProcess(&proc)) {
			ret = LM_EnumSymbolsEx(proc, mod, callback, arg);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_EnumSymbolsEx(lm_process_t proc,
		 lm_module_t  mod,
	         lm_bool_t  (*callback)(lm_cstring_t symbol,
		 			lm_address_t addr,
					lm_void_t   *arg),
		 lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc) || !callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		lm_address_t alloc;

		alloc = LM_AllocMemory(LM_PROT_RW, mod.size);
		if (alloc == (lm_address_t)LM_BAD)
			return ret;
		
		if (LM_ReadMemoryEx(proc, alloc, mod.base, mod.size)) {
			ret = _LM_EnumSymbolsPE(LM_GetProcessBitsEx(proc),
						alloc,
						callback,
						arg);
		}

		LM_FreeMemory(alloc, mod.size);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		int         fd;
		lm_tchar_t *modpath;
		lm_size_t   bits;

		modpath = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
		if (!modpath)
			return ret;

		if (!LM_GetModulePathEx(proc, mod,
					modpath, LM_PATH_MAX))
			goto _FREE_RET;
		

		fd = open(modpath, O_RDONLY);
		if (fd == -1)
			goto _FREE_RET;
		
		bits = LM_GetProcessBitsEx(proc);

		if (bits == 64) {
			Elf64_Ehdr ehdr;
			Elf64_Off  shstrtab_off = 0;
			Elf64_Shdr shstrtab;
			Elf64_Off  symtab_off = 0;
			Elf64_Half symtab_entsize = 0;
			Elf64_Half symtab_num = 0;
			Elf64_Off  dynsym_off = 0;
			Elf64_Half dynsym_entsize = 0;
			Elf64_Half dynsym_num = 0;
			Elf64_Off  strtab_off = 0;
			Elf64_Off  dynstr_off = 0;
			Elf64_Half i;

			lseek(fd, 0, SEEK_SET);
			read(fd, &ehdr, sizeof(ehdr));

			shstrtab_off = ehdr.e_shoff + (
				ehdr.e_shstrndx * ehdr.e_shentsize
			);

			lseek(fd, shstrtab_off, SEEK_SET);
			read(fd, &shstrtab, ehdr.e_shentsize);
			shstrtab_off = shstrtab.sh_offset;

			lseek(fd, ehdr.e_shoff, SEEK_SET);
			for (i = 0; i < ehdr.e_shnum; ++i) {
				Elf64_Shdr shdr;
				lm_char_t  shstr[16] = { 0 };

				read(fd, &shdr, ehdr.e_shentsize);
				pread(fd, shstr, sizeof(shstr),
				      shstrtab_off + shdr.sh_name);
				
				if (!LM_CSTRCMP(shstr, LM_CSTR(".strtab"))) {
					strtab_off = shdr.sh_offset;
				} else if (!LM_CSTRCMP(shstr, LM_CSTR(".dynstr"))) {
					dynstr_off = shdr.sh_offset;
				} else if (!LM_CSTRCMP(shstr, LM_CSTR(".symtab"))) {
					symtab_off = shdr.sh_offset;
					symtab_entsize = shdr.sh_entsize;
					symtab_num = shdr.sh_size;
				} else if (!LM_CSTRCMP(shstr, LM_CSTR(".dynsym"))) {
					dynsym_off = shdr.sh_offset;
					dynsym_entsize = shdr.sh_entsize;
					dynsym_num = shdr.sh_size;
				}
			}

			lseek(fd, symtab_off, SEEK_SET);
			for (i = 0; i < symtab_num; ++i) {
				Elf64_Sym    sym;
				lm_char_t    c;
				lm_size_t    j = 0;
				lm_char_t   *symstr = (lm_tchar_t *)LM_NULL;
				lm_address_t addr;
				lm_bool_t    cbret;

				read(fd, &sym, symtab_entsize);

				do {
					lm_char_t *old_symstr = symstr;
					
					symstr = LM_CALLOC(j + 1,
							   sizeof(lm_char_t));

					if (old_symstr) {
						if (symstr) {
							LM_CSTRNCPY(symstr,
								    old_symstr,
								    j);
						}

						LM_FREE(old_symstr);
					}

					if (!symstr)
						goto _CLEAN_RET;
					
					pread(fd, &c, sizeof(c),
					      strtab_off + sym.st_name + j);
					
					symstr[j] = c;

					++j;
				} while (c != LM_CSTR('\x00'));

				if (ehdr.e_type != ET_EXEC) {
					addr = (lm_address_t)(
						&((lm_byte_t *)mod.base)[
							sym.st_value
						]
					);
				} else {
					addr = (lm_address_t)(
						(lm_uintptr_t)sym.st_value
					);
				}

				cbret = callback(symstr, addr, arg);
				
				LM_FREE(symstr);

				if (!cbret)
					goto _GOOD_RET;
			}

			lseek(fd, dynsym_off, SEEK_SET);
			for (i = 0; i < dynsym_num; ++i) {
				Elf64_Sym    sym;
				lm_char_t    c;
				lm_size_t    j = 0;
				lm_char_t   *symstr = (lm_tchar_t *)LM_NULL;
				lm_address_t addr;
				lm_bool_t    cbret;

				read(fd, &sym, dynsym_entsize);

				do {
					lm_char_t *old_symstr = symstr;
					
					symstr = LM_CALLOC(j + 1,
							   sizeof(lm_tchar_t));

					if (old_symstr) {
						if (symstr) {
							LM_CSTRNCPY(symstr,
								    old_symstr,
								    j);
						}

						LM_FREE(old_symstr);
					}

					if (!symstr)
						goto _CLEAN_RET;
					
					pread(fd, &c, sizeof(c),
					      dynstr_off + sym.st_name + j);
					
					symstr[j] = c;

					++j;
				} while (c != LM_CSTR('\x00'));

				if (ehdr.e_type != ET_EXEC) {
					addr = (lm_address_t)(
						&((lm_byte_t *)mod.base)[
							sym.st_value
						]
					);
				} else {
					addr = (lm_address_t)(
						(lm_uintptr_t)sym.st_value
					);
				}

				cbret = callback(symstr, addr, arg);
				
				LM_FREE(symstr);

				if (!cbret)
					goto _GOOD_RET;
			}
		} else {
			Elf32_Ehdr ehdr;
			Elf32_Off  shstrtab_off = 0;
			Elf32_Shdr shstrtab;
			Elf32_Off  symtab_off = 0;
			Elf32_Half symtab_entsize = 0;
			Elf32_Half symtab_num = 0;
			Elf32_Off  dynsym_off = 0;
			Elf32_Half dynsym_entsize = 0;
			Elf32_Half dynsym_num = 0;
			Elf32_Off  strtab_off = 0;
			Elf32_Off  dynstr_off = 0;
			Elf32_Half i;

			lseek(fd, 0, SEEK_SET);
			read(fd, &ehdr, sizeof(ehdr));

			shstrtab_off = ehdr.e_shoff + (
				ehdr.e_shstrndx * ehdr.e_shentsize
			);

			lseek(fd, shstrtab_off, SEEK_SET);
			read(fd, &shstrtab, ehdr.e_shentsize);
			shstrtab_off = shstrtab.sh_offset;

			lseek(fd, ehdr.e_shoff, SEEK_SET);
			for (i = 0; i < ehdr.e_shnum; ++i) {
				Elf32_Shdr shdr;
				lm_char_t  shstr[16] = { 0 };

				read(fd, &shdr, ehdr.e_shentsize);
				pread(fd, shstr, sizeof(shstr),
				      shstrtab_off + shdr.sh_name);
				
				if (!LM_CSTRCMP(shstr, LM_CSTR(".strtab"))) {
					strtab_off = shdr.sh_offset;
				} else if (!LM_CSTRCMP(shstr, LM_CSTR(".dynstr"))) {
					dynstr_off = shdr.sh_offset;
				} else if (!LM_CSTRCMP(shstr, LM_CSTR(".symtab"))) {
					symtab_off = shdr.sh_offset;
					symtab_entsize = shdr.sh_entsize;
					symtab_num = shdr.sh_size;
				} else if (!LM_CSTRCMP(shstr, LM_CSTR(".dynsym"))) {
					dynsym_off = shdr.sh_offset;
					dynsym_entsize = shdr.sh_entsize;
					dynsym_num = shdr.sh_size;
				}
			}

			lseek(fd, symtab_off, SEEK_SET);
			for (i = 0; i < symtab_num; ++i) {
				Elf32_Sym    sym;
				lm_char_t    c;
				lm_size_t    j = 0;
				lm_char_t   *symstr = (lm_tchar_t *)LM_NULL;
				lm_address_t addr;
				lm_bool_t    cbret;

				read(fd, &sym, symtab_entsize);

				do {
					lm_char_t *old_symstr = symstr;
					
					symstr = LM_CALLOC(j + 1,
							   sizeof(lm_char_t));

					if (old_symstr) {
						if (symstr) {
							LM_CSTRNCPY(symstr,
								    old_symstr,
								    j);
						}

						LM_FREE(old_symstr);
					}

					if (!symstr)
						goto _CLEAN_RET;
					
					pread(fd, &c, sizeof(c),
					      strtab_off + sym.st_name + j);
					
					symstr[j] = c;

					++j;
				} while (c != LM_CSTR('\x00'));

				if (ehdr.e_type != ET_EXEC) {
					addr = (lm_address_t)(
						&((lm_byte_t *)mod.base)[
							sym.st_value
						]
					);
				} else {
					addr = (lm_address_t)(
						(lm_uintptr_t)sym.st_value
					);
				}

				cbret = callback(symstr, addr, arg);
				
				LM_FREE(symstr);

				if (!cbret)
					goto _GOOD_RET;
			}

			lseek(fd, dynsym_off, SEEK_SET);
			for (i = 0; i < dynsym_num; ++i) {
				Elf32_Sym    sym;
				lm_char_t    c;
				lm_size_t    j = 0;
				lm_char_t   *symstr = (lm_tchar_t *)LM_NULL;
				lm_address_t addr;
				lm_bool_t    cbret;

				read(fd, &sym, dynsym_entsize);

				do {
					lm_char_t *old_symstr = symstr;
					
					symstr = LM_CALLOC(j + 1,
							   sizeof(lm_tchar_t));

					if (old_symstr) {
						if (symstr) {
							LM_CSTRNCPY(symstr,
								    old_symstr,
								    j);
						}

						LM_FREE(old_symstr);
					}

					if (!symstr)
						goto _CLEAN_RET;
					
					pread(fd, &c, sizeof(c),
					      dynstr_off + sym.st_name + j);
					
					symstr[j] = c;

					++j;
				} while (c != LM_CSTR('\x00'));

				if (ehdr.e_type != ET_EXEC) {
					addr = (lm_address_t)(
						&((lm_byte_t *)mod.base)[
							sym.st_value
						]
					);
				} else {
					addr = (lm_address_t)(
						(lm_uintptr_t)sym.st_value
					);
				}

				cbret = callback(symstr, addr, arg);
				
				LM_FREE(symstr);

				if (!cbret)
					goto _GOOD_RET;
			}	
		}

	_GOOD_RET:
		ret = LM_TRUE;
	_CLEAN_RET:
		close(fd);
	_FREE_RET:
		LM_FREE(modpath);
	}
#	endif

	return ret;
}

static lm_bool_t
_LM_GetSymbolCallback(lm_cstring_t symbol,
		      lm_address_t addr,
		      lm_void_t   *arg)
{
	_lm_get_symbol_t *parg = (_lm_get_symbol_t *)arg;
	
	if (!LM_STRCMP(symbol, parg->symbol)) {
		parg->addr = addr;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_address_t
LM_GetSymbol(lm_module_t  mod,
	     lm_cstring_t symstr)
{
	lm_address_t symaddr = (lm_address_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		HMODULE hModule;
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
				  (LPTSTR)mod.base, &hModule);
		
		if (hModule) {
			symaddr = (lm_address_t)GetProcAddress(hModule, symstr);
			if (!symaddr)
				symaddr = (lm_address_t)LM_BAD;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_process_t proc;

		if (LM_OpenProcess(&proc)) {
			symaddr = LM_GetSymbolEx(proc, mod, symstr);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	return symaddr;
}

LM_API lm_address_t
LM_GetSymbolEx(lm_process_t proc,
	       lm_module_t  mod,
	       lm_cstring_t symstr)
{
	_lm_get_symbol_t arg;
	arg.symbol = symstr;
	arg.addr   = (lm_address_t)LM_BAD;

	if (!_LM_ValidProcess(proc) || !symstr)
		return arg.addr;
	
	LM_EnumSymbolsEx(proc, mod, _LM_GetSymbolCallback, (lm_void_t *)&arg);

	return arg.addr;
}

/****************************************/

LM_API lm_bool_t
LM_EnumPages(lm_bool_t(*callback)(lm_page_t  page,
				  lm_void_t *arg),
	     lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		lm_address_t addr;
		MEMORY_BASIC_INFORMATION mbi;

		for (addr = (lm_address_t)0;
		     VirtualQuery(addr, &mbi, sizeof(mbi));
		     addr = (lm_address_t)(
			     &((lm_byte_t *)mbi.BaseAddress)[mbi.RegionSize]
		     )) {
			lm_page_t page;

			page.base  = (lm_address_t)mbi.BaseAddress;
			page.size  = (lm_size_t)mbi.RegionSize;
			page.end   = (lm_address_t)(
				&((lm_byte_t *)page.base)[page.size]
			);
			page.prot  = mbi.Protect;
			page.flags = mbi.Type;

			if (callback(page, arg) == LM_FALSE)
				break;
		}

		ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_process_t proc;

		if (LM_OpenProcess(&proc)) {
			ret = LM_EnumPagesEx(proc, callback, arg);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_EnumPagesEx(lm_process_t proc,
	       lm_bool_t  (*callback)(lm_page_t  page,
				      lm_void_t *arg),
	       lm_void_t   *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc) || !callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		lm_address_t addr;
		MEMORY_BASIC_INFORMATION mbi;

		for (addr = (lm_address_t)0;
		     VirtualQueryEx(proc.handle, addr, &mbi, sizeof(mbi));
		     addr = (lm_address_t)(
			     &((lm_byte_t *)mbi.BaseAddress)[mbi.RegionSize]
		     )) {
			lm_page_t page;

			page.base  = (lm_address_t)mbi.BaseAddress;
			page.size  = (lm_size_t)mbi.RegionSize;
			page.end   = (lm_address_t)(
				&((lm_byte_t *)page.base)[page.size]
			);
			page.prot  = mbi.Protect;
			page.flags = mbi.Type;

			if (callback(page, arg) == LM_FALSE)
				break;
		}

		ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t *maps_buf;
		lm_tchar_t *ptr;
		lm_tchar_t maps_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

#		if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path) - 1,
			    LM_STR("%s/%d/maps"), LM_PROCFS, proc.pid);
#		elif LM_OS == LM_OS_BSD
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path) - 1,
			    LM_STR("%s/%d/map"), LM_PROCFS, proc.pid);
#		endif
		
		if (!_LM_OpenFileBuf(maps_path, &maps_buf))
			return ret;

		ret = LM_TRUE;

		for (ptr = maps_buf; ptr; ptr = LM_STRCHR(ptr, LM_STR('\n'))) {
			lm_page_t page;

			if (ptr != maps_buf)
				ptr = &ptr[1];
			
			page.base = (lm_address_t)LM_STRTOP(ptr, NULL, 16);

#			if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
			ptr = LM_STRCHR(ptr, LM_STR('-'));
#			elif LM_OS == LM_OS_BSD
			ptr = LM_STRSTR(ptr, LM_STR(" 0x"));
#			endif

			if (!ptr)
				break; /* EOF */

			ptr = &ptr[1];

			page.end = (lm_address_t)LM_STRTOP(ptr, NULL, 16);
			page.size = (lm_size_t)(
				(lm_uintptr_t)page.end - 
				(lm_uintptr_t)page.base
			);

			page.prot  = 0;
			page.flags = 0;

#			if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
			{
				lm_size_t i;

				ptr = LM_STRCHR(ptr, LM_STR(' '));
				ptr = &ptr[1];

				for (i = 0; i < 4; ++i) {
					switch (ptr[i]) {
					case LM_STR('r'):
						page.prot |= PROT_READ;
						break;
					case LM_STR('w'):
						page.prot |= PROT_WRITE;
						break;
					case LM_STR('x'):
						page.prot |= PROT_EXEC;
						break;
					case LM_STR('p'):
						page.flags = MAP_PRIVATE;
						break;
					case LM_STR('s'):
						page.flags = MAP_SHARED;
						break;
					}
				}
			}
#			elif LM_OS == LM_OS_BSD
			{
				lm_size_t i;

				for (i = 0; i < 4; ++i) {
					ptr = LM_STRCHR(ptr, LM_STR(' '));
					ptr = &ptr[1];
				}

				for (i = 0; i < 3; ++i) {
					switch (ptr[i]) {
					case LM_STR('r'):
						page.prot |= PROT_READ;
						break;
					case LM_STR('w'):
						page.prot |= PROT_WRITE;
						break;
					case LM_STR('x'):
						page.prot |= PROT_EXEC;
						break;
					}
				}
			}
#			endif

			if (callback(page, arg) == LM_FALSE)
				break;
		}

		_LM_CloseFileBuf(&maps_buf);
	}
#	endif

	return ret;
}

static lm_bool_t
_LM_GetPageCallback(lm_page_t  page,
		    lm_void_t *arg)
{
	_lm_get_page_t *parg = (_lm_get_page_t *)arg;
	
	if ((lm_uintptr_t)parg->addr >= (lm_uintptr_t)page.base &&
	    (lm_uintptr_t)parg->addr < (lm_uintptr_t)page.end) {
		*parg->pagebuf = page;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_bool_t
LM_GetPage(lm_address_t addr,
	   lm_page_t   *page)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_page_t arg;

	if (!addr || !page)
		return ret;

	arg.addr = addr;
	arg.pagebuf = page;
	arg.pagebuf->base = (lm_address_t)LM_BAD;
	arg.pagebuf->size = 0;
	arg.pagebuf->end  = (lm_address_t)LM_BAD;

	LM_EnumPages(_LM_GetPageCallback, (lm_void_t *)&arg);

	ret = page->size > 0 ? LM_TRUE : LM_FALSE;
	return ret;
}

LM_API lm_bool_t
LM_GetPageEx(lm_process_t proc,
	     lm_address_t addr,
	     lm_page_t   *page)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_page_t arg;

	if (!_LM_ValidProcess(proc) || !addr || !page)
		return ret;

	arg.addr = addr;
	arg.pagebuf = page;
	arg.pagebuf->base = (lm_address_t)LM_BAD;
	arg.pagebuf->size = 0;
	arg.pagebuf->end  = (lm_address_t)LM_BAD;

	LM_EnumPagesEx(proc, _LM_GetPageCallback, (lm_void_t *)&arg);

	ret = page->size > 0 ? LM_TRUE : LM_FALSE;
	return ret;
}

/****************************************/

LM_API lm_size_t
LM_ReadMemory(lm_address_t src,
	      lm_byte_t   *dst,
	      lm_size_t    size)
{
	lm_size_t i;

	for (i = 0; i < size; ++i)
		dst[i] = ((lm_byte_t *)src)[i];

	return i;
}

LM_API lm_size_t
LM_ReadMemoryEx(lm_process_t proc,
		lm_address_t src,
		lm_byte_t   *dst,
		lm_size_t    size)
{
	lm_size_t rdsize = 0;

	if (!_LM_ValidProcess(proc) || !src || !dst || !size)
		return rdsize;
	
#	if LM_OS == LM_OS_WIN
	{
		rdsize = (lm_size_t)ReadProcessMemory(proc.handle, src, dst,
						      size, NULL);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		struct iovec iosrc = { 0 };
		struct iovec iodst = { 0 };
		iodst.iov_base = dst;
		iodst.iov_len  = size;
		iosrc.iov_base = src;
		iosrc.iov_len  = size;
		rdsize = (lm_size_t)process_vm_readv(proc.pid, &iodst, 1,
						     &iosrc, 1, 0);

		if (rdsize == (lm_size_t)-1)
			rdsize = 0;
	}
#	elif LM_OS == LM_OS_BSD
	{
		int fd;
		lm_tchar_t mem_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

		LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path) - 1,
			    LM_STR("%s/%d/mem"), LM_PROCFS, proc.pid);
		
		fd = open(mem_path, O_RDONLY);
		if (fd == -1)
			return rdsize;
		
		rdsize = (lm_size_t)pread(fd, dst, size, (off_t)src);
		close(fd);

		if (rdsize == (lm_size_t)-1)
			rdsize = 0;
	}
#	endif

	return rdsize;
}

LM_API lm_size_t
LM_WriteMemory(lm_address_t dst,
	       lm_bstring_t src,
	       lm_size_t    size)
{
	lm_size_t i;

	for (i = 0; i < size; ++i)
		((lm_byte_t *)dst)[i] = src[i];

	return i;
}

LM_API lm_size_t
LM_WriteMemoryEx(lm_process_t proc,
		 lm_address_t dst,
		 lm_bstring_t src,
		 lm_size_t    size)
{
	lm_size_t wrsize = 0;

	if (!_LM_ValidProcess(proc) || !dst || !src || !size)
		return wrsize;

#	if LM_OS == LM_OS_WIN
	{
		wrsize = (lm_size_t)WriteProcessMemory(proc.handle, dst, src,
						       size, NULL);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		struct iovec iosrc = { 0 };
		struct iovec iodst = { 0 };
		iosrc.iov_base = src;
		iosrc.iov_len = size;
		iodst.iov_base = dst;
		iodst.iov_len = size;
		wrsize = (lm_size_t)process_vm_writev(proc.pid, &iosrc, 1,
						      &iodst, 1, 0);

		if (wrsize == (lm_size_t)-1)
			wrsize = 0;
	}
#	elif LM_OS == LM_OS_BSD
	{
		int fd;
		lm_tchar_t mem_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

		LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path) - 1,
			    LM_STR("%s/%d/mem"), LM_PROCFS, proc.pid);
		
		fd = open(mem_path, O_WRONLY);
		if (fd == -1)
			return wrsize;
		
		wrsize = (lm_size_t)pwrite(fd, src, size, (off_t)dst);
		close(fd);

		if (wrsize == (lm_size_t)-1)
			wrsize = 0;
	}
#	endif

	return wrsize;
}

LM_API lm_size_t
LM_SetMemory(lm_byte_t *dst,
	     lm_byte_t  byte,
	     lm_size_t  size)
{
	lm_size_t i;

	for (i = 0; i < size; ++i)
		dst[i] = byte;
	
	return i;
}

LM_API lm_size_t
LM_SetMemoryEx(lm_process_t proc,
	       lm_address_t dst,
	       lm_byte_t    byte,
	       lm_size_t    size)
{
	lm_size_t  wrsize = 0;
	lm_byte_t *data;

	data = LM_MALLOC(size);
	if (!data)
		return wrsize;

	if (LM_SetMemory(data, byte, size) != size)
		return wrsize;
	
	wrsize = LM_WriteMemoryEx(proc, dst, data, size);

	LM_FREE(data);
	return wrsize;
}

LM_API lm_bool_t
LM_ProtMemory(lm_address_t addr,
	      lm_size_t    size,
	      lm_prot_t    prot,
	      lm_prot_t   *oldprot)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		DWORD old_prot;
		if (VirtualProtect(addr, size, prot, &old_prot)) {
			if (oldprot)
				*oldprot = (lm_prot_t)old_prot;
			
			ret = LM_TRUE;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		long pagesize;
		lm_page_t page;

		if (oldprot) {
			if (!LM_GetPage(addr, &page))
				return ret;
		}

		pagesize = sysconf(_SC_PAGE_SIZE);
		addr = (lm_address_t)(
			(lm_uintptr_t)addr & (lm_uintptr_t)(-pagesize)
		);
		if (!mprotect(addr, size, prot))
			ret = LM_TRUE;
		
		if (oldprot)
			*oldprot = page.prot;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_ProtMemoryEx(lm_process_t proc,
		lm_address_t addr,
		lm_size_t    size,
		lm_prot_t    prot,
		lm_prot_t   *oldprot)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc))
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		DWORD old_prot;
		if (VirtualProtectEx(proc.handle, addr, size,
				     prot, &old_prot)) {
			if (oldprot)
				*oldprot = (lm_prot_t)old_prot;
			
			ret = LM_TRUE;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		lm_datio_t   arg_nsyscall;
		lm_uintptr_t dat_nsyscall;

		lm_datio_t   arg_addr;
		lm_uintptr_t dat_addr = (lm_uintptr_t)addr;

		lm_datio_t   arg_length;
		lm_uintptr_t dat_length = (lm_uintptr_t)size;

		lm_datio_t   arg_prot;
		lm_uintptr_t dat_prot = (lm_uintptr_t)prot;

		lm_datio_t   retbuf;
		lm_uintptr_t retdat = (lm_uintptr_t)LM_BAD;

		lm_page_t    page;
		long         pagesize;

		if (oldprot) {
			if (!LM_GetPageEx(proc, addr, &page))
				return ret;
		}

		arg_nsyscall.data = (lm_byte_t *)&dat_nsyscall;
		arg_nsyscall.size = 0;

		arg_addr.data     = (lm_byte_t *)&dat_addr;
		arg_addr.size     = 0;

		arg_length.data   = (lm_byte_t *)&dat_length;
		arg_length.size   = 0;

		arg_prot.data     = (lm_byte_t *)&dat_prot;
		arg_prot.size     = 0;

		retbuf.data       = (lm_byte_t *)&retdat;

#		if LM_ARCH == LM_ARCH_X86
#		if LM_BITS == 64
		if (LM_GetProcessBitsEx(proc) == 64) {
			dat_nsyscall = 10;

			arg_nsyscall.datloc = LM_DATLOC_RAX;
			arg_addr.datloc     = LM_DATLOC_RDI;
			arg_length.datloc   = LM_DATLOC_RSI;
			arg_prot.datloc     = LM_DATLOC_RDX;
			retbuf.datloc       = LM_DATLOC_RAX;
		}
		else {
			dat_nsyscall = 125;

			arg_nsyscall.datloc = LM_DATLOC_EAX;
			arg_addr.datloc     = LM_DATLOC_EBX;
			arg_length.datloc   = LM_DATLOC_ECX;
			arg_prot.datloc     = LM_DATLOC_EDX;
			retbuf.datloc       = LM_DATLOC_EAX;
		}
#		else
		dat_nsyscall = 125;

		arg_nsyscall.datloc = LM_DATLOC_EAX;
		arg_addr.datloc     = LM_DATLOC_EBX;
		arg_length.datloc   = LM_DATLOC_ECX;
		arg_prot.datloc     = LM_DATLOC_EDX;
		retbuf.datloc       = LM_DATLOC_EAX;
#		endif
#		elif LM_ARCH == LM_ARCH_ARM
#		endif

		pagesize = sysconf(_SC_PAGE_SIZE);
		dat_addr &= -pagesize;

		LM_SystemCallEx(proc, 0, 4, 1,
				arg_nsyscall,
				arg_addr,
				arg_length,
				arg_prot,
				retbuf);
		
		if (oldprot)
			*oldprot = page.prot;
		
		if (!retdat)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		lm_datio_t   arg_nsyscall;
		lm_uintptr_t dat_nsyscall = SYS_mprotect;

		lm_datio_t   arg_addr;
		lm_uintptr_t dat_addr = (lm_uintptr_t)addr;

		lm_datio_t   arg_length;
		lm_uintptr_t dat_length = (lm_uintptr_t)size;

		lm_datio_t   arg_prot;
		lm_uintptr_t dat_prot = (lm_uintptr_t)prot;

		lm_datio_t   retbuf;
		lm_uintptr_t retdat = (lm_uintptr_t)LM_BAD;

		lm_page_t    page;
		long         pagesize;

		if (oldprot) {
			if (!LM_GetPageEx(proc, addr, &page))
				return ret;
		}

		arg_nsyscall.data = (lm_byte_t *)&dat_nsyscall;
		arg_nsyscall.size = 0;

		arg_addr.data     = (lm_byte_t *)&dat_addr;
		arg_addr.size     = 0;

		arg_length.data   = (lm_byte_t *)&dat_length;
		arg_length.size   = 0;

		arg_prot.data     = (lm_byte_t *)&dat_prot;
		arg_prot.size     = 0;

		retbuf.data       = (lm_byte_t *)&retdat;

#		if LM_ARCH == LM_ARCH_X86
#		if LM_BITS == 64
		if (LM_GetProcessBitsEx(proc) == 64) {
			arg_nsyscall.datloc = LM_DATLOC_RAX;
			arg_addr.datloc     = LM_DATLOC_RDI;
			arg_length.datloc   = LM_DATLOC_RSI;
			arg_prot.datloc     = LM_DATLOC_RDX;
			retbuf.datloc       = LM_DATLOC_RAX;
		}
		else {
			arg_nsyscall.datloc = LM_DATLOC_EAX;
			arg_addr.datloc     = LM_DATLOC_STACK;
			arg_length.datloc   = LM_DATLOC_STACK;
			arg_prot.datloc     = LM_DATLOC_STACK;
			retbuf.datloc       = LM_DATLOC_EAX;
		}
#		else
		arg_nsyscall.datloc = LM_DATLOC_EAX;
		arg_addr.datloc     = LM_DATLOC_STACK;
		arg_length.datloc   = LM_DATLOC_STACK;
		arg_prot.datloc     = LM_DATLOC_STACK;
		retbuf.datloc       = LM_DATLOC_EAX;
#		endif
#		elif LM_ARCH == LM_ARCH_ARM
#		endif

		pagesize = sysconf(_SC_PAGE_SIZE);
		dat_addr &= -pagesize;

		LM_SystemCallEx(proc, 0, 4, 1,
				arg_nsyscall,
				arg_prot,
				arg_length,
				arg_addr,
				retbuf);
		
		if (oldprot)
			*oldprot = page.prot;
		
		if (!retdat)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_address_t
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot)
{
	lm_address_t alloc = (lm_address_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		alloc = VirtualAlloc(NULL,
				     size,
				     MEM_COMMIT | MEM_RESERVE,
				     prot);
		
		if (!alloc)
			alloc = (lm_address_t)LM_BAD;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		alloc = mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANON, -1, 0);
		if (alloc == (lm_address_t)MAP_FAILED)
			alloc = (lm_address_t)LM_BAD;
	}
#	endif

	return alloc;
}

LM_API lm_address_t
LM_AllocMemoryEx(lm_process_t proc,
		 lm_size_t    size,
		 lm_prot_t    prot)
{
	lm_address_t alloc = (lm_address_t)LM_BAD;

	if (!_LM_ValidProcess(proc))
		return alloc;

#	if LM_OS == LM_OS_WIN
	{
		alloc = VirtualAllocEx(proc.handle,
				       NULL,
				       size, 
				       MEM_COMMIT | MEM_RESERVE,
				       prot);
		
		if (!alloc)
			alloc = (lm_address_t)LM_BAD;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		lm_uintptr_t nsyscall;
		lm_datio_t   arg_nsyscall;

		lm_datio_t   arg_addr;
		lm_uintptr_t dat_addr = (lm_uintptr_t)LM_NULL;

		lm_datio_t   arg_length;
		lm_uintptr_t dat_length = (lm_uintptr_t)size;

		lm_datio_t   arg_prot;
		lm_uintptr_t dat_prot = (lm_uintptr_t)prot;

		lm_datio_t   arg_flags;
		lm_uintptr_t dat_flags = MAP_PRIVATE | MAP_ANON;

		lm_datio_t   arg_fd;
		lm_uintptr_t dat_fd = (lm_uintptr_t)-1;

		lm_datio_t   arg_offset;
		lm_uintptr_t dat_offset = 0;

		lm_datio_t   retval;
		lm_uintptr_t retdat = (lm_uintptr_t)LM_BAD;

		arg_nsyscall.data = (lm_byte_t *)&nsyscall;
		arg_nsyscall.size = 0;

		arg_addr.data   = (lm_byte_t *)&dat_addr;
		arg_addr.size   = 0;

		arg_length.data = (lm_byte_t *)&dat_length;
		arg_length.size = 0;

		arg_prot.data   = (lm_byte_t *)&dat_prot;
		arg_prot.size   = 0;

		arg_flags.data  = (lm_byte_t *)&dat_flags;
		arg_flags.size  = 0;

		arg_fd.data     = (lm_byte_t *)&dat_fd;
		arg_fd.size     = 0;

		arg_offset.data = (lm_byte_t *)&dat_offset;
		arg_offset.size = 0;

		retval.data     = (lm_byte_t *)&retdat;
		retval.size     = 0;

#		if LM_ARCH == LM_ARCH_X86
#		if LM_BITS == 64
		if (LM_GetProcessBitsEx(proc) == 64) {
			nsyscall = 9;
			arg_nsyscall.datloc = LM_DATLOC_RAX;
			arg_addr.datloc     = LM_DATLOC_RDI;
			arg_length.datloc   = LM_DATLOC_RSI;
			arg_prot.datloc     = LM_DATLOC_RDX;
			arg_flags.datloc    = LM_DATLOC_R10;
			arg_fd.datloc       = LM_DATLOC_R8;
			arg_offset.datloc   = LM_DATLOC_R9;
			retval.datloc       = LM_DATLOC_RAX;
		}
		else {
			nsyscall = 192;
			arg_nsyscall.datloc = LM_DATLOC_EAX;
			arg_addr.datloc     = LM_DATLOC_EBX;
			arg_length.datloc   = LM_DATLOC_ECX;
			arg_prot.datloc     = LM_DATLOC_EDX;
			arg_flags.datloc    = LM_DATLOC_ESI;
			arg_fd.datloc       = LM_DATLOC_EDI;
			arg_offset.datloc   = LM_DATLOC_EBP;
			retval.datloc       = LM_DATLOC_EAX;
		}
#		else
		nsyscall = 192;
		arg_nsyscall.datloc = LM_DATLOC_EAX;
		arg_addr.datloc     = LM_DATLOC_EBX;
		arg_length.datloc   = LM_DATLOC_ECX;
		arg_prot.datloc     = LM_DATLOC_EDX;
		arg_flags.datloc    = LM_DATLOC_ESI;
		arg_fd.datloc       = LM_DATLOC_EDI;
		arg_offset.datloc   = LM_DATLOC_EBP;
		retval.datloc       = LM_DATLOC_EAX;
#		endif
#		elif LM_ARCH == LM_ARCH_ARM
#		endif

		LM_SystemCallEx(proc, 0, 7, 1,
				arg_nsyscall,
				arg_addr,
				arg_length,
				arg_prot,
				arg_flags,
				arg_fd,
				arg_offset,
				retval);
		
		alloc = (lm_address_t)retdat;
		
		if (alloc == (lm_address_t)MAP_FAILED || 
		    alloc == (lm_address_t)(lm_uintptr_t)nsyscall ||
		    (lm_uintptr_t)alloc >= (lm_uintptr_t)-1024 ||
		    (lm_uintptr_t)alloc <= (lm_uintptr_t)1024)
			alloc = (lm_address_t)LM_BAD;
	}
#	elif LM_OS == LM_OS_BSD
	{
		lm_uintptr_t nsyscall = SYS_mmap;
		lm_size_t    bits;
		lm_datio_t   retval;
		lm_uintptr_t retdat = (lm_uintptr_t)LM_BAD;

		retval.data = (lm_byte_t *)&retdat;
		retval.size = 0;

		bits = LM_GetProcessBitsEx(proc);

#		if LM_ARCH == LM_ARCH_X86
#		if LM_BITS == 64
		if (bits == 64) {
			lm_datio_t   arg_nsyscall;

			lm_datio_t   arg_addr;
			lm_uintptr_t dat_addr = (lm_uintptr_t)LM_NULL;

			lm_datio_t   arg_length;
			lm_uintptr_t dat_length = (lm_uintptr_t)size;

			lm_datio_t   arg_prot;
			lm_uintptr_t dat_prot = (lm_uintptr_t)prot;

			lm_datio_t   arg_flags;
			lm_uintptr_t dat_flags = MAP_PRIVATE | MAP_ANON;

			lm_datio_t   arg_fd;
			lm_uintptr_t dat_fd = (lm_uintptr_t)-1;

			lm_datio_t   arg_offset;
			lm_uintptr_t dat_offset = 0;

			arg_nsyscall.datloc = LM_DATLOC_RAX;
			arg_nsyscall.data   = (lm_byte_t *)&nsyscall;
			arg_nsyscall.size   = 0;

			arg_addr.datloc   = LM_DATLOC_RDI;
			arg_addr.data     = (lm_byte_t *)&dat_addr;
			arg_addr.size     = 0;

			arg_length.datloc = LM_DATLOC_RSI;
			arg_length.data   = (lm_byte_t *)&dat_length;
			arg_length.size   = 0;

			arg_prot.datloc   = LM_DATLOC_RDX;
			arg_prot.data     = (lm_byte_t *)&dat_prot;
			arg_prot.size     = 0;

			arg_flags.datloc  = LM_DATLOC_R10;
			arg_flags.data    = (lm_byte_t *)&dat_flags;
			arg_flags.size    = 0;

			arg_fd.datloc     = LM_DATLOC_R8;
			arg_fd.data       = (lm_byte_t *)&dat_fd;
			arg_fd.size       = 0;

			arg_offset.datloc = LM_DATLOC_R9;
			arg_offset.data   = (lm_byte_t *)&dat_offset;
			arg_offset.size   = 0;

			retval.datloc     = LM_DATLOC_RAX;

			LM_SystemCallEx(proc, 0, 7, 1,
				arg_nsyscall,
				arg_addr,
				arg_length,
				arg_prot,
				arg_flags,
				arg_fd,
				arg_offset,
				retval);
		} else {
			lm_datio_t   mmap_args;

			struct {
				void  *addr;
				size_t length;
				int    prot;
				int    flags;
				int    fd;
				off_t  offset;
			} mmap_args_dat;

			mmap_args_dat.addr   = NULL;
			mmap_args_dat.length = size;
			mmap_args_dat.prot   = prot;
			mmap_args_dat.flags  = MAP_PRIVATE | MAP_ANON;
			mmap_args_dat.fd     = -1;
			mmap_args_dat.offset = 0;

			mmap_args.datloc = LM_DATLOC_STACK;
			mmap_args.data   = (lm_byte_t *)&mmap_args_dat;
			mmap_args.size   = sizeof(mmap_args_dat);

			LM_SystemCallEx(proc, -8, 1, 1,
					mmap_args,
					retval);
		}
#		else
		{
			lm_datio_t   mmap_args;

			struct {
				void  *addr;
				size_t length;
				int    prot;
				int    flags;
				int    fd;
				off_t  offset;
			} mmap_args_dat;

			mmap_args_dat.addr   = NULL;
			mmap_args_dat.length = size;
			mmap_args_dat.prot   = prot;
			mmap_args_dat.flags  = MAP_PRIVATE | MAP_ANON;
			mmap_args_dat.fd     = -1;
			mmap_args_dat.offset = 0;

			mmap_args.datloc = LM_DATLOC_STACK;
			mmap_args.data   = (lm_byte_t *)&mmap_args_dat;
			mmap_args.size   = sizeof(mmap_args_dat);

			LM_SystemCallEx(proc, -8, 1, 1,
					mmap_args,
					retval);
		}
#		endif
#		endif

		alloc = (lm_address_t)retdat;
		
		if (alloc == (lm_address_t)MAP_FAILED || 
		    alloc == (lm_address_t)(lm_uintptr_t)nsyscall ||
		    (lm_uintptr_t)alloc >= (lm_uintptr_t)-1024 ||
		    (lm_uintptr_t)alloc <= (lm_uintptr_t)1024)
			alloc = (lm_address_t)LM_BAD;
	}
#	endif

	return alloc;
}

LM_API lm_bool_t
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		if (VirtualFree(alloc, 0, MEM_RELEASE))
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		if (!munmap(alloc, size))
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_FreeMemoryEx(lm_process_t proc,
		lm_address_t alloc,
		lm_size_t    size)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc))
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (VirtualFreeEx(proc.handle, alloc, 0, MEM_RELEASE))
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		lm_datio_t   arg_nsyscall;
		lm_uintptr_t nsyscall;

		lm_datio_t   arg_addr;
		lm_uintptr_t dat_addr = (lm_uintptr_t)alloc;

		lm_datio_t   arg_length;
		lm_uintptr_t dat_length = (lm_uintptr_t)size;

		lm_datio_t   retbuf;
		lm_uintptr_t retdat = (lm_uintptr_t)LM_BAD;

		arg_nsyscall.data = (lm_byte_t *)&nsyscall;
		arg_nsyscall.size = 0;

		arg_addr.data   = (lm_byte_t *)&dat_addr;
		arg_addr.size   = 0;

		arg_length.data = (lm_byte_t *)&dat_length;
		arg_length.size = 0;

		retbuf.data = (lm_byte_t *)&retdat;
		retbuf.size = 0;

#		if LM_ARCH == LM_ARCH_X86
#		if LM_BITS == 64
		if (LM_GetProcessBitsEx(proc) == 64) {
			nsyscall = 11;

			arg_nsyscall.datloc = LM_DATLOC_RAX;
			arg_addr.datloc     = LM_DATLOC_RDI;
			arg_length.datloc   = LM_DATLOC_RSI;
			retbuf.datloc       = LM_DATLOC_RAX;
		}
		else {
			nsyscall = 91;

			arg_nsyscall.datloc = LM_DATLOC_EAX;
			arg_addr.datloc     = LM_DATLOC_EBX;
			arg_length.datloc   = LM_DATLOC_ECX;
			retbuf.datloc       = LM_DATLOC_EAX;
		}
#		else
		nsyscall = 91;

		arg_nsyscall.datloc = LM_DATLOC_EAX;
		arg_addr.datloc     = LM_DATLOC_EBX;
		arg_length.datloc   = LM_DATLOC_ECX;
		retbuf.datloc       = LM_DATLOC_EAX;
#		endif
#		elif LM_ARCH == LM_ARCH_ARM
#		endif

		LM_SystemCallEx(proc, 0, 3, 1,
				arg_nsyscall,
				arg_addr,
				arg_length,
				retbuf);
		
		if (!retdat)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		lm_datio_t   arg_nsyscall;
		lm_uintptr_t nsyscall = SYS_munmap;

		lm_datio_t   arg_addr;
		lm_uintptr_t dat_addr = (lm_uintptr_t)alloc;

		lm_datio_t   arg_length;
		lm_uintptr_t dat_length = (lm_uintptr_t)size;

		lm_datio_t   retbuf;
		lm_uintptr_t retdat = (lm_uintptr_t)LM_BAD;

		arg_nsyscall.data = (lm_byte_t *)&nsyscall;
		arg_nsyscall.size = 0;

		arg_addr.data   = (lm_byte_t *)&dat_addr;
		arg_addr.size   = 0;

		arg_length.data = (lm_byte_t *)&dat_length;
		arg_length.size = 0;

		retbuf.data = (lm_byte_t *)&retdat;
		retbuf.size = 0;

#		if LM_ARCH == LM_ARCH_X86
#		if LM_BITS == 64
		{
			lm_size_t bits;

			bits = LM_GetProcessBitsEx(proc);

			if (bits == 64) {
				arg_nsyscall.datloc = LM_DATLOC_RAX;
				arg_addr.datloc     = LM_DATLOC_RDI;
				arg_length.datloc   = LM_DATLOC_RSI;
				retbuf.datloc       = LM_DATLOC_RAX;
			} else {
				arg_nsyscall.datloc = LM_DATLOC_EAX;
				arg_addr.datloc     = LM_DATLOC_STACK;
				arg_length.datloc   = LM_DATLOC_STACK;
				retbuf.datloc       = LM_DATLOC_EAX;
			}
		}
#		else
		{
			arg_nsyscall.datloc = LM_DATLOC_EAX;
			arg_addr.datloc     = LM_DATLOC_STACK;
			arg_length.datloc   = LM_DATLOC_STACK;
			retbuf.datloc       = LM_DATLOC_EAX;
		}
#		endif
#		elif LM_ARCH == LM_ARCH_ARM
#		endif

		LM_SystemCallEx(proc, -8, 3, 1,
				arg_nsyscall,
				arg_length,
				arg_addr,
				retbuf);
		
		if (!retdat)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_address_t
LM_DataScan(lm_bstring_t data,
	    lm_size_t    size,
	    lm_address_t start,
	    lm_address_t stop)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_byte_t   *ptr;
	lm_prot_t    oldprot;
	lm_size_t    scansize;

	if (!data || !size || !start || !stop || 
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;

	scansize = (lm_uintptr_t)stop - (lm_uintptr_t)start;
	
	if (!LM_ProtMemory(start, scansize, LM_PROT_XRW, &oldprot))
		return match;

	for (ptr = (lm_byte_t *)start;
	     ptr != (lm_byte_t *)stop;
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		for (i = 0; check && i < size; ++i)
			check = (ptr[i] == data[i]) ? check : LM_FALSE;
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	LM_ProtMemory(start, scansize, oldprot, (lm_prot_t *)LM_NULL);

	return match;
}

LM_API lm_address_t
LM_DataScanEx(lm_process_t proc,
	      lm_bstring_t data,
	      lm_size_t    size,
	      lm_address_t start,
	      lm_address_t stop)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_byte_t   *ptr;
	lm_prot_t    oldprot;
	lm_size_t    scansize;

	if (!_LM_ValidProcess(proc) || !data || !size || !start || !stop ||
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;
	
	scansize = (lm_uintptr_t)stop - (lm_uintptr_t)start;

	if (!LM_ProtMemoryEx(proc, start, scansize, LM_PROT_XRW, &oldprot))
		return match;

	for (ptr = (lm_byte_t *)start;
	     ptr != (lm_byte_t *)stop;
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		for (i = 0; check && i < size; ++i) {
			lm_byte_t curbyte = 0;

			if (!LM_ReadMemoryEx(proc, (lm_address_t)(&ptr[i]),
					     &curbyte, sizeof(curbyte))) {
				check = LM_FALSE;
				break;
			}
			
			check = (curbyte == data[i]) ? check : LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	LM_ProtMemory(start, scansize, oldprot, (lm_prot_t *)LM_NULL);

	return match;
}

LM_API lm_address_t
LM_PatternScan(lm_bstring_t pattern,
	       lm_tstring_t mask,
	       lm_address_t start,
	       lm_address_t stop)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_size_t    size;
	lm_size_t    scansize;
	lm_prot_t    oldprot;
	lm_byte_t   *ptr;

	if (!pattern || !mask || !start || !stop ||
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;

	size = LM_STRLEN(mask);
	if (!size)
		return match;
	
	scansize = (lm_uintptr_t)stop - (lm_uintptr_t)start;
	
	if (!LM_ProtMemory(start, scansize, LM_PROT_XRW, &oldprot))
		return match;
	
	for (ptr = (lm_byte_t *)start;
	     ptr != (lm_byte_t *)stop;
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		for (i = 0; check && i < size; ++i) {
			if (LM_CHKMASK(mask[i]) && ptr[i] != pattern[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}
	
	LM_ProtMemory(start, scansize, oldprot, (lm_prot_t *)LM_NULL);

	return match;
}

LM_API lm_address_t
LM_PatternScanEx(lm_process_t proc,
		 lm_bstring_t pattern,
		 lm_tstring_t mask,
		 lm_address_t start,
		 lm_address_t stop)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_size_t    size;
	lm_size_t    scansize;
	lm_prot_t    oldprot;
	lm_byte_t   *ptr;

	if (!_LM_ValidProcess(proc) || !pattern || !mask || !start || !stop ||
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;

	size = LM_STRLEN(mask);
	if (!size)
		return match;
	
	scansize = (lm_uintptr_t)stop - (lm_uintptr_t)start;
	
	if (!LM_ProtMemoryEx(proc, start, scansize, LM_PROT_XRW, &oldprot))
		return match;
	
	for (ptr = (lm_byte_t *)start;
	     ptr != (lm_byte_t *)stop;
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		for (i = 0; check && i < size; ++i) {
			lm_byte_t curbyte;

			if (!LM_ReadMemoryEx(proc, (lm_address_t)&ptr[i],
					     &curbyte, sizeof(curbyte))) {
				check = LM_FALSE;
				break;
			}

			if (LM_CHKMASK(mask[i]) && curbyte != pattern[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}
	
	LM_ProtMemoryEx(proc, start, scansize, oldprot, (lm_prot_t *)LM_NULL);

	return match;
}

LM_API lm_address_t
LM_SigScan(lm_tstring_t sig,
	   lm_address_t start,
	   lm_address_t stop)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_bstring_t pattern = (lm_byte_t *)LM_NULL;
	lm_tstring_t mask = (lm_tchar_t *)LM_NULL;
	
	if (!sig || !start || !stop ||
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;

	if (!_LM_ParseSig(sig, &pattern, &mask))
		return match;
	
	match = LM_PatternScan(pattern, mask, start, stop);

	LM_FREE(pattern);
	LM_FREE(mask);

	return match;
}

LM_API lm_address_t
LM_SigScanEx(lm_process_t proc,
	     lm_tstring_t sig,
	     lm_address_t start,
	     lm_address_t stop)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_byte_t   *pattern = (lm_byte_t *)LM_NULL;
	lm_tchar_t  *mask = (lm_tchar_t *)LM_NULL;

	if (!_LM_ValidProcess(proc) || !sig || !start || !stop ||
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;
	
	if (!_LM_ParseSig(sig, &pattern, &mask))
		return match;
	
	match = LM_PatternScanEx(proc, pattern, mask, start, stop);

	LM_FREE(pattern);
	LM_FREE(mask);

	return match;
}

/****************************************/

LM_API lm_uintptr_t
LM_SystemCall(lm_int_t     nsyscall,
	      lm_uintptr_t arg0,
	      lm_uintptr_t arg1,
	      lm_uintptr_t arg2,
	      lm_uintptr_t arg3,
	      lm_uintptr_t arg4,
	      lm_uintptr_t arg5)
{
	lm_uintptr_t syscall_ret = (lm_uintptr_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		syscall_ret = (lm_uintptr_t)syscall(nsyscall,
						    arg0, arg1, arg2,
						    arg3, arg4, arg5);
	}
#	endif

	return syscall_ret;
}

LM_API lm_bool_t
LM_SystemCallEx(lm_process_t proc,
		lm_size_t    stack_align,
		lm_size_t    nargs,
		lm_size_t    nrets,
		...)
{
	lm_bool_t    ret = LM_FALSE;
	lm_size_t    bits;
	lm_bool_t    attached;
	lm_regs_t    regs;
	lm_regs_t    post_regs;
	lm_datio_t  *datargs = (lm_datio_t *)LM_NULL;

	if (!_LM_ValidProcess(proc))
		return ret;

	bits = LM_GetProcessBitsEx(proc);
	if (bits > LM_GetProcessBits())
		return ret;
	
	attached = LM_DebugCheck(proc);
	if (attached != LM_TRUE) {
		LM_DebugAttach(proc);
		LM_DebugWait();
	}

	if (nargs + nrets > 0)
	{
		va_list   args;
		lm_size_t i;

		datargs = LM_CALLOC(nargs + nrets, sizeof(lm_datio_t));
		if (!datargs)
			return ret;

		va_start(args, nrets);

		for (i = 0; i < nargs + nrets; ++i) {
			datargs[i] = va_arg(args, lm_datio_t);
		}

		va_end(args);
	}

	LM_DebugGetRegs(proc, &regs);
	if (datargs)
		_LM_ParseDatArgsIn(proc, datargs, nargs, stack_align, &regs);

#	if LM_ARCH == LM_ARCH_X86
	{
#		if LM_BITS == 64
		if (bits == 64) {
			lm_byte_t code[] = {
				0x0F, 0x05, /* syscall */
			};

			LM_DebugInjectSingle(proc, code, sizeof(code), regs, &post_regs);
		}
		else {
			lm_byte_t code[] = {
				0xCD, 0x80, /* int $80 */
			};

			LM_DebugInjectSingle(proc, code, sizeof(code), regs, &post_regs);
		}
#		else
		{
			lm_byte_t code[] = {
				0xCD, 0x80 /* int $80 */
			};

			LM_DebugInjectSingle(proc, code, sizeof(code), regs, &post_regs);
		}
#		endif

		ret = LM_TRUE;
	}
#	elif LM_ARCH == LM_ARCH_ARM
	{

	}
#	endif

	if (datargs)
		_LM_ParseDatArgsOut(proc, &datargs[nargs], nrets, stack_align, post_regs);

	if (attached != LM_TRUE) {
		LM_DebugDetach(proc);
	}

	return ret;
}

LM_API lm_uintptr_t
LM_FunctionCall(lm_address_t fnaddr,
		lm_size_t    nargs,
		...);

LM_API lm_bool_t
LM_FunctionCallEx(lm_process_t proc,
		  lm_uintptr_t stack_align,
		  lm_address_t fnaddr,
		  lm_size_t    nargs,
		  lm_size_t    nrets,
		  ...)
{
	lm_bool_t   ret = LM_FALSE;
	lm_datio_t *datargs = (lm_datio_t *)LM_NULL;
	lm_size_t   bits;
	lm_regs_t   regs;
	lm_regs_t   post_regs;
	lm_int_t    attached;

	if (!_LM_ValidProcess(proc))
		return ret;
	
	bits = LM_GetProcessBitsEx(proc);
	attached = LM_DebugCheck(proc);
	
	if (nargs + nrets > 0) {
		va_list   args;
		lm_size_t i;

		datargs = LM_CALLOC(nargs + nrets, sizeof(lm_datio_t));
		if (!datargs)
			return ret;
		
		va_start(args, nrets);

		for (i = 0; i < nargs + nrets; ++i)
			datargs[i] = va_arg(args, lm_datio_t);

		va_end(args);
	}

	if (attached != LM_TRUE) {
		LM_DebugAttach(proc);
		LM_DebugWait();
	}
	
	LM_DebugGetRegs(proc, &regs);

#	if LM_ARCH == LM_ARCH_X86
	_LM_ParseDatArgsIn(proc, datargs, nargs, stack_align, &regs);

	if (bits == 64) {
		lm_byte_t code[] = {
			0xFF, 0x15, 0x1, 0x0, 0x0, 0x0,        /* call *1(%rip) */
			0xCC,                                  /* int3 */
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 /* <abs_addr> */
		};

		*(lm_uintptr_t *)&code[7] = (lm_uintptr_t)fnaddr;

		LM_DebugInject(proc, code, sizeof(code),
				regs, &post_regs);
	} else {
		lm_byte_t code[] = {
			0xE8, 0x0, 0x0, 0x0, 0x0, /* call <rel_addr> */
			0xCC                      /* int3 */
		};

		*(lm_uintptr_t *)&code[1] = (lm_uintptr_t)(
			(lm_uintptr_t)fnaddr - 
			(lm_uintptr_t)LM_DebugReadReg(LM_DATLOC_EIP, regs) -
			5
		);

		LM_DebugInject(proc, code, sizeof(code),
				regs, &post_regs);
	}

	_LM_ParseDatArgsOut(proc, &datargs[nargs], nrets,
			    stack_align, post_regs);

	ret = LM_TRUE;
#	elif LM_ARCH == LM_ARCH_ARM
	{

	}
#	endif


	if (datargs)
		LM_FREE(datargs);
	
	if (attached != LM_TRUE)
		LM_DebugDetach(proc);

	return ret;
}

LM_API lm_bool_t
LM_DetourCode(lm_address_t src,
	      lm_address_t dst,
	      lm_detour_t  detour)
{
	lm_bool_t  ret = LM_FALSE;
	lm_byte_t *buf = (lm_byte_t *)LM_NULL;
	lm_size_t  size;
	lm_prot_t  old_prot = LM_PROT_XRW;

	size = _LM_DetourPayload(src, dst, detour, LM_GetProcessBits(), &buf);
	if (!size || !buf)
		return ret;
	
	if (!LM_ProtMemory(src, size, LM_PROT_XRW, &old_prot))
		goto _FREE_EXIT;

	ret = LM_WriteMemory(src, buf, size) == size ? LM_TRUE : ret;
	LM_ProtMemory(src, size, old_prot, LM_NULLPTR);
_FREE_EXIT:
	LM_FREE(buf);

	return ret;
}

LM_API lm_bool_t
LM_DetourCodeEx(lm_process_t proc,
		lm_address_t src,
		lm_address_t dst,
		lm_detour_t  detour)
{
	lm_bool_t  ret = LM_FALSE;
	lm_byte_t *buf = (lm_byte_t *)LM_NULL;
	lm_size_t  size;
	lm_prot_t  old_prot = LM_PROT_XRW;

	size = _LM_DetourPayload(src, dst, detour,
				 LM_GetProcessBitsEx(proc), &buf);
	if (!size || !buf)
		return ret;
	
	if (!LM_ProtMemoryEx(proc, src, size, LM_PROT_XRW, &old_prot))
		goto _FREE_EXIT;

	ret = LM_WriteMemoryEx(proc, src, buf, size) == size ? LM_TRUE : ret;
	LM_ProtMemoryEx(proc, src, size, old_prot, LM_NULLPTR);
_FREE_EXIT:
	LM_FREE(buf);

	return ret;
}

LM_API lm_address_t
LM_MakeTrampoline(lm_address_t src,
		  lm_size_t    size)
{
	lm_address_t tramp = (lm_address_t)LM_BAD;
	lm_prot_t    old_prot = LM_PROT_XRW;

	if (!LM_ProtMemory(src, size, LM_PROT_XRW, &old_prot))
		return tramp;

#	if LM_ARCH == LM_ARCH_X86
	{
		lm_byte_t *payload = (lm_byte_t *)LM_NULL;
		lm_size_t  payload_size;
		
		payload_size = _LM_DetourPayload(LM_NULLPTR,
						 &((lm_byte_t *)src)[size],
						 LM_DETOUR_JMP64,
						 LM_GetProcessBits(),
						 &payload);
		
		if (!payload_size || !payload)
			return tramp;

		tramp = LM_AllocMemory(size + payload_size, LM_PROT_XRW);
		if (!tramp)
			goto _FREE_PAYLOAD;
		
		LM_WriteMemory(tramp, src, size);
		LM_WriteMemory((lm_address_t)(&((lm_byte_t *)tramp)[size]),
			       payload,
			       payload_size);
	_FREE_PAYLOAD:
		LM_FREE(payload);
	}
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	LM_ProtMemory(src, size, old_prot, LM_NULLPTR);

	return tramp;
}

LM_API lm_address_t
LM_MakeTrampolineEx(lm_process_t proc,
		    lm_address_t src,
		    lm_size_t    size)
{
	lm_address_t tramp = (lm_address_t)LM_BAD;
	lm_prot_t    old_prot = LM_PROT_XRW;

	if (!LM_ProtMemoryEx(proc, src, size, LM_PROT_XRW, &old_prot))
		return tramp;

#	if LM_ARCH == LM_ARCH_X86
	{
		lm_byte_t *payload = (lm_byte_t *)LM_NULL;
		lm_size_t  payload_size;
		
		payload_size = _LM_DetourPayload(LM_NULLPTR,
						 &((lm_byte_t *)src)[size],
						 LM_DETOUR_JMP64,
						 LM_GetProcessBits(),
						 &payload);
		
		if (!payload_size || !payload)
			return tramp;

		tramp = LM_AllocMemoryEx(proc, size + payload_size,
					 LM_PROT_XRW);
		if (!tramp)
			goto _FREE_PAYLOAD;
		
		LM_WriteMemoryEx(proc, tramp, src, size);
		LM_WriteMemoryEx(proc,
				 (lm_address_t)(&((lm_byte_t *)tramp)[size]),
				 payload,
				 payload_size);
	_FREE_PAYLOAD:
		LM_FREE(payload);
	}
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	LM_ProtMemoryEx(proc, src, size, old_prot, LM_NULLPTR);

	return tramp;
}

LM_API lm_void_t
LM_DestroyTrampoline(lm_address_t tramp)
{
	if (tramp)
		LM_FreeMemory(tramp, 1);
}

LM_API lm_void_t
LM_DestroyTrampolineEx(lm_process_t proc,
		       lm_address_t tramp)
{
	if (tramp)
		LM_FreeMemoryEx(proc, tramp, 1);
}

/****************************************/

LM_API lm_bool_t
LM_DebugAttach(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc))
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (DebugActiveProcess(proc.pid))
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		if (ptrace(PTRACE_ATTACH, proc.pid, NULL, NULL) != -1)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		if (ptrace(PT_ATTACH, proc.pid, NULL, 0) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugDetach(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		if (DebugActiveProcessStop(proc.pid))
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		if (ptrace(PTRACE_DETACH, proc.pid, NULL, NULL) != -1)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		if (ptrace(PT_DETACH, proc.pid, NULL, 0) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_int_t
LM_DebugCheck(lm_process_t proc)
{
	lm_int_t state = (lm_int_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		BOOL Check;

		CheckRemoteDebuggerPresent(proc.handle, &Check);
		state = Check == TRUE ? LM_TRUE : LM_FALSE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t  status_path[64] = { 0 };
		lm_tchar_t *status_buf;
		lm_tchar_t *ptr;

		LM_SNPRINTF(status_path, LM_ARRLEN(status_path) - 1,
			    LM_STR("/proc/%d/status"), proc.pid);

		if (!_LM_OpenFileBuf(status_path, &status_buf))
			return state;
		
		ptr = LM_STRSTR(status_buf, LM_STR("TracerPid:"));
		ptr = LM_STRCHR(ptr, LM_STR('\t'));
		ptr = &ptr[1];

		if (LM_ATOI(ptr))
			state = LM_TRUE;
		else
			state = LM_FALSE;
		
		_LM_CloseFileBuf(&status_buf);
	}
#	elif LM_OS == LM_OS_BSD
	{

	}
#	endif

	return state;
}

LM_API lm_bool_t
LM_DebugRead(lm_process_t proc,
	     lm_address_t src,
	     lm_byte_t   *dst,
	     lm_size_t    size)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		ret = LM_ReadMemoryEx(proc, src, dst, size);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		ret = _LM_PtraceRead(proc, src, dst, size);
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugWrite(lm_process_t proc,
	      lm_address_t dst,
	      lm_byte_t   *src,
	      lm_size_t    size)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		ret = LM_ReadMemoryEx(proc, src, dst, size);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		ret = _LM_PtraceWrite(proc, dst, src, size);
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugGetRegs(lm_process_t proc,
		lm_regs_t   *regsbuf)
{
	lm_bool_t ret = LM_FALSE;

	if (!regsbuf)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		lm_tid_t tid;

		tid = LM_GetThreadIdEx(proc);
		if (tid != (lm_tid_t)LM_BAD) {
			HANDLE  hThread;

			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
			if (!hThread)
				return ret;
			
#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64) {
				if (GetThreadContext(hThread, &regsbuf->regs))
					ret = LM_TRUE;
			} else {
				if (Wow64GetThreadContext(hThread,
							  &regsbuf->regs32))
					ret = LM_TRUE;
			}
#			else
			if (GetThreadContext(hThread, &regsbuf->regs))
				ret = LM_TRUE;
#			endif

			CloseHandle(hThread);
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
#		if LM_ARCH == LM_ARCH_X86
		if (ptrace(PTRACE_GETREGS, proc.pid,
			   NULL, &regsbuf->regs) != -1 &&
		    ptrace(PTRACE_GETFPREGS, proc.pid,
			   NULL, &regsbuf->fpregs) != -1)
			ret = LM_TRUE;
		
		ret = LM_TRUE;
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
#	elif LM_OS == LM_OS_BSD
	{
#		if LM_ARCH == LM_ARCH_X86
		if (ptrace(PT_GETREGS, proc.pid,
			   (caddr_t)&regsbuf->regs, 0) != -1 &&
		    ptrace(PT_GETFPREGS, proc.pid,
			   (caddr_t)&regsbuf->fpregs, 0) != -1)
			ret = LM_TRUE;
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
#	endif

	return ret;
}

LM_API lm_void_t *
LM_DebugPickReg(lm_datloc_t regid,
	       lm_regs_t  *regs)
{
	lm_void_t *preg = (lm_void_t *)LM_NULL;

#	if LM_OS == LM_OS_WIN
#	if LM_ARCH == LM_ARCH_X86
#	if LM_BITS == 64
	switch (regid) {
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs32.Eax;
		break;
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs32.Ebx;
		break;
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs32.Ecx;
		break;
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs32.Edx;
		break;
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs32.Esi;
		break;
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs32.Edi;
		break;
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs32.Esp;
		break;
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs32.Ebp;
		break;
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs32.Eip;
		break;
	case LM_DATLOC_RAX:
		preg = (lm_void_t *)&regs->regs.Rax;
		break;
	case LM_DATLOC_RBX:
		preg = (lm_void_t *)&regs->regs.Rbx;
		break;
	case LM_DATLOC_RCX:
		preg = (lm_void_t *)&regs->regs.Rcx;
		break;
	case LM_DATLOC_RDX:
		preg = (lm_void_t *)&regs->regs.Rdx;
		break;
	case LM_DATLOC_RSI:
		preg = (lm_void_t *)&regs->regs.Rsi;
		break;
	case LM_DATLOC_RDI:
		preg = (lm_void_t *)&regs->regs.Rdi;
		break;
	case LM_DATLOC_RSP:
		preg = (lm_void_t *)&regs->regs.Rsp;
		break;
	case LM_DATLOC_RBP:
		preg = (lm_void_t *)&regs->regs.Rbp;
		break;
	case LM_DATLOC_RIP:
		preg = (lm_void_t *)&regs->regs.Rip;
		break;
	case LM_DATLOC_R8:
		preg = (lm_void_t *)&regs->regs.R8;
		break;
	case LM_DATLOC_R9:
		preg = (lm_void_t *)&regs->regs.R9;
		break;
	case LM_DATLOC_R10:
		preg = (lm_void_t *)&regs->regs.R10;
		break;
	case LM_DATLOC_R11:
		preg = (lm_void_t *)&regs->regs.R11;
		break;
	case LM_DATLOC_R12:
		preg = (lm_void_t *)&regs->regs.R12;
		break;
	case LM_DATLOC_R13:
		preg = (lm_void_t *)&regs->regs.R13;
		break;
	case LM_DATLOC_R14:
		preg = (lm_void_t *)&regs->regs.R14;
		break;
	case LM_DATLOC_R15:
		preg = (lm_void_t *)&regs->regs.R15;
		break;
	}
#	else
	switch (regid) {
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.Eax;
		break;
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.Ebx;
		break;
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.Ecx;
		break;
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.Edx;
		break;
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.Esi;
		break;
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.Edi;
		break;
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.Esp;
		break;
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.Ebp;
		break;
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.Eip;
		break;
	}
#	endif
#	elif LM_ARCH == LM_ARCH_ARM
#	endif
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
#	if LM_ARCH == LM_ARCH_X86
#	if LM_BITS == 64
	switch (regid) {
	case LM_DATLOC_RAX:
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.rax;
		break;
	case LM_DATLOC_RBX:
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.rbx;
		break;
	case LM_DATLOC_RCX:
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.rcx;
		break;
	case LM_DATLOC_RDX:
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.rdx;
		break;
	case LM_DATLOC_RSI:
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.rsi;
		break;
	case LM_DATLOC_RDI:
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.rdi;
		break;
	case LM_DATLOC_RSP:
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.rsp;
		break;
	case LM_DATLOC_RBP:
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.rbp;
		break;
	case LM_DATLOC_RIP:
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.rip;
		break;
	case LM_DATLOC_R8:
		preg = (lm_void_t *)&regs->regs.r8;
		break;
	case LM_DATLOC_R9:
		preg = (lm_void_t *)&regs->regs.r9;
		break;
	case LM_DATLOC_R10:
		preg = (lm_void_t *)&regs->regs.r10;
		break;
	case LM_DATLOC_R11:
		preg = (lm_void_t *)&regs->regs.r11;
		break;
	case LM_DATLOC_R12:
		preg = (lm_void_t *)&regs->regs.r12;
		break;
	case LM_DATLOC_R13:
		preg = (lm_void_t *)&regs->regs.r13;
		break;
	case LM_DATLOC_R14:
		preg = (lm_void_t *)&regs->regs.r14;
		break;
	case LM_DATLOC_R15:
		preg = (lm_void_t *)&regs->regs.r15;
		break;
	}
#	else
	switch (regid) {
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.eax;
		break;
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.ebx;
		break;
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.ecx;
		break;
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.edx;
		break;
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.esi;
		break;
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.edi;
		break;
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.esp;
		break;
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.ebp;
		break;
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.eip;
		break;
	}
#	endif
#	elif LM_ARCH == LM_ARCH_ARM
#	endif
#	elif LM_OS == LM_OS_BSD
#	if LM_ARCH == LM_ARCH_X86
#	if LM_BITS == 64
	switch (regid) {
	case LM_DATLOC_RAX:
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.r_rax;
		break;
	case LM_DATLOC_RBX:
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.r_rbx;
		break;
	case LM_DATLOC_RCX:
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.r_rcx;
		break;
	case LM_DATLOC_RDX:
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.r_rdx;
		break;
	case LM_DATLOC_RSI:
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.r_rsi;
		break;
	case LM_DATLOC_RDI:
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.r_rdi;
		break;
	case LM_DATLOC_RSP:
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.r_rsp;
		break;
	case LM_DATLOC_RBP:
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.r_rbp;
		break;
	case LM_DATLOC_RIP:
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.r_rip;
		break;
	case LM_DATLOC_R8:
		preg = (lm_void_t *)&regs->regs.r_r8;
		break;
	case LM_DATLOC_R9:
		preg = (lm_void_t *)&regs->regs.r_r9;
		break;
	case LM_DATLOC_R10:
		preg = (lm_void_t *)&regs->regs.r_r10;
		break;
	case LM_DATLOC_R11:
		preg = (lm_void_t *)&regs->regs.r_r11;
		break;
	case LM_DATLOC_R12:
		preg = (lm_void_t *)&regs->regs.r_r12;
		break;
	case LM_DATLOC_R13:
		preg = (lm_void_t *)&regs->regs.r_r13;
		break;
	case LM_DATLOC_R14:
		preg = (lm_void_t *)&regs->regs.r_r14;
		break;
	case LM_DATLOC_R15:
		preg = (lm_void_t *)&regs->regs.r_r15;
		break;
	}
#	else
	switch (regid) {
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.r_eax;
		break;
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.r_ebx;
		break;
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.r_ecx;
		break;
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.r_edx;
		break;
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.r_esi;
		break;
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.r_edi;
		break;
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.r_esp;
		break;
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.r_ebp;
		break;
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.r_eip;
		break;
	}
#	endif
#	elif LM_ARCH == LM_ARCH_ARM
#	endif
#	endif

	return preg;
}

LM_API lm_bool_t
LM_DebugSetRegs(lm_process_t proc,
		lm_regs_t    regs)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		lm_tid_t tid;

		tid = LM_GetThreadIdEx(proc);
		if (tid != (lm_tid_t)LM_BAD) {
			HANDLE  hThread;

			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
			if (!hThread)
				return ret;
			
#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64) {
				if (SetThreadContext(hThread, &regs.regs))
					ret = LM_TRUE;
			} else {
				if (Wow64SetThreadContext(hThread,
							  &regs.regs32))
					ret = LM_TRUE;
			}
#			else
			if (SetThreadContext(hThread, &regs.regs))
				ret = LM_TRUE;
#			endif

			CloseHandle(hThread);
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
#		if LM_ARCH == LM_ARCH_X86
		if (ptrace(PTRACE_SETREGS, proc.pid,
			   NULL, &regs.regs) != -1 &&
		    ptrace(PTRACE_SETFPREGS, proc.pid,
		    	   NULL, &regs.fpregs) != -1)
			ret = LM_TRUE;
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
#	elif LM_OS == LM_OS_BSD
	{
#		if LM_ARCH == LM_ARCH_X86
		if (ptrace(PT_SETREGS, proc.pid,
			   (caddr_t)&regs.regs, 0) != -1 &&
		    ptrace(PT_SETFPREGS, proc.pid,
		    	   (caddr_t)&regs.fpregs, 0) != -1)
			ret = LM_TRUE;
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
#	endif

	return ret;
}

LM_API lm_uintptr_t
LM_DebugReadReg(lm_datloc_t regid,
		lm_regs_t   regs)
{
	lm_uintptr_t val = (lm_uintptr_t)LM_BAD;
	lm_void_t   *preg;

	preg = LM_DebugPickReg(regid, &regs);
	if (preg) {
#		if LM_OS == LM_OS_WIN
#		if LM_BITS == 64
		if (regid < LM_DATLOC_RAX) {
			/* 32-bit register */

			val = (lm_uintptr_t)(*(lm_uint32_t *)preg);
		} else {
			val = *(lm_uintptr_t *)preg;
		}
#		else
		val = *(lm_uintptr_t *)preg;
#		endif
#		else
		val = *(lm_uintptr_t *)preg;
#		endif
	}

	return val;
}

LM_API lm_bool_t
LM_DebugWriteReg(lm_datloc_t  regid,
		 lm_uintptr_t data,
		 lm_regs_t   *regs)
{
	lm_bool_t    ret = LM_FALSE;
	lm_void_t   *preg;

	preg = LM_DebugPickReg(regid, regs);
	if (preg) {
#		if LM_OS == LM_OS_WIN
#		if LM_BITS == 64
		if (regid < LM_DATLOC_RAX)
			*(lm_uint32_t *)preg = (lm_uint32_t)data;
		else
			*(lm_uintptr_t *)preg = data;
#		else
		*(lm_uintptr_t *)preg = data;
#		endif
#		else
		*(lm_uintptr_t *)preg = data;
#		endif

		ret = LM_TRUE;
	}

	return ret;
}

LM_API lm_bool_t
LM_DebugContinue(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{

	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		if (ptrace(PTRACE_CONT, proc.pid, NULL, NULL) != -1)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		if (ptrace(PT_CONTINUE, proc.pid, (caddr_t)1, 0) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugStep(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		if (ptrace(PTRACE_SINGLESTEP, proc.pid, NULL, NULL) != -1)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		if (ptrace(PT_STEP, proc.pid, (caddr_t)NULL, 0) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugWait(lm_void_t)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		int status;

		if (wait(&status) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugWaitProcess(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{

	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		int status;

		if (waitpid(proc.pid, &status, WSTOPPED) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugInject(lm_process_t proc,
	       lm_bstring_t payload,
	       lm_size_t    size,
	       lm_regs_t    regs,
	       lm_regs_t   *post_regs)
{
	return _LM_DebugInject(proc,
			       payload,
			       size,
			       regs,
			       post_regs,
			       LM_DebugContinue);
}

LM_API lm_bool_t
LM_DebugInjectSingle(lm_process_t proc,
		     lm_bstring_t payload,
		     lm_size_t    size,
		     lm_regs_t    regs,
		     lm_regs_t   *post_regs)
{
	return _LM_DebugInject(proc,
			       payload,
			       size,
			       regs,
			       post_regs,
			       LM_DebugStep);
}

#endif
