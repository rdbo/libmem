/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

#include <libmem.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "helpers.c"
#if LM_OS == LM_OS_WIN
#	include "peparser.c"
#else
#	include "elfparser.c"
#endif
#include "process.c"
#include "thread.c"
#include "module.c"
#include "symbols.c"

#if LM_COMPATIBLE
/* Additional Types */
typedef struct {
	lm_address_t addr;
	lm_page_t   *pagebuf;
} _lm_get_page_t;

/* Helpers */
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

		pattern = (lm_byte_t *)LM_CALLOC(len + 1, sizeof(lm_byte_t));
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

		mask = (lm_tchar_t *)LM_CALLOC(len + 2, sizeof(lm_tchar_t));
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

		*buf = (lm_byte_t *)LM_MALLOC(size);
		LM_MEMCPY(*buf, payload, size);
		break;
	}
	case LM_DETOUR_JMP64:
	case LM_DETOUR_ANY:
	{
		if (bits == 64) {
			lm_byte_t payload[] = {
			     0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, /* jmp [rip] */
			     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uintptr_t *)&payload[6] = (lm_uintptr_t)dst;

			*buf = (lm_byte_t *)LM_MALLOC(size);
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

			*buf = (lm_byte_t *)LM_MALLOC(size);
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

		*buf = (lm_byte_t *)LM_MALLOC(size);
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

			*buf = (lm_byte_t *)LM_MALLOC(size);
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

			*buf = (lm_byte_t *)LM_MALLOC(size);
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
					(lm_uintptr_t)(
						*(lm_uint32_t *)stack_ptr
					)
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
#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
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
	
	buf = (lm_byte_t *)LM_CALLOC(aligned_size, sizeof(lm_byte_t));
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
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
			    LM_STR("%s/%d/maps"), LM_PROCFS, proc.pid);
#		elif LM_OS == LM_OS_BSD
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
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

		LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path),
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

		LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path),
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

	data = (lm_byte_t *)LM_MALLOC(size);
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
	    lm_address_t addr,
	    lm_size_t    scansize)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_byte_t   *ptr;
	lm_page_t    oldpage;

	if (!data || !size || !scansize || addr == (lm_address_t)LM_BAD)
		return match;
	
	if (!LM_GetPage(addr, &oldpage))
		return match;
	
	LM_ProtMemory(oldpage.base, oldpage.size,
		      LM_PROT_XRW, (lm_prot_t *)LM_NULL);

	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		if ((lm_uintptr_t)ptr >= (lm_uintptr_t)oldpage.end) {
			LM_ProtMemory(oldpage.base, oldpage.size,
				      oldpage.prot, (lm_prot_t *)LM_NULL);

			if (!LM_GetPage(ptr, &oldpage))
				break;
			
			LM_ProtMemory(oldpage.base, oldpage.size,
				      LM_PROT_XRW, (lm_prot_t *)LM_NULL);
		}

		for (i = 0; check && i < size; ++i) {
			if (ptr[i] != data[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	LM_ProtMemory(oldpage.base, oldpage.size,
		      oldpage.prot, (lm_prot_t *)LM_NULL);

	return match;
}

LM_API lm_address_t
LM_DataScanEx(lm_process_t proc,
	      lm_bstring_t data,
	      lm_size_t    size,
	      lm_address_t addr,
	      lm_size_t    scansize)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_byte_t   *ptr;
	lm_page_t    oldpage;

	if (!_LM_ValidProcess(proc) || !data || !size ||
	    !scansize || addr == (lm_address_t)LM_BAD)
		return match;
	
	if (!LM_GetPageEx(proc, addr, &oldpage))
		return match;
	
	LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
			LM_PROT_XRW, (lm_prot_t *)LM_NULL);

	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		if ((lm_uintptr_t)ptr >= (lm_uintptr_t)oldpage.end) {
			LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
					oldpage.prot, (lm_prot_t *)LM_NULL);

			if (!LM_GetPageEx(proc, ptr, &oldpage))
				break;
			
			LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
					LM_PROT_XRW, (lm_prot_t *)LM_NULL);
		}

		for (i = 0; check && i < size; ++i) {
			lm_byte_t b;

			LM_ReadMemoryEx(proc, (lm_address_t)&ptr[i], &b, sizeof(b));

			if (b != data[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
			oldpage.prot, (lm_prot_t *)LM_NULL);

	return match;
}

LM_API lm_address_t
LM_PatternScan(lm_bstring_t pattern,
	       lm_tstring_t mask,
	       lm_address_t addr,
	       lm_size_t    scansize)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_size_t    size;
	lm_page_t    oldpage;
	lm_byte_t   *ptr;

	if (!pattern || !mask || !scansize || addr == (lm_address_t)LM_BAD)
		return match;

	size = LM_STRLEN(mask);
	if (!size)
		return match;
	
	if (!LM_GetPage(addr, &oldpage))
		return match;
	
	LM_ProtMemory(oldpage.base, oldpage.size,
		      LM_PROT_XRW, (lm_prot_t *)LM_NULL);
	
	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		if ((lm_uintptr_t)ptr >= (lm_uintptr_t)oldpage.end) {
			LM_ProtMemory(oldpage.base, oldpage.size,
				      oldpage.prot, (lm_prot_t *)LM_NULL);

			if (!LM_GetPage(ptr, &oldpage))
				break;
			
			LM_ProtMemory(oldpage.base, oldpage.size,
				      LM_PROT_XRW, (lm_prot_t *)LM_NULL);
		}

		for (i = 0; check && i < size; ++i) {
			if (LM_CHKMASK(mask[i]) && ptr[i] != pattern[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}
	
	LM_ProtMemory(oldpage.base, oldpage.size,
		      oldpage.prot, (lm_prot_t *)LM_NULL);

	return match;
}

LM_API lm_address_t
LM_PatternScanEx(lm_process_t proc,
		 lm_bstring_t pattern,
		 lm_tstring_t mask,
		 lm_address_t addr,
		 lm_size_t    scansize)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_size_t    size;
	lm_page_t    oldpage;
	lm_byte_t   *ptr;

	if (!_LM_ValidProcess(proc) || !pattern || !mask ||
	    !scansize || addr == (lm_address_t)LM_BAD)
		return match;

	size = LM_STRLEN(mask);
	if (!size)
		return match;
	
	if (!LM_GetPageEx(proc, addr, &oldpage))
		return match;
	
	LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
			LM_PROT_XRW, (lm_prot_t *)LM_NULL);
	
	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		if ((lm_uintptr_t)ptr >= (lm_uintptr_t)oldpage.end) {
			LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
					oldpage.prot, (lm_prot_t *)LM_NULL);

			if (!LM_GetPageEx(proc, ptr, &oldpage))
				break;
			
			LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
					LM_PROT_XRW, (lm_prot_t *)LM_NULL);
		}

		for (i = 0; check && i < size; ++i) {
			lm_byte_t b;

			LM_ReadMemoryEx(proc, &ptr[i], &b, sizeof(b));

			if (LM_CHKMASK(mask[i]) && b != pattern[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}
	
	LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
			oldpage.prot, (lm_prot_t *)LM_NULL);

	return match;
}

LM_API lm_address_t
LM_SigScan(lm_tstring_t sig,
	   lm_address_t addr,
	   lm_size_t    scansize)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_bstring_t pattern = (lm_byte_t *)LM_NULL;
	lm_tstring_t mask = (lm_tchar_t *)LM_NULL;
	
	if (!sig || !addr || addr == (lm_address_t)LM_BAD)
		return match;

	if (!_LM_ParseSig(sig, &pattern, &mask))
		return match;
	
	match = LM_PatternScan(pattern, mask, addr, scansize);

	LM_FREE(pattern);
	LM_FREE(mask);

	return match;
}

LM_API lm_address_t
LM_SigScanEx(lm_process_t proc,
	     lm_tstring_t sig,
	     lm_address_t addr,
	     lm_size_t    scansize)
{
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_byte_t   *pattern = (lm_byte_t *)LM_NULL;
	lm_tchar_t  *mask = (lm_tchar_t *)LM_NULL;

	if (!_LM_ValidProcess(proc) || !sig ||
	    !scansize || addr == (lm_address_t)LM_BAD)
		return match;
	
	if (!_LM_ParseSig(sig, &pattern, &mask))
		return match;
	
	match = LM_PatternScanEx(proc, pattern, mask, addr, scansize);

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

		datargs = (lm_datio_t *)LM_CALLOC(nargs + nrets,
						  sizeof(lm_datio_t));
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

		datargs = (lm_datio_t *)LM_CALLOC(nargs + nrets,
						  sizeof(lm_datio_t));
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
	LM_ProtMemory(src, size, old_prot, (lm_prot_t *)LM_NULLPTR);
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
	LM_ProtMemoryEx(proc, src, size, old_prot, (lm_prot_t *)LM_NULLPTR);
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
		
		LM_WriteMemory(tramp, (lm_bstring_t)src, size);
		LM_WriteMemory((lm_address_t)(&((lm_byte_t *)tramp)[size]),
			       payload,
			       payload_size);
	_FREE_PAYLOAD:
		LM_FREE(payload);
	}
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	LM_ProtMemory(src, size, old_prot, (lm_prot_t *)LM_NULLPTR);

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
		
		LM_WriteMemoryEx(proc, tramp, (lm_bstring_t)src, size);
		LM_WriteMemoryEx(proc,
				 (lm_address_t)(&((lm_byte_t *)tramp)[size]),
				 payload,
				 payload_size);
	_FREE_PAYLOAD:
		LM_FREE(payload);
	}
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	LM_ProtMemoryEx(proc, src, size, old_prot, (lm_prot_t *)LM_NULLPTR);

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

LM_API lm_bool_t
LM_Assemble(lm_cstring_t code, lm_arch_t arch, lm_size_t bits, lm_inst_t *inst)
{
	lm_bool_t ret = LM_FALSE;
	ks_engine *ks;
	ks_arch ksarch;
	ks_mode ksmode;
	unsigned char *encode;
	size_t size;
	size_t count;

	if (!code || !inst)
		return ret;

	switch (arch) {
	case LM_ARCH_X86: ksarch = KS_ARCH_X86; break;
	case LM_ARCH_ARM: ksarch = KS_ARCH_ARM; break;
	default: return ret;
	}

	switch (bits) {
	case 32: ksmode = KS_MODE_32; break;
	case 64: ksmode = KS_MODE_64; break;
	default: return ret;
	}

	if (ks_open(ksarch, ksmode, &ks) != KS_ERR_OK)
		return ret;

	ks_asm(ks, code, 0, &encode, &size, &count);
	if (size <= 0 || size > LM_INST_SIZE)
		goto CLEAN_EXIT;

	inst->size = size;
	memcpy((void *)inst->bytes, (void *)encode, size);

	ks_free(encode);
	ret = LM_TRUE;
CLEAN_EXIT:
	ks_close(ks);
	return ret;
}

LM_API lm_bool_t
LM_Disassemble(lm_address_t code, lm_arch_t arch, lm_size_t bits, lm_inst_t *inst)
{
	lm_bool_t ret = LM_FALSE;
	csh cshandle;
	cs_insn *csinsn;
	cs_arch csarch;
	cs_mode csmode;
	size_t count;

	if (!code || !inst)
		return ret;

	switch (arch) {
	case LM_ARCH_X86: csarch = CS_ARCH_X86; break;
	case LM_ARCH_ARM: csarch = CS_ARCH_ARM; break;
	}

	switch (bits) {
	case 32: csmode = CS_MODE_32; break;
	case 64: csmode = CS_MODE_64; break;
	}

	if (cs_open(csarch, csmode, &cshandle) != CS_ERR_OK)
		return LM_FALSE;

	count = cs_disasm(cshandle, code, LM_INST_SIZE, 0, 1, &csinsn);
	if (count <= 0)
		goto CLEAN_EXIT;

	memcpy((void *)inst, (void *)&csinsn[0], sizeof(lm_inst_t));

	cs_free(csinsn, count);
	ret = LM_TRUE;
CLEAN_EXIT:
	cs_close(&cshandle);
	return ret;
}

LM_API lm_size_t
LM_CodeLength(lm_address_t code, lm_size_t minlength)
{
	lm_size_t length;
	lm_inst_t inst;
	for (length = 0; length < minlength; code = (lm_address_t)LM_OFFSET(code, length)) {
		if (LM_Disassemble(code, LM_ARCH, LM_BITS, &inst) == LM_FALSE)
			return 0;
		length += inst.size;
	}

	return length;
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

		LM_SNPRINTF(status_path, LM_ARRLEN(status_path),
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
		ret = LM_WriteMemoryEx(proc, dst, src, size);
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
