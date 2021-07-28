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

/* Helpers */
static lm_bool_t
_LM_CheckProcess(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

	if (proc.pid == (lm_pid_t)LM_BAD)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (proc.pid != LM_GetProcessId() && !proc.handle)
			return ret;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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
		lm_tchar_t  curchar = LM_STR(LM_MASK_UNKNOWN);

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
			curchar = LM_STR(LM_MASK_KNOWN);
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

#if LM_OS == LM_OS_WIN
#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

static lm_address_t
_LM_GetElfSymOffset(lm_tstring_t path,
		    lm_cstring_t symstr,
		    lm_uint_t   *type)
{
	lm_address_t offset = (lm_address_t)LM_BAD;
	int          fd;
	lm_size_t    bits = 0;
	lm_size_t    symlen;
	lm_char_t   *symstrbuf;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return offset;

	symlen = LM_STRLEN(symstr);
	symstrbuf = LM_CALLOC(symlen + 1, sizeof(lm_char_t));
	if (!symstrbuf)
		goto _CLOSE_RET;
	symstrbuf[symlen] = LM_STR('\x00');

	{
		unsigned char elf_num;
		lseek(fd, EI_MAG3 + 1, SEEK_SET);
		if (read(fd, &elf_num, sizeof(elf_num)) > 0 &&
		    (elf_num == 1 || elf_num == 2))
			bits = elf_num * 32;
	}

	switch (bits) {
	case 64:
		{
			Elf64_Ehdr ehdr;
			Elf64_Off  shstrtab_off;
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

			if (type)
				*type = (lm_uint_t)ehdr.e_type;
			
			shstrtab_off = ehdr.e_shoff + 
				       (ehdr.e_shstrndx * ehdr.e_shentsize);
			
			lseek(fd, shstrtab_off, SEEK_SET);
			read(fd, &shstrtab, ehdr.e_shentsize);
			shstrtab_off = shstrtab.sh_offset;
			lseek(fd, ehdr.e_shoff, SEEK_SET);
			for (i = 0; i < ehdr.e_shnum; ++i) {
				Elf64_Shdr shdr;
				lm_char_t  shstr[64] = { 0 };

				read(fd, &shdr, ehdr.e_shentsize);
				pread(fd, shstr, sizeof(shstr), shstrtab_off + shdr.sh_name);

				if (!LM_STRCMP(shstr, LM_STR(".strtab"))) {
					strtab_off = shdr.sh_offset;
				} else if (!LM_STRCMP(shstr, LM_STR(".dynstr"))) {
					dynstr_off = shdr.sh_offset;
				} else if (!LM_STRCMP(shstr, LM_STR(".symtab"))) {
					symtab_off = shdr.sh_offset;
					symtab_entsize = shdr.sh_entsize;
					symtab_num = shdr.sh_size;
				} else if (!LM_STRCMP(shstr, LM_STR(".dynsym"))) {
					dynsym_off = shdr.sh_offset;
					dynsym_entsize = shdr.sh_entsize;
					dynsym_num = shdr.sh_size;
				}
			}

			lseek(fd, symtab_off, SEEK_SET);
			for (i = 0; i < symtab_num; ++i) {
				Elf64_Sym sym;

				read(fd, &sym, symtab_entsize);
				pread(fd,
				      symstrbuf,
				      symlen * sizeof(lm_tchar_t),
				      strtab_off + sym.st_name);
				
				if (!LM_STRCMP(symstr, symstrbuf)) {
					offset = (lm_address_t)(
						(lm_uintptr_t)sym.st_value
					);
					goto _CLEAN_RET;
				}
			}

			lseek(fd, dynsym_off, SEEK_SET);
			for (i = 0; i < dynsym_num; ++i) {
				Elf64_Sym sym;

				read(fd, &sym, dynsym_entsize);
				pread(fd,
				      symstrbuf,
				      symlen * sizeof(lm_tchar_t),
				      dynstr_off + sym.st_name);
				
				if (!LM_STRCMP(symstr, symstrbuf)) {
					offset = (lm_address_t)(
						(lm_uintptr_t)sym.st_value
					);
					goto _CLEAN_RET;
				}
			}
			

			break;
		}
	
	case 32:
		{
			Elf32_Ehdr ehdr;
			Elf32_Off  shstrtab_off;
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

			if (type)
				*type = (lm_uint_t)ehdr.e_type;
			
			shstrtab_off = ehdr.e_shoff + 
				       (ehdr.e_shstrndx * ehdr.e_shentsize);
			
			lseek(fd, shstrtab_off, SEEK_SET);
			read(fd, &shstrtab, ehdr.e_shentsize);
			shstrtab_off = shstrtab.sh_offset;
			lseek(fd, ehdr.e_shoff, SEEK_SET);
			for (i = 0; i < ehdr.e_shnum; ++i) {
				Elf32_Shdr shdr;
				lm_char_t  shstr[64] = { 0 };

				read(fd, &shdr, ehdr.e_shentsize);
				pread(fd, shstr, sizeof(shstr), shstrtab_off + shdr.sh_name);

				if (!LM_STRCMP(shstr, LM_STR(".strtab"))) {
					strtab_off = shdr.sh_offset;
				} else if (!LM_STRCMP(shstr, LM_STR(".dynstr"))) {
					dynstr_off = shdr.sh_offset;
				} else if (!LM_STRCMP(shstr, LM_STR(".symtab"))) {
					symtab_off = shdr.sh_offset;
					symtab_entsize = shdr.sh_entsize;
					symtab_num = shdr.sh_size;
				} else if (!LM_STRCMP(shstr, LM_STR(".dynsym"))) {
					dynsym_off = shdr.sh_offset;
					dynsym_entsize = shdr.sh_entsize;
					dynsym_num = shdr.sh_size;
				}
			}

			lseek(fd, symtab_off, SEEK_SET);
			for (i = 0; i < symtab_num; ++i) {
				Elf32_Sym sym;

				read(fd, &sym, symtab_entsize);
				pread(fd,
				      symstrbuf,
				      symlen * sizeof(lm_tchar_t),
				      strtab_off + sym.st_name);
				
				if (!LM_STRCMP(symstr, symstrbuf)) {
					offset = (lm_address_t)(
						(lm_uintptr_t)sym.st_value
					);
					goto _CLEAN_RET;
				}
			}

			lseek(fd, dynsym_off, SEEK_SET);
			for (i = 0; i < dynsym_num; ++i) {
				Elf32_Sym sym;

				read(fd, &sym, dynsym_entsize);
				pread(fd,
				      symstrbuf,
				      symlen * sizeof(lm_tchar_t),
				      dynstr_off + sym.st_name);
				
				if (!LM_STRCMP(symstr, symstrbuf)) {
					offset = (lm_address_t)(
						(lm_uintptr_t)sym.st_value
					);
					goto _CLEAN_RET;
				}
			}
			

			break;
		}
	}

_CLEAN_RET:
	LM_FREE(symstrbuf);
_CLOSE_RET:
	close(fd);

	return offset;
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

#	if LM_OS == LM_OS_LINUX
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

#	if LM_OS == LM_OS_LINUX
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
#	elif LM_OS == LM_OS_LINUX
	{
		struct dirent *pdirent;
		DIR *dir;

		dir = opendir(LM_STR(LM_PROCFS));

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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *status_buf;
		lm_tchar_t  status_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
		lm_tchar_t *ptr;

		LM_SNPRINTF(status_path, LM_ARRLEN(status_path) - 1,
			    LM_STR("%s/%d/status"), LM_STR(LM_PROCFS), pid);
		
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		
	}
#	endif

	procbuf->pid = pid;
	ret = LM_TRUE;

	return ret;
}

LM_API lm_void_t
LM_CloseProcess(lm_process_t *proc)
{
	if (!proc)
		return;
	
#	if LM_OS == LM_OS_WIN
	{
		if (proc->handle && proc->pid != LM_GetProcessId()) {
			CloseHandle(proc->handle);
			proc->handle = (HANDLE)NULL;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{

	}
#	endif

	proc->pid = (lm_pid_t)LM_BAD;
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

	if (!_LM_CheckProcess(proc) || !pathbuf || !maxlen)
		return len;
	
#	if LM_OS == LM_OS_WIN
	{
		len = (lm_size_t)GetModuleFileNameEx(proc.handle, NULL,
						     pathbuf, maxlen - 1);
	}
#	elif LM_OS == LM_OS_LINUX
	{
		lm_tchar_t exe_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
		LM_SNPRINTF(exe_path, LM_ARRLEN(exe_path) - 1,
			    LM_STR("%s/%d/exe"), LM_STR(LM_PROCFS), proc.pid);
		
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
		lm_size_t   pathlen;

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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

	if (!_LM_CheckProcess(proc) || !namebuf || !maxlen)
		return len;

#	if LM_OS == LM_OS_WIN
	{
		len = (lm_size_t)GetModuleBaseName(proc.handle, NULL, namebuf, maxlen - 1);
		if (len)
			namebuf[len] = LM_STR('\x00');
	}
#	elif LM_OS == LM_OS_LINUX
	{
		lm_tchar_t *filebuf;
		lm_tchar_t comm_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

		LM_SNPRINTF(comm_path, LM_ARRLEN(comm_path) - 1,
			    LM_STR("%s/%d/comm"), LM_STR(LM_PROCFS), proc.pid);
		
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

	if (!_LM_CheckProcess(proc))
		return bits;

#	if LM_OS == LM_OS_WIN
	{
		BOOL IsWow64;
		BOOL Check;
		lm_size_t sysbits;

		if (!IsWow64Process(proc.handle, &IsWow64))
			return bits;

		sysbits = LM_GetSystemBits();

		if (sysbits == 32 || IsWow64)
			bits = 32;
		else if (sysbits == 64)
			bits = 64;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

	if (!_LM_CheckProcess(proc) || !callback)
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *maps_buf;
		lm_tchar_t *ptr;
		lm_tchar_t maps_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

#		if LM_OS == LM_OS_LINUX
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
			for (tmp = maps_buf;
			     (tmp = LM_STRSTR(tmp, path));
			     tmp = &tmp[1])
				holder = tmp;
			
			ptr = holder;

			holder = maps_buf;
			for (tmp = maps_buf;
			     (lm_uintptr_t)(
				     tmp = LM_STRCHR(tmp, LM_STR('\n'))
			     ) < (lm_uintptr_t)ptr;
			     tmp = &tmp[1])
				holder = &tmp[1];

#			if LM_OS == LM_OS_LINUX
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
LM_GetModule(lm_void_t   *modarg,
	     lm_module_t *modbuf,
	     lm_int_t     flags)
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
	       lm_void_t   *modarg,
	       lm_module_t *modbuf,
	       lm_int_t     flags)
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
#		elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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
#		elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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
	      lm_module_t *mod)
{
	lm_bool_t ret = LM_FALSE;

	if (!path)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (LoadLibrary(path)) {
			if (!mod || LM_GetModule(path, mod))
				ret = LM_TRUE;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		if (dlopen(path, RTLD_LAZY)) {
			if (!mod || LM_GetModule(path, mod, LM_MOD_BY_STR))
				ret = LM_TRUE;
		}
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_LoadModuleEx(lm_process_t proc,
		lm_tstring_t path,
		lm_module_t *mod);

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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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
		  lm_module_t  mod);

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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *libpath;

		libpath = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
		if (!libpath)
			return symaddr;
		
		if (LM_GetModulePath(mod, libpath, LM_PATH_MAX)) {
			void *libhandle;

			libhandle = dlopen(libpath, RTLD_NOLOAD);

			if (libhandle) {
				symaddr = (lm_address_t)dlsym(libhandle, symstr);

				if (!symaddr)
					symaddr = (lm_address_t)LM_BAD;

				dlclose(libhandle);
			}
		}

		LM_FREE(libpath);
	}
#	endif

	return symaddr;
}

LM_API lm_address_t
LM_GetSymbolEx(lm_process_t proc,
	       lm_module_t  mod,
	       lm_cstring_t symstr)
{
	lm_address_t symaddr = (lm_address_t)LM_BAD;

	if (!_LM_CheckProcess(proc) || !symstr)
		return symaddr;

#	if LM_OS == LM_OS_WIN
	{

	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t  *path;

		path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
		if (!path)
			return symaddr;
		
		if (LM_GetModulePathEx(proc, mod, path, LM_PATH_MAX)) {
			lm_address_t offset;
			lm_uint_t    type;

			offset = _LM_GetElfSymOffset(path, symstr, &type);
			if (offset != (lm_address_t)LM_BAD) {
				if (type != ET_EXEC) {
					symaddr = (lm_address_t)(
						&((lm_byte_t *)mod.base)[
							(lm_uintptr_t)offset
						]
					);
				} else {
					symaddr = offset;
				}
			}
		}

		LM_FREE(path);
	}
#	endif

	return symaddr;
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

	if (!_LM_CheckProcess(proc) || !callback)
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *maps_buf;
		lm_tchar_t *ptr;
		lm_tchar_t maps_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

#		if LM_OS == LM_OS_LINUX
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

#			if LM_OS == LM_OS_LINUX
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

#			if LM_OS == LM_OS_LINUX
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

	if (!_LM_CheckProcess(proc) || !addr || !page)
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

	if (!_LM_CheckProcess(proc) || !src || !dst || !size)
		return rdsize;
	
#	if LM_OS == LM_OS_WIN
	{
		rdsize = (lm_size_t)ReadProcessMemory(proc.handle, src, dst,
						      size, NULL);
	}
#	elif LM_OS == LM_OS_LINUX
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
			    LM_STR("%s/%d/mem"), LM_STR(LM_PROCFS), proc.pid);
		
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

	if (!_LM_CheckProcess(proc) || !dst || !src || !size)
		return wrsize;

#	if LM_OS == LM_OS_WIN
	{
		wrsize = (lm_size_t)WriteProcessMemory(proc.handle, dst, src,
						       size, NULL);
	}
#	elif LM_OS == LM_OS_LINUX
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
			    LM_STR("%s/%d/mem"), LM_STR(LM_PROCFS), proc.pid);
		
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

	if (!_LM_CheckProcess(proc))
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		long pagesize;
		lm_page_t page;
		lm_int_t  nsyscall;

		if (oldprot) {
			if (!LM_GetPageEx(proc, addr, &page))
				return ret;
		}

#		if LM_OS == LM_OS_LINUX
		if (LM_GetProcessBitsEx(proc) == 64)
			nsyscall = 10;
		else
			nsyscall = 125;
#		elif LM_OS == LM_OS_BSD
		nsyscall = SYS_mprotect;
#		endif

		pagesize = sysconf(_SC_PAGE_SIZE);
		addr = (lm_address_t)(
			(lm_uintptr_t)addr & (lm_uintptr_t)(-pagesize)
		);
		if (!LM_SystemCallEx(proc, nsyscall,
				     (lm_uintptr_t)addr,
				     (lm_uintptr_t)size,
				     (lm_uintptr_t)prot,
				     LM_NULL, LM_NULL, LM_NULL))
			ret = LM_TRUE;
		
		if (oldprot)
			*oldprot = page.prot;
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

	if (!_LM_CheckProcess(proc))
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_int_t  nsyscall;
		lm_size_t bits;

		bits = LM_GetProcessBitsEx(proc);

#		if LM_OS == LM_OS_LINUX
		if (bits == 64)
			nsyscall = 9;
		else
			nsyscall = 192;
#		elif LM_OS == LM_OS_BSD
		nsyscall = SYS_mmap;
#		endif

		alloc = (lm_address_t)(
			LM_SystemCallEx(proc, nsyscall,
					LM_NULL,
					size,
					(lm_uintptr_t)prot,
					MAP_PRIVATE | MAP_ANON,
					(lm_uintptr_t)-1,
					0)
		);
		
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
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

	if (!_LM_CheckProcess(proc))
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (VirtualFreeEx(proc.handle, alloc, 0, MEM_RELEASE))
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_int_t nsyscall;

#		if LM_OS == LM_OS_LINUX
		if (LM_GetProcessBitsEx(proc) == 64)
			nsyscall = 11;
		else
			nsyscall = 91;
#		elif LM_OS == LM_OS_BSD
		nsyscall = SYS_munmap;
#		endif

		if (!LM_SystemCallEx(proc, nsyscall,
				     (lm_uintptr_t)alloc, size,
				     LM_NULL, LM_NULL,
				     LM_NULL, LM_NULL))
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

	if (!data || !size || !start || !stop || 
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;
	
	if (!LM_ProtMemory(start, size, LM_PROT_XRW, &oldprot))
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

	LM_ProtMemory(start, size, oldprot, (lm_prot_t *)LM_NULL);

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

	if (!_LM_CheckProcess(proc) || !data || !size || !start || !stop ||
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;
	
	if (!LM_ProtMemoryEx(proc, start, size, LM_PROT_XRW, &oldprot))
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

	LM_ProtMemory(start, size, oldprot, (lm_prot_t *)LM_NULL);

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
	lm_prot_t    oldprot;
	lm_byte_t   *ptr;

	if (!pattern || !mask || !start || !stop ||
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;
	
	size = LM_STRLEN(mask);
	if (!size)
		return match;
	
	if (!LM_ProtMemory(start, size, LM_PROT_XRW, &oldprot))
		return match;
	
	for (ptr = (lm_byte_t *)start;
	     ptr != (lm_byte_t *)stop;
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		for (i = 0; check && i < size; ++i) {
			if (!LM_CHKMASK(mask[i]) && ptr[i] != pattern[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}
	
	LM_ProtMemory(start, size, oldprot, (lm_prot_t *)LM_NULL);

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
	lm_prot_t    oldprot;
	lm_byte_t   *ptr;

	if (!_LM_CheckProcess(proc) || !pattern || !mask || !start || !stop ||
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;
	
	size = LM_STRLEN(mask);
	if (!size)
		return match;
	
	if (!LM_ProtMemoryEx(proc, start, size, LM_PROT_XRW, &oldprot))
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
	
	LM_ProtMemoryEx(proc, start, size, oldprot, (lm_prot_t *)LM_NULL);

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

	if (!_LM_CheckProcess(proc) || !sig || !start || !stop ||
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
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		syscall_ret = (lm_uintptr_t)syscall(nsyscall,
						    arg0, arg1, arg2,
						    arg3, arg4, arg5);
	}
#	endif

	return syscall_ret;
}

LM_API lm_uintptr_t
LM_SystemCallEx(lm_process_t proc,
		lm_int_t     nsyscall,
		lm_uintptr_t arg0,
		lm_uintptr_t arg1,
		lm_uintptr_t arg2,
		lm_uintptr_t arg3,
		lm_uintptr_t arg4,
		lm_uintptr_t arg5)
{
	lm_uintptr_t syscall_ret = (lm_uintptr_t)LM_BAD;

	if (!_LM_CheckProcess(proc))
		return syscall_ret;

#	if LM_OS == LM_OS_WIN
	{

	}
#	elif LM_OS == LM_OS_LINUX
	{
		int status;
		lm_size_t bits;

		bits = LM_GetProcessBitsEx(proc);

		if (bits > LM_GetProcessBits())
			return syscall_ret;

#		if LM_ARCH == LM_ARCH_X86
		{
			struct user_regs_struct regs, old_regs;
			lm_byte_t code[2] = { 0 };
			lm_byte_t old_code[LM_ARRLEN(code)];
			lm_address_t inj_addr;

#			if LM_BITS == 64
			if (bits == 64) {
				code[0] = 0x0F;
				code[1] = 0x05;
				/* code:
				 * syscall
				 */
			} else {
				code[0] = 0xCD;
				code[1] = 0x80;
				/*
				 * code:
				 * int $80
				 */
			}
#			else
			code[0] = 0xCD;
			code[1] = 0x80;
			/*
			 * code:
			 * int $80
			 */
#			endif

			ptrace(PTRACE_ATTACH, proc.pid, NULL, NULL);
			wait(&status);
			ptrace(PTRACE_GETREGS, proc.pid, NULL, &old_regs);
			regs = old_regs;
#			if LM_BITS == 64
			if (bits == 64) {
				regs.rax = (lm_uintptr_t)nsyscall;
				regs.rdi = arg0;
				regs.rsi = arg1;
				regs.rdx = arg2;
				regs.r10 = arg3;
				regs.r8  = arg4;
				regs.r9  = arg5;
			} else {
				regs.rax = (lm_uintptr_t)nsyscall;
				regs.rbx = arg0;
				regs.rcx = arg1;
				regs.rdx = arg2;
				regs.rsi = arg3;
				regs.rdi = arg4;
				regs.rbp = arg5;
			}
			inj_addr = (lm_address_t)regs.rip;
#			else
			regs.eax = (lm_uintptr_t)nsyscall;
			regs.ebx = arg0;
			regs.ecx = arg1;
			regs.edx = arg2;
			regs.esi = arg3;
			regs.edi = arg4;
			regs.ebp = arg5;
			inj_addr = (lm_address_t)regs.eip;
#			endif

			_LM_PtraceRead(proc, inj_addr, old_code, sizeof(old_code));
			_LM_PtraceWrite(proc, inj_addr, code, sizeof(code));
			ptrace(PTRACE_SETREGS, proc.pid, NULL, &regs);
			ptrace(PTRACE_SINGLESTEP, proc.pid, NULL, NULL);
			waitpid(proc.pid, &status, WSTOPPED);
			ptrace(PTRACE_GETREGS, proc.pid, NULL, &regs);
#			if LM_BITS == 64
			syscall_ret = (lm_uintptr_t)regs.rax;
#			else
			syscall_ret = (lm_uintptr_t)regs.eax;
#			endif
			_LM_PtraceWrite(proc, inj_addr, old_code, sizeof(old_code));
			ptrace(PTRACE_SETREGS, proc.pid, NULL, &old_regs);
			ptrace(PTRACE_DETACH, proc.pid, NULL, NULL);
		}
#		elif LM_ARCH == LM_ARCH_ARM
		{
			struct user_regs regs, old_regs;
			lm_byte_t code[4] = { 0 };
			lm_byte_t old_code[LM_ARRLEN(code)];
			lm_address_t inj_addr;
			struct iovec pt_iovec;

			code[0] = 0xEF;
			code[1] = 0x00;
			code[2] = 0x00;
			code[3] = 0x00;
			/* code:
			 * swi #0
			 */

			ptrace(PTRACE_ATTACH, proc.pid, NULL, NULL);
			wait(&status);
			pt_iovec.iov_base = (void *)&old_regs;
			pt_iovec.iov_len = sizeof(old_regs);
			ptrace(PTRACE_GETREGSET, proc.pid,
			       (void *)NT_PRSTATUS, &pt_iovec);
			regs = old_regs;
			regs.uregs[0] = arg0;
			regs.uregs[1] = arg1;
			regs.uregs[2] = arg2;
			regs.uregs[3] = arg3;
			regs.uregs[4] = arg4;
			regs.uregs[5] = arg5;
			if (bits == 64) {
				regs.uregs[8] = (lm_uintptr_t)nsyscall;
			} else {
				regs.uregs[6] = 0;
				regs.uregs[7] = (lm_uintptr_t)nsyscall;
			}

			inj_addr = (lm_address_t)regs.uregs[15];

			_LM_PtraceRead(proc, inj_addr, old_code, sizeof(old_code));
			_LM_PtraceWrite(proc, inj_addr, code, sizeof(code));
			pt_iovec.iov_base = (void *)&regs;
			pt_iovec.iov_len = sizeof(regs);
			ptrace(PTRACE_SETREGSET, proc.pid,
			       (void *)NT_PRSTATUS, &pt_iovec);
			ptrace(PTRACE_SINGLESTEP, proc.pid, NULL, NULL);
			waitpid(proc.pid, &status, WSTOPPED);
			pt_iovec.iov_base = (void *)&regs;
			pt_iovec.iov_len = sizeof(regs);
			ptrace(PTRACE_GETREGSET, proc.pid,
			       (void *)NT_PRSTATUS, &pt_iovec);
			syscall_ret = (lm_uintptr_t)regs.uregs[0];
			_LM_PtraceWrite(proc, inj_addr, old_code, sizeof(old_code));
			pt_iovec.iov_base = (void *)&old_regs;
			pt_iovec.iov_len = sizeof(old_regs);
			ptrace(PTRACE_SETREGSET, proc.pid,
			       (void *)NT_PRSTATUS, &pt_iovec);
			ptrace(PTRACE_DETACH, proc.pid, NULL, NULL);
		}
#		endif
	}
#	elif LM_OS == LM_OS_BSD
	{
		int status;
		lm_size_t bits;

		bits = LM_GetProcessBitsEx(proc);

		if (bits > LM_GetProcessBits())
			return syscall_ret;

#		if LM_ARCH == LM_ARCH_X86
		{
			struct reg regs, old_regs;
			lm_byte_t code[9] = { 0 };
			lm_byte_t old_code[LM_ARRLEN(code)];
			lm_address_t inj_addr;

#			if LM_BITS == 64
			if (bits == 64) {
				code[0] = 0x0F;
				code[1] = 0x05;
				code[2] = 0xCC;
				/* code:
				 * syscall
				 * int3
				 */
			} else {
				code[0] = 0x55;
				code[1] = 0x57;
				code[2] = 0x56;
				code[3] = 0x52;
				code[4] = 0x51;
				code[5] = 0x53;
				code[6] = 0xCD;
				code[7] = 0x80;
				code[8] = 0xCC;
				/*
				 * code:
				 * push ebp
				 * push edi
				 * push esi
				 * push edx
				 * push ecx
				 * push ebx
				 * int $80
				 * int3
				*/
			}
#			else
			code[0] = 0x55;
			code[1] = 0x57;
			code[2] = 0x56;
			code[3] = 0x52;
			code[4] = 0x51;
			code[5] = 0x53;
			code[6] = 0xCD;
			code[7] = 0x80;
			code[8] = 0xCC;
			/*
			 * code:
			 * push ebp
			 * push edi
			 * push esi
			 * push edx
			 * push ecx
			 * push ebx
			 * int $80
			 * int3
			 */
#			endif

			ptrace(PT_ATTACH, proc.pid, NULL, 0);
			wait(&status);
			ptrace(PT_GETREGS, proc.pid, (caddr_t)&old_regs, 0);
			regs = old_regs;
#			if LM_BITS == 64
			if (bits == 64) {
				regs.r_rax = (lm_uintptr_t)nsyscall;
				regs.r_rdi = arg0;
				regs.r_rsi = arg1;
				regs.r_rdx = arg2;
				regs.r_r10 = arg3;
				regs.r_r8  = arg4;
				regs.r_r9  = arg5;
			} else {
				regs.r_rax = (lm_uintptr_t)nsyscall;
				regs.r_rbx = arg0;
				regs.r_rcx = arg1;
				regs.r_rdx = arg2;
				regs.r_rsi = arg3;
				regs.r_rdi = arg4;
				regs.r_rbp = arg5;
			}
			inj_addr = (lm_address_t)regs.r_rip;
#			else
			regs.r_eax = (lm_uintptr_t)nsyscall;
			regs.r_ebx = arg0;
			regs.r_ecx = arg1;
			regs.r_edx = arg2;
			regs.r_esi = arg3;
			regs.r_edi = arg4;
			regs.r_ebp = arg5;
			inj_addr = (lm_address_t)regs.r_eip;
#			endif

			_LM_PtraceRead(proc, inj_addr, old_code, sizeof(old_code));
			_LM_PtraceWrite(proc, inj_addr, code, sizeof(code));
			ptrace(PT_SETREGS, proc.pid, (caddr_t)&regs, 0);
			if (bits == 64)
				ptrace(PT_STEP, proc.pid, (caddr_t)NULL, 0);
			else
				ptrace(PT_CONTINUE, proc.pid, (caddr_t)1, 0);
			waitpid(proc.pid, &status, WSTOPPED);
			ptrace(PT_GETREGS, proc.pid, (caddr_t)&regs, 0);
#			if LM_BITS == 64
			syscall_ret = (lm_uintptr_t)regs.r_rax;
#			else
			syscall_ret = (lm_uintptr_t)regs.r_eax;
#			endif
			_LM_PtraceWrite(proc, inj_addr, old_code, sizeof(old_code));
			ptrace(PT_SETREGS, proc.pid, (caddr_t)&old_regs, 0);
			ptrace(PT_DETACH, proc.pid, NULL, 0);
		}
#		elif LM_ARCH == LM_ARCH_ARM
		{
			struct reg regs, old_regs;
			lm_byte_t code[4];
			lm_byte_t old_code[LM_ARRLEN(code)];
			lm_address_t inj_addr;
			struct iovec pt_iovec;

			code[0] = 0xEF;
			code[1] = 0x00;
			code[2] = 0x00;
			code[3] = 0x00;

			ptrace(PTRACE_ATTACH, proc.pid, NULL, NULL);
			wait(&status);
			pt_iovec.iov_base = (void *)&old_regs;
			pt_iovec.iov_len = sizeof(old_regs);
			ptrace(PTRACE_GETREGSET, proc.pid,
			       (void *)NT_PRSTATUS, &pt_iovec);
			regs = old_regs;
			regs.uregs[0] = arg0;
			regs.uregs[1] = arg1;
			regs.uregs[2] = arg2;
			regs.uregs[3] = arg3;
			regs.uregs[4] = arg4;
			regs.uregs[5] = arg5;
			if (bits == 64) {
				regs.uregs[8] = (lm_uintptr_t)nsyscall;
			} else {
				regs.uregs[6] = 0;
				regs.uregs[7] = (lm_uintptr_t)nsyscall;
			}

			inj_addr = (lm_address_t)regs.uregs[15];

			_LM_PtraceRead(proc, inj_addr, old_code, sizeof(old_code));
			_LM_PtraceWrite(proc, inj_addr, code, sizeof(code));
			pt_iovec.iov_base = (void *)&regs;
			pt_iovec.iov_len = sizeof(regs);
			ptrace(PTRACE_SETREGSET, proc.pid,
			       (void *)NT_PRSTATUS, &pt_iovec);
			ptrace(PTRACE_SINGLESTEP, proc.pid, NULL, NULL);
			waitpid(proc.pid, &status, WSTOPPED);
			pt_iovec.iov_base = (void *)&regs;
			pt_iovec.iov_len = sizeof(regs);
			ptrace(PTRACE_GETREGSET, proc.pid,
			       (void *)NT_PRSTATUS, &pt_iovec);
			syscall_ret = (lm_uintptr_t)regs.uregs[0];
			_LM_PtraceWrite(proc, inj_addr, old_code, sizeof(old_code));
			pt_iovec.iov_base = (void *)&old_regs;
			pt_iovec.iov_len = sizeof(old_regs);
			ptrace(PTRACE_SETREGSET, proc.pid,
			       (void *)NT_PRSTATUS, &pt_iovec);
			ptrace(PTRACE_DETACH, proc.pid, NULL, NULL);
		}
#		endif
	}
#	endif

	return syscall_ret;
}

LM_API lm_uintptr_t
LM_LibraryCall(lm_address_t fnaddr,
	       lm_size_t    nargs,
	       ...);

LM_API lm_uintptr_t
LM_LibraryCallEx(lm_process_t proc,
		 lm_address_t fnaddr,
		 lm_size_t    nargs,
		 ...);

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

#endif
