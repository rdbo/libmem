LM_PRIVATE lm_size_t
_LM_GetElfBits(lm_tchar_t *path)
{
	lm_size_t bits = 0;
	int fd;
	unsigned char elf_num;

	LM_ASSERT(path != LM_NULLPTR);

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return bits;

	/*
	 * ELF Magic:
	 * 32 bits -> 0x7F, E, L, F, 1
	 * 64 bits -> 0x7F, E, L, F, 2
	 */

	lseek(fd, EI_MAG3 + 1, SEEK_SET);
	if (read(fd, &elf_num, sizeof(elf_num)) > 0 &&
	    (elf_num == 1 || elf_num == 2))
		bits = elf_num * 32;

	close(fd);

	return bits;
}

LM_PRIVATE lm_bool_t
_LM_EnumElf32Syms(int fd,
		  lm_module_t mod,
		  lm_bool_t (*callback)(lm_cstring_t symbol,
					lm_address_t addr,
					lm_void_t   *arg),
		  lm_void_t  *arg)
{
	lm_bool_t  ret = LM_FALSE;
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
			
			/* TODO: Use realloc */
			symstr = (lm_char_t *)(
				LM_CALLOC(j + 1,
					  sizeof(lm_char_t))
			);

			if (old_symstr) {
				if (symstr) {
					LM_CSTRNCPY(symstr,
						    old_symstr,
						    j);
				}

				LM_FREE(old_symstr);
			}

			if (!symstr)
				return ret;
			
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
		lm_char_t   *symstr = (lm_char_t *)LM_NULL;
		lm_address_t addr;
		lm_bool_t    cbret;

		read(fd, &sym, dynsym_entsize);

		do {
			/* TODO: Use realloc */
			lm_char_t *old_symstr = symstr;
			
			symstr = (lm_char_t *)(
				LM_CALLOC(j + 1,
					   sizeof(lm_char_t))
			);

			if (old_symstr) {
				if (symstr) {
					LM_CSTRNCPY(symstr,
						    old_symstr,
						    j);
				}

				LM_FREE(old_symstr);
			}

			if (!symstr)
				return ret;
			
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

_GOOD_RET:
	ret = LM_TRUE;
	return ret;
}

LM_PRIVATE lm_bool_t
_LM_EnumElf64Syms(int fd,
		  lm_module_t mod,
		  lm_bool_t (*callback)(lm_cstring_t symbol,
					lm_address_t addr,
					lm_void_t   *arg),
		  lm_void_t  *arg)
{
	lm_bool_t  ret = LM_FALSE;
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
		lm_char_t   *symstr = (lm_char_t *)LM_NULL;
		lm_address_t addr;
		lm_bool_t    cbret;

		read(fd, &sym, symtab_entsize);

		do {
			/* TODO: Use realloc */
			lm_char_t *old_symstr = symstr;
			
			symstr = (lm_char_t *)(
				LM_CALLOC(j + 1,
					  sizeof(lm_char_t))
			);

			if (old_symstr) {
				if (symstr) {
					LM_CSTRNCPY(symstr,
						    old_symstr,
						    j);
				}

				LM_FREE(old_symstr);
			}

			if (!symstr)
				return ret;
			
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
		lm_char_t   *symstr = (lm_char_t *)LM_NULL;
		lm_address_t addr;
		lm_bool_t    cbret;

		read(fd, &sym, dynsym_entsize);

		do {
			/* TODO: Use realloc */
			lm_char_t *old_symstr = symstr;
			
			symstr = (lm_char_t *)(
				LM_CALLOC(j + 1,
					  sizeof(lm_char_t))
			);

			if (old_symstr) {
				if (symstr) {
					LM_CSTRNCPY(symstr,
						    old_symstr,
						    j);
				}

				LM_FREE(old_symstr);
			}

			if (!symstr)
				return ret;
			
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

_GOOD_RET:
	ret = LM_TRUE;
	return ret;
}

LM_PRIVATE lm_bool_t
_LM_EnumElfSyms(lm_module_t mod,
		lm_tchar_t *modpath,
		lm_bool_t (*callback)(lm_cstring_t symbol,
				      lm_address_t addr,
				      lm_void_t   *arg),
		lm_void_t  *arg)
{
	lm_bool_t   ret = LM_FALSE;
	int         fd;
	lm_size_t   bits;

	fd = open(modpath, O_RDONLY);
	if (fd == -1)
		return ret;

	bits = _LM_GetElfBits(modpath);
	if (bits == 64) {
		ret = _LM_EnumElf64Syms(fd, mod, callback, arg);
	} else {
		ret = _LM_EnumElf32Syms(fd, mod, callback, arg);
	}

	close(fd);
	return ret;
}
