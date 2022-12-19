LM_PRIVATE lm_bool_t
_LM_EnumPeSyms(lm_size_t    bits,
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
