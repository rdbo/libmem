#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem.h>

#if LM_LANG == LM_LANG_CPP
#define LM_PRIVATE extern "C"
#else
#define LM_PRIVATE
#endif

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumPeSyms(lm_size_t    bits,
	       lm_address_t modbase,
	       lm_bool_t  (*callback)(lm_cstring_t symbol,
				      lm_address_t addr,
				      lm_void_t   *arg),
	       lm_void_t *arg);
#else
LM_PRIVATE lm_bool_t
_LM_EnumElfSyms(lm_module_t mod,
		lm_tchar_t *modpath,
		lm_bool_t (*callback)(lm_cstring_t symbol,
				      lm_address_t addr,
				      lm_void_t   *arg),
		lm_void_t  *arg);
#endif

#endif
