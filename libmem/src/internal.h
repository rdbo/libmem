#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem.h>

#if LM_LANG == LM_LANG_CPP
#define LM_PRIVATE extern "C"
#else
#define LM_PRIVATE
#endif

LM_PRIVATE lm_bool_t
_LM_ValidProcess(lm_process_t proc);

#if LM_OS == LM_OS_WIN
#else
LM_PRIVATE lm_size_t
_LM_OpenFileBuf(lm_tstring_t path, 
		lm_tchar_t **pfilebuf);

LM_PRIVATE lm_void_t
_LM_CloseFileBuf(lm_tchar_t **pfilebuf);

LM_PRIVATE lm_size_t
_LM_GetElfBits(lm_tchar_t *path);
#endif

#endif
