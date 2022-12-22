#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem.h>

#define LM_PRIVATE

LM_PRIVATE lm_bool_t
_LM_ValidProcess(lm_process_t proc);

#if LM_OS == LM_OS_WIN
#else
LM_PRIVATE lm_size_t
_LM_OpenFileBuf(lm_tstring_t path, 
		lm_tchar_t **pfilebuf);

LM_PRIVATE lm_void_t
_LM_CloseFileBuf(lm_tchar_t **pfilebuf);
#endif

#endif
