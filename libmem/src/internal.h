#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem.h>

#if LM_LANG == LM_LANG_CPP
#define LM_PRIVATE extern "C"
#else
#define LM_PRIVATE
#endif

#if LM_OS == LM_OS_WIN
#else
LM_PRIVATE lm_size_t
_LM_GetElfBits(lm_tchar_t *path);
#endif

#endif
