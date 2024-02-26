#ifndef UTILS_H
#define UTILS_H
#include <libmem/libmem.h>

/* Internal functions used throughout the codebase */
LM_PRIVATE lm_time_t
_LM_GetProcessStartTime(lm_pid_t pid);

LM_PRIVATE lm_pid_t
_LM_GetProcessId(lm_void_t);

LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t);

LM_PRIVATE lm_pid_t
_LM_GetParentIdEx(lm_pid_t pid);

LM_PRIVATE lm_size_t
_LM_GetProcessPath(lm_char_t *pathbuf,
		   lm_size_t  maxlen);

LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t   pid,
		     lm_char_t *pathbuf,
		     lm_size_t  maxlen);

/* TODO: Unify this API! */
#if LM_OS == LM_OS_WIN
	LM_PRIVATE lm_size_t
	_LM_GetProcessBitsEx(lm_pid_t pid);
#else
	LM_PRIVATE lm_size_t
	_LM_GetProcessBitsEx(lm_char_t *elfpath);
#endif

LM_PRIVATE lm_size_t
_LM_GetNameFromPath(lm_char_t *path,
		    lm_char_t *namebuf,
		    lm_size_t  maxlen);

LM_PRIVATE lm_prot_t
_LM_GetRealProt(lm_prot_t prot); /* turn libmem flags into OS-specific flags */

LM_PRIVATE lm_prot_t
_LM_GetProt(lm_prot_t prot); /* turn OS-specific flags into libmem flags */
#endif
