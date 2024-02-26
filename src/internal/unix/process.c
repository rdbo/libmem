#include "internal.h"

LM_PRIVATE lm_void_t
_LM_GetSystemBits(lm_size_t *bits)
{
	struct utsname utsbuf;

	if (uname(&utsbuf))
		return;
		
	if (!LM_STRCMP(utsbuf.machine, LM_STR("x86_64")) ||
	    !LM_STRCMP(utsbuf.machine, LM_STR("amd64")) ||
	    !LM_STRCMP(utsbuf.machine, LM_STR("aarch64")))
		*bits = 64;
}
