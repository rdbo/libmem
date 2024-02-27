#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_LoadModule(lm_string_t path)
{
	return dlopen(path, RTLD_LAZY) ? LM_TRUE : LM_FALSE;
}
