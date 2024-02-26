#include "internal.h"

LM_PRIVATE lm_size_t
_LM_GetNameFromPath(lm_char_t *path,
		    lm_char_t *namebuf,
		    lm_size_t  maxlen)
{
	lm_char_t *name;
	lm_size_t   len = 0;

	name = LM_STRRCHR(path, LM_PATH_SEP);
	if (!name) {
		namebuf[0] = LM_STR('\x00');
		return len;
	}

	name = &name[1]; /* skip path separator */

	len = LM_STRLEN(name);
	if (len >= maxlen)
		len = maxlen - 1;

	LM_STRNCPY(namebuf, name, len);
	namebuf[len] = LM_STR('\x00');
	
	return len;
}
