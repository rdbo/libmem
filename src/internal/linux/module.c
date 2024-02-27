#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumModulesEx(const lm_process_t *pproc,
		  lm_bool_t (LM_CALL *callback)(lm_module_t *pmod,
						lm_void_t   *arg),
		  lm_void_t          *arg)
{
	DIR *d;
	struct dirent *dir;
	regex_t regex;
	regmatch_t matches[3];
	lm_module_t mod;

	lm_address_t start;
	lm_address_t end;
	char path[LM_PATH_MAX];
	char real_path[LM_PATH_MAX];
	ssize_t result;
	lm_char_t *name;
	lm_char_t *tmp;

	LM_CSNPRINTF(path, sizeof(path), "/proc/%d/map_files", pproc->pid);
	d = opendir(path);
	if (!d)
		return LM_FALSE;

	if (regcomp(&regex, "([a-z0-9]+)-([a-z0-9]+)", REG_ICASE | REG_EXTENDED))
		goto CLOSE_RET;

	mod.base = 0;
	mod.end = 0;
	
	while ((dir = readdir(d)) != NULL) {
		if (!regexec(&regex, dir->d_name, 3, matches, 0)) {
			start = (lm_address_t)LM_STRTOP(&dir->d_name[matches[1].rm_so], NULL, 16);
			end = (lm_address_t)LM_STRTOP(&dir->d_name[matches[2].rm_so], NULL, 16);

			LM_SNPRINTF(path, sizeof(path), LM_STR("/proc/%d/map_files/%s"), pproc->pid, dir->d_name);
			if ((result = readlink(path, real_path, sizeof(real_path))) == -1)
				continue;

			real_path[result] = '\0';
			result++;

			if (!mod.base) {
				mod.base = start;
				mod.end = end;
				LM_MEMCPY(mod.path, real_path, (lm_size_t)result); /* TODO: Avoid repetition of this code below */
			} else {
				if (start != mod.end || LM_STRCMP(mod.path, real_path)) {
					LM_MEMCPY(path, mod.path, sizeof(path)); /* temporary path for adding the /proc/<pid>/root prefix later */
					LM_SNPRINTF(mod.path, LM_ARRLEN(mod.path), "/proc/%d/root%s", pproc->pid, path);
					for (tmp = mod.path; (tmp = LM_STRCHR(tmp, LM_STR('/'))) != NULL; tmp = &tmp[1])
						name = tmp;
					name = &name[1];
					LM_STRCPY(mod.name, name);
					mod.size = mod.end - mod.base;

					callback(&mod, arg);
					mod.base = start;
					mod.end = end;
					LM_MEMCPY(mod.path, real_path, (lm_size_t)result);
				} else {
					mod.end = end;
				}
			}
		}
	}

	/* TODO: avoid the repeating code to setup 'mod' */
	if (mod.base) {
		LM_SNPRINTF(mod.path, LM_ARRLEN(mod.path), "/proc/%d/root%s", pproc->pid, real_path); /* Since this is the last module, we don't have to create a copy of 'mod.path', as 'real_path' still holds it */
		for (tmp = mod.path; (tmp = LM_STRCHR(tmp, LM_STR('/'))) != NULL; tmp = &tmp[1])
			name = tmp;
		name = &name[1];
		LM_STRCPY(mod.name, name);
		mod.size = mod.end - mod.base;

		callback(&mod, arg);
	}

	regfree(&regex);

CLOSE_RET:
	closedir(d);
	
	return LM_TRUE;
}
