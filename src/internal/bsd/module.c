#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumModulesEx(const lm_process_t *pproc,
		  lm_bool_t (LM_CALL *callback)(lm_module_t *pmod,
						lm_void_t   *arg),
		  lm_void_t          *arg)
{
	lm_bool_t    ret = LM_FALSE;
	lm_char_t    maps_path[LM_PATH_MAX];
	FILE        *maps_file;
	lm_char_t   *maps_line = NULL;
	lm_size_t    maps_line_len;
	ssize_t      line_len;
	regex_t      regex;
	regmatch_t   matches[5];
	lm_module_t  mod;
	lm_string_t  curpath;

	mod.size = 0;
	mod.path[0] = LM_STR('\x00');

	if (regcomp(&regex, "^0x([a-z0-9]+)[[:blank:]]+0x([a-z0-9]+)[[:blank:]]+[^/]+(/.*)([[:blank:]])+[A-Z]+[[:blank:]]+.*$", REG_EXTENDED))
		return ret;

	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/map"), LM_PROCFS, pproc->pid);

	maps_file = LM_FOPEN(maps_path, "r");
	if (!maps_file)
		goto FREE_EXIT;

	while ((line_len = LM_GETLINE(&maps_line, &maps_line_len, maps_file)) > 0) {
		if (regexec(&regex, maps_line, LM_ARRLEN(matches), matches, 0))
			continue;

		maps_line[--line_len] = LM_STR('\x00'); /* remove \n */
		maps_line[matches[4].rm_so] = LM_STR('\x00');
		curpath = &maps_line[matches[3].rm_so];


		/* TODO: Group copies of base and path of first and new module conditions */

		/* if it is the first module, copy the base and path */
		if (LM_STRLEN(mod.path) == 0) {
			lm_size_t pathlen = LM_STRLEN(curpath);

			if (pathlen >= LM_ARRLEN(mod.path))
				pathlen = LM_ARRLEN(mod.path) - 1;

			LM_STRNCPY(mod.path, curpath, pathlen);
			mod.path[pathlen] = LM_STR('\x00');

			_LM_GetNameFromPath(mod.path, mod.name, LM_ARRLEN(mod.name));

			mod.base = (lm_address_t)LM_STRTOP(
				&maps_line[matches[1].rm_so], NULL, 16
			);
		}

		/* if the module changes, run a callback and copy the new base and path */
		if (LM_STRCMP(curpath, mod.path)) {
			lm_size_t pathlen;

			mod.size = (lm_size_t)(
				(lm_uintptr_t)mod.end - (lm_uintptr_t)mod.base
			);

			/* NOTE: This is a fix for virtualized filesystems on Linux.
			 * The "magic symlink" directory `/proc/<PID>/root` gives a
			 * root filesystem viewed from the process' perspective, unlike
			 * `/proc/<PID>/maps`, which only gives information about
			 * what the process thinks the paths are. This is useful for
			 * getting modules for apps that are "virtualized", like Flatpaks
			 * and others.
			 * TODO: Test this on BSD.
			 */
			/*
#			if LM_OS == LM_OS_LINUX
			{
				lm_char_t old_path[LM_PATH_MAX];

				LM_STRNCPY(old_path, mod.path, LM_PATH_MAX);
				LM_SNPRINTF(mod.path, LM_ARRLEN(mod.path), LM_STR("/proc/%d/root%s"), pproc->pid, old_path);
			}
#			endif
			*/

			if (callback(&mod, arg) == LM_FALSE) {
				mod.size = 0; /* prevent last module callback */
				break;
			}

			pathlen = LM_STRLEN(curpath);
			if (pathlen >= LM_ARRLEN(mod.path))
				pathlen = LM_ARRLEN(mod.path) - 1;

			LM_STRNCPY(mod.path, curpath, pathlen);
			mod.path[pathlen] = LM_STR('\x00');

			_LM_GetNameFromPath(mod.path, mod.name, LM_ARRLEN(mod.name));

			mod.base = (lm_address_t)LM_STRTOP(
				&maps_line[matches[1].rm_so], NULL, 16
			);
		}

		/* the module end address should always update, since it's supposed
		   to be the last valid address for a module */
		mod.end = (lm_address_t)LM_STRTOP(
			&maps_line[matches[2].rm_so], NULL, 16
		);
	}

	/* run a callback for the last module */
	if (mod.size != 0) {
		/* NOTE: This is a fix for virtualized filesystems on Linux.
		 * The "magic symlink" directory `/proc/<PID>/root` gives a
		 * root filesystem viewed from the process' perspective, unlike
		 * `/proc/<PID>/maps`, which only gives information about
		 * what the process thinks the paths are. This is useful for
		 * getting modules for apps that are "virtualized", like Flatpaks
		 * and others.
		 * TODO: Test this on BSD.
		 */
		/*
#		if LM_OS == LM_OS_LINUX
		{
			lm_char_t old_path[LM_PATH_MAX];

			LM_STRNCPY(old_path, mod.path, LM_PATH_MAX);
			LM_SNPRINTF(mod.path, LM_ARRLEN(mod.path), LM_STR("/proc/%d/root%s"), pproc->pid, old_path);
		}
#		endif
		*/
		callback(&mod, arg);
	}

	ret = LM_TRUE;

	LM_FCLOSE(maps_file);
FREE_EXIT:
	regfree(&regex);
	return ret;
}
