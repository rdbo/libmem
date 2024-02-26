#include "internal.h"

LM_PRIVATE lm_time_t
_LM_GetProcessStartTime(lm_pid_t pid)
{
	lm_time_t   start_time = LM_TIME_BAD;
	lm_char_t   stat_path[LM_PATH_MAX] = { 0 };
	FILE       *stat_file;
	lm_char_t  *stat_line = NULL;
	size_t      buf_len;

	LM_SNPRINTF(stat_path, LM_ARRLEN(stat_path),
		    LM_STR("%s/%d/stat"), LM_PROCFS, pid);

	stat_file = LM_FOPEN(stat_path, "r");
	if (!stat_file)
		goto FREE_EXIT;


	if (LM_GETLINE(&stat_line, &buf_len, stat_file) > 0) {
		sscanf(stat_line, "%*d %*[(]%*[^)]%*[)] %*c %*d %*d %*d %*d %*d %*u %*lu %*lu %*lu %*lu %*lu %*lu %*ld %*ld %*ld %*ld %*ld %*ld %llu", (unsigned long long *)&start_time);
	}

	LM_FREE(stat_line);
	LM_FCLOSE(stat_file);
FREE_EXIT:
	return start_time;
}

/********************************/

LM_PRIVATE lm_pid_t
_LM_GetParentIdEx(lm_pid_t pid)
{
	lm_pid_t    ppid = LM_PID_BAD;	
	lm_char_t   stat_path[LM_PATH_MAX] = { 0 };
	FILE       *stat_file;
	lm_char_t  *stat_line = NULL;
	size_t      buf_len;
	regex_t     regex;
	regmatch_t  matches[2];

	if (regcomp(&regex, "^[0-9]+[[:blank:]]+[(].*[)][[:blank:]]+[A-Z][[:blank:]]+([0-9]+)[[:blank:]].*$", REG_EXTENDED))
		return ppid;

	LM_SNPRINTF(stat_path, LM_ARRLEN(stat_path),
		    LM_STR("%s/%d/stat"), LM_PROCFS, pid);

	stat_file = LM_FOPEN(stat_path, "r");
	if (!stat_file)
		goto FREE_EXIT;


	if (LM_GETLINE(&stat_line, &buf_len, stat_file) > 0 && !regexec(&regex, stat_line, LM_ARRLEN(matches), matches, 0)) {
		stat_line[matches[1].rm_eo] = LM_STR('\x00'); /* place null terminator to do 'LM_STRCMP' later */
		ppid = (lm_pid_t)LM_ATOI(&stat_line[matches[1].rm_so]);
		if (ppid == 0 && LM_STRCMP(&stat_line[matches[1].rm_so], "0"))
			ppid = LM_PID_BAD;
	}

	LM_FREE(stat_line);
	LM_FCLOSE(stat_file);
FREE_EXIT:
	regfree(&regex);
	return ppid;
}

/********************************/

LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t   pid,
		     lm_char_t *pathbuf,
		     lm_size_t  maxlen)
{
	ssize_t slen;
	lm_char_t exe_path[LM_PATH_MAX] = { 0 };

	LM_SNPRINTF(exe_path, LM_ARRLEN(exe_path),
		    LM_STR("%s/%d/exe"), LM_PROCFS, pid);
	
	/* readlink does not append a null terminator, so use maxlen - 1
	   and append it later */
	slen = readlink(exe_path, pathbuf, maxlen - 1);
	if (slen == -1)
		slen = 0;
	pathbuf[slen] = LM_STR('\x00');
	return (lm_size_t)slen;
}
