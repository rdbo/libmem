/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "utils.h"
#include "consts.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

lm_bool_t
get_stat_info(lm_pid_t pid, lm_pid_t *ppid_out, lm_time_t *start_time_out)
{
	lm_bool_t result = LM_FALSE;
	pid_t ppid;
	unsigned long long starttime;
	char path[PATH_MAX];
	FILE *stat_file;
	char stat_buf[512] = { 0 }; /* This buffer is big enough, because the process `comm`
	                             * is truncated, and other values are relatively small. */
	char *ptr;

	/* At least one of the 'out' variables must be not NULL,
	 * otherwise, this function would just be a big no-op */
	assert(pid != LM_PID_BAD && (ppid_out || start_time_out));

	snprintf(path, sizeof(path), "%s/%d/stat", PROCFS_PATH, pid);
	stat_file = fopen(path, "r");
	if (!stat_file) {
		return result;
	}

	/*
	 * /proc/<pid>/stat contents:
	 * 
	 * (1) pid (%d)
	 * (2) comm (%s) - up to 16 chars
	 * (3) state (%c)
	 * (4) ppid (%d)
	 * ... (17 other unused values)
	 * (22) starttime (%llu)
	 */

	if (fread(stat_buf, 1, sizeof(stat_buf), stat_file) == 0) {
		goto CLOSE_EXIT;
	}

	/*
	 * NOTE: Processes can have whitespaces and ')' in their 'comm' string of
	 *       `/proc/<pid>/stat`, which can make parsing annoying. To circumvent
	 *       that, we will just skip to the last closing parenthese, and skip
	 *       through whitespaces from there.
	 *       This means our pointer will be at the end of `comm (2)`, and we
	 *       can use a scanf-like function to parse the rest
	 */
	ptr = strrchr(stat_buf, ')');
	if (!ptr)
		goto CLOSE_EXIT;
	ptr = &ptr[1];

	errno = 0;
	if (sscanf(ptr, "%*s %d %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu",
	           &ppid, &starttime) == 0 || errno) {
		goto CLOSE_EXIT;
	}

	if (ppid_out) {
		*ppid_out = (lm_pid_t)ppid;
	}

	if (start_time_out) {
		long ticks_per_sec;

		/* Convert ticks to milliseconds */
		ticks_per_sec = sysconf(_SC_CLK_TCK);
		*start_time_out = (lm_time_t)(starttime * (ticks_per_sec / 1000.0L));
	}

	result = LM_TRUE;

CLOSE_EXIT:
	fclose(stat_file);
	return result;
}

lm_size_t
get_process_path(lm_pid_t pid, lm_char_t *pathbuf, size_t pathsize)
{
	char exe_path[PATH_MAX];
	ssize_t len;
	
	assert(pid != LM_PID_BAD && pathbuf != NULL && pathsize > 0);

	snprintf(exe_path, sizeof(exe_path), "%s/%d/exe", PROCFS_PATH, pid);
	len = readlink(exe_path, pathbuf, pathsize - 1);
	if (len == -1) {
		len = 0;
	} else {
		/* We reserved space for the null terminator in the call above,
		 * so we can safely use 'len' to place it */
		pathbuf[len] = '\0';
	}

	return (lm_size_t)len;
}
