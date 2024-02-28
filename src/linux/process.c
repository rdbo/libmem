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

#include <errno.h>
#include <libmem/libmem.h>
#include <posixutils/posixutils.h>
#include <elfutils/elfutils.h>
#include "consts.h"
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

lm_bool_t
get_stat_info(lm_pid_t pid, lm_pid_t *ppid_out, lm_time_t *start_time_out)
{
	lm_bool_t result = LM_FALSE;
	pid_t ppid;
	unsigned long long starttime;
	char path[PATH_MAX];
	FILE *stat_file;

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
	 * (2) comm (%s)
	 * (3) state (%c)
	 * (4) ppid (%d)
	 * ... (17 other unused values)
	 * (22) starttime (%llu)
	 */

	errno = 0;
	const char *scanstr = "%*s %*s %*s %d %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu";
	if (fscanf(stat_file, scanstr, &ppid, &starttime) == 0 || errno) {
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

/********************************/

LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *process,
					       lm_void_t    *arg),
		 lm_void_t          *arg)
{
	if (callback == NULL)
		return LM_FALSE;

	struct dirent *dirent;
	DIR *dir;
	lm_process_t process;

	dir = opendir(PROCFS_PATH);
	if (!dir)
		return LM_FALSE;

	while ((dirent = readdir(dir))) {
		FILE *elf;

		process.pid = atoi(dirent->d_name);

		/* Since 'atoi' returns 0 on failure, we need to check if the PID is 0, or 
		 * the function actually failed. If the PID is invalid, skip */
		if (!process.pid && strcmp(dirent->d_name, "0"))
			continue;

		if (!get_stat_info(process.pid, &process.ppid, &process.start_time)) {
			continue;
		}

		if (get_process_path(process.pid, process.path, sizeof(process.path)) == 0)
			continue;

		if (get_name_from_path(process.path, process.name, sizeof(process.name)) == 0) {
			continue;
		}

		process.bits = get_elf_bits(process.path);

		if (callback(&process, arg) == LM_FALSE)
			break;
	}

	closedir(dir);

	return LM_TRUE;
}

/********************************/

/*
 * NOTE: Previously, libmem had a caching mechanism for getting the current
 *       process by using a static variable. That is not a good idea, because
 *       the current process can 'fork()' for example, and suddenly this
 *       function gives a bad value.
 */
LM_API lm_bool_t LM_CALL
LM_GetProcess(lm_process_t *process_out)
{
	if (!process_out)
		return LM_FALSE;
	
	process_out->pid = getpid();
	process_out->ppid = getppid();

	if (get_process_path(process_out->pid, process_out->path, sizeof(process_out->path)) == 0) {
		return LM_FALSE;
	}

	if (get_name_from_path(process_out->path, process_out->name, sizeof(process_out->name)) == 0) {
		return LM_FALSE;
	}

	if (!get_stat_info(process_out->pid, LM_NULLPTR, &process_out->start_time)) {
		return LM_FALSE;
	}

	process_out->bits = sizeof(void *);

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *process_out)
{
	if (pid == LM_PID_BAD || !process_out)
		return LM_FALSE;
	
	process_out->pid = pid;

	if (get_process_path(process_out->pid, process_out->path, sizeof(process_out->path)) == 0) {
		return LM_FALSE;
	}

	if (get_name_from_path(process_out->path, process_out->name, sizeof(process_out->name)) == 0) {
		return LM_FALSE;
	}

	if (!get_stat_info(process_out->pid, &process_out->ppid, &process_out->start_time)) {
		return LM_FALSE;
	}

	process_out->bits = sizeof(void *);

	return LM_TRUE;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_GetSystemBits(lm_void_t)
{
	return (lm_size_t)get_system_bits();
}
