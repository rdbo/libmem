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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 /* Required for 'gettid' */
#endif
#include <libmem/libmem.h>
#include "consts.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>

LM_API lm_bool_t LM_CALL
LM_EnumThreadsEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					       lm_void_t   *arg),
		 lm_void_t          *arg)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *dirent;
	lm_thread_t thread;

	if (!process || !callback)
		return LM_FALSE;

	snprintf(path, sizeof(path), "%s/%d/task", PROCFS_PATH, process->pid);
	dir = opendir(path);
	if (!dir)
		return LM_FALSE;

	thread.owner_pid = process->pid;
	while((dirent = readdir(dir))) {
		thread.tid = atoi(dirent->d_name);
		if (thread.tid == 0 && strcmp(dirent->d_name, "0"))
			continue;

		if (callback(&thread, arg) == LM_FALSE)
			break;
	}

	closedir(dir);

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetThread(lm_thread_t *thread_out)
{
	char path[PATH_MAX];
	DIR *dir;
	
	if (!thread_out)
		return LM_FALSE;

	/*
	 * From: https://www.man7.org/linux/man-pages/man2/gettid.2.html
	 *
	 * "In a single-threaded process, the thread ID is equal to the process ID (PID,
         * as returned by getpid(2)).  In a multithreaded process, all
         * threads have the same PID, but each one has a unique TID."
	 */

	thread_out->tid = (lm_tid_t)gettid();
	thread_out->owner_pid = (lm_pid_t)getpid();

	return LM_TRUE;
}
