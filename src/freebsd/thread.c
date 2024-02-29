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

#include <libmem/libmem.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <libprocstat.h>

LM_API lm_bool_t LM_CALL
LM_EnumThreadsEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					       lm_void_t   *arg),
		 lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	struct procstat *ps;
	struct kinfo_proc *procs;
	unsigned int nprocs;
	unsigned int i;
	lm_thread_t thread;

	if (!process || !callback)
		return result;

	ps = procstat_open_sysctl();
	if (!ps)
		return result;

	procs = procstat_getprocs(ps, KERN_PROC_PID|KERN_PROC_INC_THREAD, process->pid, &nprocs);
	if (!procs)
		goto CLOSE_EXIT;

	thread.owner_pid = process->pid;
	for (i = 0; i < nprocs; ++i) {
		thread.tid = (lm_tid_t)procs[i].ki_tid;

		if (!callback(&thread, arg))
			break;
	}

	result = LM_TRUE;

	procstat_freeprocs(ps, procs);
CLOSE_EXIT:
	procstat_close(ps);
	return result;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetThread(lm_thread_t *thread_out)
{
	long tid;
	
	if (!thread_out)
		return LM_FALSE;

	/*
	 * From: https://man.freebsd.org/cgi/man.cgi?query=thr_self&sektion=2&n=1
	 *
	 * "The thr_self() system call stores the system-wide thread	identifier for
         * the  current kernel-scheduled thread in the variable pointed by the ar-
         * gument id."
	 */

	if (thr_self(&tid))
		return LM_FALSE;

	thread_out->tid = (lm_tid_t)tid;
	thread_out->owner_pid = (lm_pid_t)getpid();

	return LM_TRUE;
}
