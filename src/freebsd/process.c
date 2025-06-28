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
#include <posixutils/posixutils.h>
#include <elfutils/elfutils.h>
#include <arch/arch.h>
#include <assert.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <libprocstat.h>
#include "utils.h"

LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *process,
					       lm_void_t    *arg),
		 lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	struct procstat *ps;
	struct kinfo_proc *procs;
	unsigned int nprocs;
	unsigned int i;
	lm_process_t process;
	FILE *elf;

	if (!callback)
		return result;

	ps = procstat_open_sysctl();
	if (!ps)
		return result;

	procs = procstat_getprocs(ps, KERN_PROC_PROC, 0, &nprocs);
	if (!procs)
		goto CLOSE_EXIT;

	for (i = 0; i < nprocs; ++i) {
		process.pid = (lm_pid_t)procs[i].ki_pid;
		process.ppid = (lm_pid_t)procs[i].ki_ppid;

		if (procstat_getpathname(ps, &procs[i], process.path, sizeof(process.path)))
			continue;

		if (get_name_from_path(process.path, process.name, sizeof(process.name)) == 0)
			continue;

		process.start_time = get_process_start_time(&procs[i]);

		process.bits = get_elf_bits(process.path);

		process.arch = get_architecture_from_bits(process.bits);

		if (callback(&process, arg) == LM_FALSE)
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
LM_GetProcess(lm_process_t *process_out)
{
	lm_bool_t result = LM_FALSE;
	struct procstat *ps;
	struct kinfo_proc *procs;
	unsigned int nprocs;

	if (!process_out)
		return result;

	ps = procstat_open_sysctl();
	if (!ps)
		return result;

	process_out->pid = (lm_pid_t)getpid();
	process_out->ppid = (lm_pid_t)getppid();

	procs = procstat_getprocs(ps, KERN_PROC_PID, (pid_t)process_out->pid, &nprocs);
	if (!procs)
		goto CLOSE_EXIT;

	if (procstat_getpathname(ps, &procs[0], process_out->path, sizeof(process_out->path)))
		goto CLOSE_EXIT;

	if (get_name_from_path(process_out->path, process_out->name, sizeof(process_out->name)) == 0)
		goto CLOSE_EXIT;

	process_out->start_time = get_process_start_time(procs);
	process_out->bits = LM_GetBits();

	process_out->arch = get_architecture_from_bits(process_out->bits);

	result = LM_TRUE;

	procstat_freeprocs(ps, procs);
CLOSE_EXIT:
	procstat_close(ps);
	return result;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *process_out)
{
	lm_bool_t result = LM_FALSE;
	struct procstat *ps;
	struct kinfo_proc *procs;
	unsigned int nprocs;

	if (pid == LM_PID_BAD || !process_out)
		return result;

	ps = procstat_open_sysctl();
	if (!ps)
		return result;

	process_out->pid = pid;

	procs = procstat_getprocs(ps, KERN_PROC_PID, (pid_t)process_out->pid, &nprocs);
	if (!procs)
		goto CLOSE_EXIT;

	process_out->ppid = procs[0].ki_ppid;

	if (procstat_getpathname(ps, &procs[0], process_out->path, sizeof(process_out->path)))
		goto CLOSE_EXIT;

	if (get_name_from_path(process_out->path, process_out->name, sizeof(process_out->name)) == 0)
		goto CLOSE_EXIT;

	process_out->start_time = get_process_start_time(procs);
	process_out->bits = get_elf_bits(process_out->path);

	process_out->arch = get_architecture_from_bits(process_out->bits);

	result = LM_TRUE;

	procstat_freeprocs(ps, procs);
CLOSE_EXIT:
	procstat_close(ps);
	return result;
}

/********************************/

LM_API lm_char_t * LM_CALL
LM_GetCommandLine(lm_process_t *process)
{
	struct procstat *ps;
	struct kinfo_proc *proc;
	unsigned int nprocs;
	lm_char_t **cmdargs = NULL;

	assert(process != NULL);

	ps = procstat_open_sysctl();
	if (!ps)
		return result;

	proc = procstat_getprocs(ps, KERN_PROC_PID, process->pid, &nprocs);
	if (!proc)
		goto CLOSE_EXIT;

	cmdargs = get_process_cmdline(ps, proc);

	procstat_freeprocs(ps, proc);
CLOSE_EXIT:
	procstat_close(ps);
	return cmdargs;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_GetSystemBits()
{
	return (lm_size_t)get_system_bits();
}
