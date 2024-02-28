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
#include <libprocstat.h>

lm_time_t
get_process_start_time(struct kinfo_proc *proc)
{
	/* Turn the seconds and the microseconds from the 'struct timeval' into milliseconds */
	return (lm_time_t)((proc->ki_start.tv_sec * 1000) + (proc->ki_start.tv_usec / 1000.0L));
}

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

		if (get_name_from_path(process.path, process.name, sizeof(process.name)) == 0) {
			continue;
		}

		process.start_time = get_process_start_time(&procs[i]);

		process.bits = sizeof(void *); /* Assume target process bits == size of pointer by default */
		elf = fopen(process.path, "r");
		if (elf) {
			size_t bits = get_elf_bits(elf);
			if (bits > 0) {
				process.bits = bits;
			}

			fclose(elf);
		}

		if (callback(&process, arg) == LM_FALSE)
			break;
	}

	procstat_freeprocs(ps, procs);
CLOSE_EXIT:
	procstat_close(ps);
}
