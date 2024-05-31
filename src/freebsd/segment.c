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
#include <unistd.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <libprocstat.h>

LM_API lm_bool_t LM_CALL
LM_EnumSegments(lm_bool_t (LM_CALL *callback)(lm_segment_t *segment,
                			      lm_void_t    *arg),
		lm_void_t          *arg)
{
	lm_process_t process;

	if (!callback)
		return LM_FALSE;

	if (!LM_GetProcess(&process))
		return LM_FALSE;

	return LM_EnumSegmentsEx(&process, callback, arg);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_EnumSegmentsEx(const lm_process_t *process,
                  lm_bool_t (LM_CALL *callback)(lm_segment_t *segment,
						lm_void_t    *arg),
		  lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	struct procstat *ps;
	struct kinfo_proc *proc;
	struct kinfo_vmentry *vmmap;
	unsigned int count;
	unsigned int i;
	lm_segment_t segment;
	
	if (!process || !callback)
		return result;

	ps = procstat_open_sysctl();
	if (!ps)
		return result;

	proc = procstat_getprocs(ps, KERN_PROC_PID, process->pid, &count);
	if (!proc)
		goto CLOSE_EXIT;

	vmmap = procstat_getvmmap(ps, proc, &count);
	procstat_freeprocs(ps, proc);
	if (!vmmap)
		goto CLOSE_EXIT;

	for (i = 0; i < count; ++i) {
		segment.base = vmmap[i].kve_start;
		segment.end = vmmap[i].kve_end;
		segment.size = segment.end - segment.base;
		segment.prot = get_prot(vmmap[i].kve_protection);

		if (callback(&segment, arg) == LM_FALSE)
			break;
	}

	result = LM_TRUE;

	procstat_freevmmap(ps, vmmap);
CLOSE_EXIT:
	procstat_close(ps);
	return result;
}
