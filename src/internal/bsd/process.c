#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *pproc,
						lm_void_t    *arg),
		  lm_void_t          *arg)
{
	lm_bool_t ret = LM_FALSE;
	struct procstat *ps;
	unsigned int nprocs = 0;
	struct kinfo_proc *procs;
	lm_process_t proc;
	lm_size_t    len;

	ps = procstat_open_sysctl();
	if (!ps)
		return ret;
		
	procs = procstat_getprocs(
		ps, KERN_PROC_PROC, 
		0, &nprocs
	);

	if (procs) {
		unsigned int i;

		for (i = 0; i < nprocs; ++i) {
			proc.pid = (lm_pid_t)procs[i].ki_pid;
			proc.ppid = (lm_pid_t)procs[i].ki_ppid;
			if (!_LM_GetProcessPathEx(proc.pid, proc.path, LM_ARRLEN(proc.path)))
				continue;

			proc.start_time = _LM_GetProcessStartTime(proc.pid);
			if (proc.start_time == LM_TIME_BAD)
				continue;

			len = LM_STRLEN(procs[i].ki_comm);
			if (len >= LM_ARRLEN(proc.name))
				len = LM_ARRLEN(proc.name) - 1;

			LM_STRNCPY(proc.name, procs[i].ki_comm, len);

			proc.bits = _LM_GetProcessBitsEx(proc.path);

			if (callback(&proc, arg) == LM_FALSE)
				break;
		}

		procstat_freeprocs(ps, procs);

		ret = LM_TRUE;
	}

	procstat_close(ps);

	return ret;
}
