#include "internal.h"

LM_PRIVATE lm_time_t
_LM_GetProcessStartTime(lm_pid_t pid)
{
	lm_time_t start_time = LM_TIME_BAD;
	struct procstat *ps;
	unsigned int nprocs = 0;
	struct kinfo_proc *procs;

	ps = procstat_open_sysctl();
	if (!ps)
		return start_time;

	procs = procstat_getprocs(
		ps, KERN_PROC_PID,
		pid, &nprocs
	);

	if (procs && nprocs) {
		start_time = (lm_time_t)procs[0].ki_start.tv_sec;
		procstat_freeprocs(ps, procs);
	}

	procstat_close(ps);

	return start_time;

}

/********************************/

LM_PRIVATE lm_pid_t
_LM_GetParentIdEx(lm_pid_t pid)
{
	lm_pid_t ppid = LM_PID_BAD;
	struct procstat *ps;
	unsigned int nprocs = 0;
	struct kinfo_proc *procs;

	ps = procstat_open_sysctl();
	if (!ps)
		return ppid;

	procs = procstat_getprocs(
		ps, KERN_PROC_PID,
		pid, &nprocs
	);

	if (procs && nprocs) {
		ppid = (lm_pid_t)procs[0].ki_ppid;
		procstat_freeprocs(ps, procs);
	}

	procstat_close(ps);

	return ppid;
}

/********************************/

LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t   pid,
		     lm_char_t *pathbuf,
		     lm_size_t  maxlen)
{
	lm_size_t len = 0;
	struct procstat *ps;
	unsigned int nprocs = 0;
	struct kinfo_proc *procs;

	ps = procstat_open_sysctl();
	if (!ps)
		return len;

	procs = procstat_getprocs(
		ps, KERN_PROC_PID,
		pid, &nprocs
	);

	if (procs && nprocs) {
		if (!procstat_getpathname(ps, procs,
					  pathbuf, maxlen))
			len = LM_STRLEN(pathbuf);

		procstat_freeprocs(ps, procs);
	}

	procstat_close(ps);

	return len;
}
