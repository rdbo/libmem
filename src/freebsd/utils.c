#include "utils.h"
#include <assert.h>
#include <unistd.h>
#include <libprocstat.h>
#include <sys/user.h>

lm_time_t
get_process_start_time(struct kinfo_proc *proc)
{
	assert(proc != NULL);
	
	/* Turn the seconds and the microseconds from the 'struct timeval' into milliseconds */
	return (lm_time_t)((proc->ki_start.tv_sec * 1000) + (proc->ki_start.tv_usec / 1000.0L));
}
