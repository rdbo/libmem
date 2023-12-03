#include <libmem/libmem.h>

int
main()
{
	lm_process_t current_process;
	lm_process_t parent_process;

	/* get the current process */
	if (!LM_GetProcess(&current_process)) {
		printf("[*] Failed to get current process\n");
		return -1;
	}

	printf("[*] Process ID:          %u\n", current_process.pid);
	printf("[*] Parent Process ID:   %u\n", current_process.ppid);

	/* get the parent process using the 'ppid' field */
	if (!LM_GetProcessEx(current_process.ppid, &parent_process)) {
		printf("[*] Failed to get the parent process\n");
		return -1;
	}

	printf("[*] Parent Process Name: %s\n", parent_process.name);

	return 0;
}
