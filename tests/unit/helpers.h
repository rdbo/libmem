#include <libmem/libmem.h>
#include <string.h>
#include <stdio.h>

#define CHECK_PROCESS(proc) ( \
	(proc)->pid != LM_PID_BAD && \
	strlen((proc)->path) > 0 && \
	strlen((proc)->name) > 0 \
)

#define EQUAL_PROCESSES(p1, p2) ( \
	(p1)->pid == (p2)->pid && \
	(p1)->ppid == (p2)->ppid && \
	(p1)->start_time == (p2)->start_time && \
	!strcmp((p1)->path, (p2)->path) && \
	!strcmp((p1)->name, (p2)->name) \
)

#define CHECK_THREAD(thread) ((thread)->tid != LM_TID_BAD)
#define EQUAL_THREADS(t1, t2) ((t1)->tid == (t2)->tid)

#define CHECK_MODULE(mod) ( \
	(mod)->base != LM_ADDRESS_BAD && \
	(mod)->end != LM_ADDRESS_BAD && \
	(mod)->size > 0 && \
	strlen((mod)->path) > 0 && \
	strlen((mod)->name) > 0 \
)

#define CHECK_SEGMENT(segment) ( \
	(segment)->base != LM_ADDRESS_BAD && \
	(segment)->end != LM_ADDRESS_BAD && \
	(segment)->size > 0 && \
	LM_CHECK_PROT((segment)->prot) \
)

struct thread_args {
	lm_process_t *pcurproc;
	lm_process_t *ptargetproc;
	lm_thread_t *pcurthread;
	lm_thread_t *ptargetthread;
};

struct load_module_args {
	lm_process_t *ptargetproc;
	lm_module_t *pmod;
};

struct memory_args {
	lm_process_t *ptargetproc;
	lm_address_t *palloc; /* TODO: Change this to just 'lm_address_t alloc' */
};

struct hook_args {
	lm_process_t *ptargetproc;
	lm_address_t trampoline;
	lm_size_t hksize;
};

extern const lm_byte_t scanbuf[20];

struct scan_args {
	lm_process_t *ptargetproc;
	lm_address_t scanaddr;
};
