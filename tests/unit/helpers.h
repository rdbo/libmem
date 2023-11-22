#include <libmem/libmem.h>

#define CHECK_PROCESS(proc) ( \
	(proc)->pid != LM_PID_BAD && \
	LM_STRLEN((proc)->path) > 0 && \
	LM_STRLEN((proc)->name) > 0 \
)

#define EQUAL_PROCESSES(p1, p2) ( \
	(p1)->pid == (p2)->pid && \
	(p1)->ppid == (p2)->ppid && \
	(p1)->start_time == (p2)->start_time && \
	!LM_STRCMP((p1)->path, (p2)->path) && \
	!LM_STRCMP((p1)->name, (p2)->name) \
)

#define CHECK_THREAD(thread) ((thread)->tid != LM_TID_BAD)
#define EQUAL_THREADS(t1, t2) ((t1)->tid == (t2)->tid)

#define CHECK_MODULE(mod) ( \
	(mod)->base != LM_ADDRESS_BAD && \
	(mod)->end != LM_ADDRESS_BAD && \
	(mod)->size > 0 && \
	LM_STRLEN((mod)->path) > 0 && \
	LM_STRLEN((mod)->name) > 0 \
)

#define CHECK_PAGE(page) ( \
	(page)->base != LM_ADDRESS_BAD && \
	(page)->end != LM_ADDRESS_BAD && \
	(page)->size > 0 && \
	LM_VALID_PROT((page)->prot) \
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
