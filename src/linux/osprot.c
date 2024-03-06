#include "osprot.h"
#include <sys/mman.h>

int
get_os_prot(lm_prot_t prot)
{
	switch (prot) {
	LM_PROT_X: return PROT_EXEC;
	LM_PROT_R: return PROT_READ;
	LM_PROT_W: return PROT_WRITE;
	LM_PROT_XR: return PROT_EXEC | PROT_READ;
	LM_PROT_XW: return PROT_EXEC | PROT_WRITE;
	LM_PROT_RW: return PROT_READ | PROT_WRITE;
	LM_PROT_XRW: return PROT_EXEC | PROT_READ | PROT_WRITE;
	}

	return PROT_NONE;
}
