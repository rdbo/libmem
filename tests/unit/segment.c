#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

struct enum_segments_cbarg {
	lm_module_t mod;
	lm_bool_t check;
};

lm_bool_t _LM_EnumSegmentsCallback(lm_segment_t *psegment, lm_void_t *arg)
{
	struct enum_segments_cbarg *parg = (struct enum_segments_cbarg *)arg;

	/* Check if process module has at least one executable segment */
	if (psegment->base >= parg->mod.base && psegment->base <= parg->mod.end && (psegment->prot | LM_PROT_X)) {
		parg->check = LM_TRUE;
		return LM_FALSE;
	}

	return LM_TRUE;
}

char *test_LM_EnumSegments(lm_process_t *pcurproc)
{
	struct enum_segments_cbarg arg;
	arg.check = LM_FALSE;

	/* TODO: Get module from 'module' test */
	mu_assert("failed to retrieve current process module", LM_FindModule(pcurproc->name, &arg.mod) == LM_TRUE);
	mu_assert("failed to enumerate segments", LM_EnumSegments(_LM_EnumSegmentsCallback, &arg) == LM_TRUE);
	mu_assert("could not find executable segment in process module", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumSegments(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_EnumSegmentsEx(lm_process_t *ptargetproc)
{
	struct enum_segments_cbarg arg;
	arg.check = LM_FALSE;

	/* TODO: Get module from 'module' test */
	mu_assert("failed to retrieve current process module", LM_FindModuleEx(ptargetproc, ptargetproc->name, &arg.mod) == LM_TRUE);
	mu_assert("failed to enumerate segments", LM_EnumSegmentsEx(ptargetproc, _LM_EnumSegmentsCallback, &arg) == LM_TRUE);
	mu_assert("could not find executable segment in process module", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid process)", LM_EnumSegmentsEx(LM_NULLPTR, _LM_EnumSegmentsCallback, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumSegmentsEx(ptargetproc, LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_FindSegment(lm_process_t *pcurproc)
{
	lm_module_t mod;
	lm_segment_t segment;
	/* TODO: Get module from 'module' test */
	mu_assert("failed to retrieve current process module", LM_FindModule(pcurproc->name, &mod) == LM_TRUE);
	mu_assert("failed to get segment", LM_FindSegment(mod.base, &segment) == LM_TRUE);
	printf(" <SEGMENT: %lx-%lx %d> ", (long)segment.base, (long)segment.end, segment.prot);
	fflush(stdout);
	mu_assert("segment is invalid", CHECK_SEGMENT(&segment));
	mu_assert("function attempted to run with bad arguments (invalid segmentbuf)", LM_FindSegment(mod.base, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_FindSegmentEx(lm_process_t *ptargetproc)
{
	lm_module_t mod;
	lm_segment_t segment;
	/* TODO: Get module from 'module' test */
	mu_assert("failed to retrieve current process module", LM_FindModuleEx(ptargetproc, ptargetproc->name, &mod) == LM_TRUE);
	mu_assert("failed to get segment", LM_FindSegmentEx(ptargetproc, mod.base, &segment) == LM_TRUE);
	mu_assert("segment is invalid", CHECK_SEGMENT(&segment));
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_FindSegmentEx(LM_NULLPTR, mod.base, &segment) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid segmentbuf)", LM_FindSegmentEx(ptargetproc, mod.base, LM_NULLPTR) == LM_FALSE);

	return NULL;
}
