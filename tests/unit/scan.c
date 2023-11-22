#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

const lm_byte_t scanbuf[20] = { 0x1, 0x43, 0xfa, 0x48, 0x15, 'A', 'B', 'C', 0x0, 'D', 'E', 'F', 0xfa, 0x44, 0xde, 0xad, 0xbe, 0xef, 0x0, 0x0 };
const lm_size_t match_offset = 5;
static const lm_byte_t *expected_match = &scanbuf[match_offset];
static lm_byte_t datascan[] = { 'A', 'B', 'C', '\0', 'D', 'E', 'F' };
static lm_byte_t scanpattern[] = { 'A', 'B', 'C', '\xFF', 'D', 'E', 'F' };
static lm_string_t scanmask = "xxx?xxx";
static lm_byte_t invalidscan[] = { 'L', 'I', 'B', '\0', 'M', 'E', 'M' };
static lm_string_t scansig = "41 42 43 ?? 44 45 46";
static lm_string_t invalidsig = "61 62 63 ?? 64 65 66";

char *test_LM_DataScan(void *arg)
{
	lm_address_t result;

	result = LM_DataScan(datascan, sizeof(datascan), (lm_address_t)scanbuf, sizeof(scanbuf));
	mu_assert("result does not match expected address", result == (lm_address_t)expected_match);

	result = LM_DataScan(invalidscan, sizeof(invalidscan), (lm_address_t)scanbuf, sizeof(scanbuf));
	mu_assert("scan returned invalid match", result == LM_ADDRESS_BAD);

	mu_assert("function attempted to run with bad argument (invalid data)", LM_DataScan(LM_NULLPTR, sizeof(datascan), (lm_address_t)scanbuf, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid size)", LM_DataScan(datascan, 0, (lm_address_t)scanbuf, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan address)", LM_DataScan(datascan, sizeof(datascan), LM_ADDRESS_BAD, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan size)", LM_DataScan(datascan, sizeof(datascan), (lm_address_t)scanbuf, 0) == LM_ADDRESS_BAD);

	return NULL;
}

char *test_LM_DataScanEx(struct scan_args *arg)
{
	lm_address_t result;

	result = LM_DataScanEx(arg->ptargetproc, datascan, sizeof(datascan), arg->scanaddr, sizeof(scanbuf));
	mu_assert("result does not match expected address", result == (arg->scanaddr + match_offset));

	result = LM_DataScanEx(arg->ptargetproc, invalidscan, sizeof(invalidscan), arg->scanaddr, sizeof(scanbuf));
	mu_assert("scan returned invalid match", result == LM_ADDRESS_BAD);

	mu_assert("function attempted to run with bad argument (invalid proc)", LM_DataScanEx(LM_NULLPTR, datascan, sizeof(datascan), arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid data)", LM_DataScanEx(arg->ptargetproc, LM_NULLPTR, sizeof(datascan), arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid size)", LM_DataScanEx(arg->ptargetproc, datascan, 0, arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan address)", LM_DataScanEx(arg->ptargetproc, datascan, sizeof(datascan), LM_ADDRESS_BAD, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan size)", LM_DataScanEx(arg->ptargetproc, datascan, sizeof(datascan), arg->scanaddr, 0) == LM_ADDRESS_BAD);

	return NULL;
}

char *test_LM_PatternScan(void *arg)
{
	lm_address_t result;

	result = LM_PatternScan(scanpattern, scanmask, (lm_address_t)scanbuf, sizeof(scanbuf));
	mu_assert("result does not match expected address", result == (lm_address_t)expected_match);

	result = LM_PatternScan(invalidscan, scanmask, (lm_address_t)scanbuf, sizeof(scanbuf));
	mu_assert("scan returned invalid match", result == LM_ADDRESS_BAD);

	mu_assert("function attempted to run with bad argument (invalid pattern)", LM_PatternScan(LM_NULLPTR, scanmask, (lm_address_t)scanbuf, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid mask)", LM_PatternScan(scanpattern, LM_NULLPTR, (lm_address_t)scanbuf, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan address)", LM_PatternScan(scanpattern, scanmask, LM_ADDRESS_BAD, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan size)", LM_PatternScan(scanpattern, scanmask, (lm_address_t)scanbuf, 0) == LM_ADDRESS_BAD);

	return NULL;
}

char *test_LM_PatternScanEx(struct scan_args *arg)
{
	lm_address_t result;

	result = LM_PatternScanEx(arg->ptargetproc, scanpattern, scanmask, arg->scanaddr, sizeof(scanbuf));
	mu_assert("result does not match expected address", result == (arg->scanaddr + match_offset));

	result = LM_PatternScanEx(arg->ptargetproc, invalidscan, scanmask, arg->scanaddr, sizeof(scanbuf));
	mu_assert("scan returned invalid match", result == LM_ADDRESS_BAD);

	mu_assert("function attempted to run with bad argument (invalid proc)", LM_PatternScanEx(LM_NULLPTR, scanpattern, scanmask, arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid pattern)", LM_PatternScanEx(arg->ptargetproc, LM_NULLPTR, scanmask, arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid mask)", LM_PatternScanEx(arg->ptargetproc, scanpattern, LM_NULLPTR, arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan address)", LM_PatternScanEx(arg->ptargetproc, scanpattern, scanmask, LM_ADDRESS_BAD, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan size)", LM_PatternScanEx(arg->ptargetproc, scanpattern, scanmask, arg->scanaddr, 0) == LM_ADDRESS_BAD);

	return NULL;
}

char *test_LM_SigScan(void *arg)
{
	lm_address_t result;

	result = LM_SigScan(scansig, (lm_address_t)scanbuf, sizeof(scanbuf));
	mu_assert("result does not match expected address", result == (lm_address_t)expected_match);

	result = LM_SigScan(invalidsig, (lm_address_t)scanbuf, sizeof(scanbuf));
	mu_assert("scan returned invalid match", result == LM_ADDRESS_BAD);

	mu_assert("function attempted to run with bad argument (invalid sig)", LM_SigScan(LM_NULLPTR, (lm_address_t)scanbuf, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan address)", LM_SigScan(scansig, LM_ADDRESS_BAD, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan size)", LM_SigScan(scansig, (lm_address_t)scanbuf, 0) == LM_ADDRESS_BAD);

	return NULL;
}

char *test_LM_SigScanEx(struct scan_args *arg)
{
	lm_address_t result;

	result = LM_SigScanEx(arg->ptargetproc, scansig, arg->scanaddr, sizeof(scanbuf));
	mu_assert("result does not match expected address", result == (arg->scanaddr + match_offset));

	result = LM_SigScanEx(arg->ptargetproc, invalidsig, arg->scanaddr, sizeof(scanbuf));
	mu_assert("scan returned invalid match", result == LM_ADDRESS_BAD);

	mu_assert("function attempted to run with bad argument (invalid proc)", LM_SigScanEx(LM_NULLPTR, scansig, arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid sig)", LM_SigScanEx(arg->ptargetproc, LM_NULLPTR, arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan address)", LM_SigScanEx(arg->ptargetproc, scansig, LM_ADDRESS_BAD, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan size)", LM_SigScanEx(arg->ptargetproc, scansig, arg->scanaddr, 0) == LM_ADDRESS_BAD);

	return NULL;
}