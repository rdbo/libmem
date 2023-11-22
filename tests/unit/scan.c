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
	mu_assert("result does not match expected address", result == arg->scanaddr + match_offset);

	result = LM_DataScanEx(arg->ptargetproc, invalidscan, sizeof(invalidscan), arg->scanaddr, sizeof(scanbuf));
	mu_assert("scan returned invalid match", result == LM_ADDRESS_BAD);

	mu_assert("function attempted to run with bad argument (invalid proc)", LM_DataScanEx(LM_NULLPTR, datascan, sizeof(datascan), arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid data)", LM_DataScanEx(arg->ptargetproc, LM_NULLPTR, sizeof(datascan), arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid size)", LM_DataScanEx(arg->ptargetproc, datascan, 0, arg->scanaddr, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan address)", LM_DataScanEx(arg->ptargetproc, datascan, sizeof(datascan), LM_ADDRESS_BAD, sizeof(scanbuf)) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad argument (invalid scan size)", LM_DataScanEx(arg->ptargetproc, datascan, sizeof(datascan), arg->scanaddr, 0) == LM_ADDRESS_BAD);

	return NULL;
}