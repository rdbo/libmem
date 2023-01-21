#include <libmem/libmem.h>

int
main()
{
	int some_var = 10;
	int read_some_var;
	int write_some_var = 1337;
	printf("[*] Value of 'some_var': %d\n", some_var);

	LM_ReadMemory((lm_address_t)&some_var, (lm_byte_t *)&read_some_var, sizeof(read_some_var));
	printf("[*] Read Value of 'some_var': %d\n", read_some_var);

	LM_WriteMemory((lm_address_t)&some_var, (lm_bytearr_t)&write_some_var, sizeof(write_some_var));
	printf("[*] Value of 'some_var' after writing: %d\n", some_var);

	return 0;
}
