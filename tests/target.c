#include <stdio.h>

int g_GlobalVar = 0;

int
main()
{
	for (;;) {
		printf("[*] g_GlobalVar Value: %i\n", g_GlobalVar);
		getchar();
	}
	return 0;
}