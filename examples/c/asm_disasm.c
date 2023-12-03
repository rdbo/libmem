#include <libmem/libmem.h>

void
print_bytes(lm_bytearr_t bytes, lm_size_t size)
{
	lm_size_t i;

	for (i = 0; i < size; ++i) {
		printf("%hhx ", bytes[i]);
	}
}

int
main()
{
	lm_cstring_t code_str = "push ebp; mov ebp, esp; mov esp, ebp; pop ebp; ret";
	lm_bytearr_t code_buf;
	lm_size_t    code_size;
	lm_inst_t   *insts;
	lm_size_t    inst_count;
	lm_size_t    i;
	lm_size_t    j;

	if (!(code_size = LM_AssembleEx(code_str, 32, 0xdeadbeef, &code_buf))) {
		printf("[*] Failed to Assemble Code\n");
		return -1;
	}

	printf("[*] Machine Code: ");
	print_bytes(code_buf, code_size);
	printf("\n");
	
	if (!(inst_count = LM_DisassembleEx((lm_address_t)code_buf, 32, code_size, 0, 0xdeadbeef, &insts))) {
		printf("[*] Failed to Disassemble 'code_buf'\n");
		return -1;
	}

	printf("[*] Disassembly of 'code_buf':\n");

	for (i = 0; i < inst_count; ++i) {
		printf("\t%s %s -> ", insts[i].mnemonic, insts[i].op_str);
		print_bytes(insts[i].bytes, insts[i].size);
		printf("\n");
	}

	LM_FreeInstructions(insts);
	LM_FreeCodeBuffer(code_buf);

	return 0;
}
