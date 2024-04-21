# LM_AllocMemoryEx

```c
LM_API lm_address_t LM_CALL
LM_AllocMemoryEx(const lm_process_t *process,
		 lm_size_t           size,
		 lm_prot_t           prot);
```

# Description
The function allocates memory in a specified process with the given size
and memory protection flags.

# Parameters
 - `process`: A pointer to the process that the memory will be allocated to.
 - `size`: The size of memory to be allocated. If the size is 0, the
function will allocate a full page of memory. If a specific size is
provided, that amount of memory will be allocated, aligned to the next
page size.
 - `prot`: The memory protection flags for the allocated memory region.
It is a bit mask of `LM_PROT_X` (execute), `LM_PROT_R` (read), `LM_PROT_W`
(write).

# Return Value
The function returns a memory address of type `lm_address_t` if the
memory allocation is successful. If there are any issues, it returns
`LM_ADDRESS_BAD`.
