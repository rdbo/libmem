# LM_AllocMemory

```c
LM_API lm_address_t LM_CALL
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot);
```

# Description
The function allocates memory with a specified size and protection flags,
returning the allocated memory address.

# Parameters
 - `size`: The size of memory to be allocated. If the size is 0, the
function will allocate a full page of memory. If a specific size is
provided, that amount of memory will be allocated, aligned to the next
page size.
 - `prot`: The memory protection flags for the allocated memory region.
It is a bit mask of `LM_PROT_X` (execute), `LM_PROT_R` (read), `LM_PROT_W`
(write).

# Return Value
The function returns the memory address of the allocated memory with
the specified allocation options, or `LM_ADDRESS_BAD` if it fails.
