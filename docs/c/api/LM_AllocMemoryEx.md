# LM_AllocMemoryEx

```c
LM_API lm_address_t LM_CALL
LM_AllocMemoryEx(const lm_process_t *process,
		 lm_size_t           size,
		 lm_prot_t           prot);
```

# Description
The function `LM_AllocMemoryEx` allocates memory in a specified process with the given size and
memory protection flags.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process that the memory will be allocated to.
 - `size`: The `size` parameter in the `LM_AllocMemory` function represents the size of memory to
be allocated. If the `size` is 0, the function will allocate a full page of memory. If a specific
size is provided, that amount of memory will be allocated, aligned to the next page size.
 - `prot`: The `prot` parameter in the `LM_AllocMemory` function specifies the memory protection
flags for the allocated memory region. It is of type `lm_prot_t`, which is an enum that represents
different memory protection flags such as read (`LM_PROT_R`), write (`LM_PROT_W`), execute (`LM_PROT_X`)
permissions.

# Return Value
The function `LM_AllocMemoryEx` returns a memory address of type `lm_address_t` if the
memory allocation is successful. If there are any issues, it returns `LM_ADDRESS_BAD`.
