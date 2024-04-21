# LM_AllocMemory

```c
LM_API lm_address_t LM_CALL
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot);
```

# Description
The function `LM_AllocMemory` allocates memory with a specified size and protection flags, returning
the allocated memory address.

# Parameters
 - `size`: The `size` parameter in the `LM_AllocMemory` function represents the size of memory to
be allocated. If the `size` is 0, the function will allocate a full page of memory. If a specific
size is provided, that amount of memory will be allocated, aligned to the next page size.
 - `prot`: The `prot` parameter in the `LM_AllocMemory` function specifies the memory protection
flags for the allocated memory region. It is of type `lm_prot_t`, which is an enum that represents
different memory protection flags such as read (`LM_PROT_R`), write (`LM_PROT_W`), execute (`LM_PROT_X`)
permissions.

# Return Value
The function `LM_AllocMemory` returns the memory address of the allocated memory with the specified
allocation options, or `LM_ADDRESS_BAD` if it fails.
