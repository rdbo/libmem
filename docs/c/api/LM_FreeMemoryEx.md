# LM_FreeMemoryEx

```c
LM_API lm_bool_t LM_CALL
LM_FreeMemoryEx(const lm_process_t *process,
		lm_address_t        alloc,
		lm_size_t           size);
```

# Description
The function deallocates memory that was previously allocated with
`LM_AllocMemoryEx` on a given process.

# Parameters
 - `process`: A pointer to the process that the memory will be deallocated from.
 - `alloc`: The address of the memory block that was previously allocated
and needs to be freed.
 - `size`: The size of the memory block that was previously allocated
and now needs to be freed. If the size is 0, the function will use the
system's page size as the default size for freeing the memory.

# Return Value
The function returns a boolean value (`LM_TRUE` or `LM_FALSE`)
indicating whether the memory deallocation operation was successful or
not.
