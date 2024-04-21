# LM_FreeMemoryEx

```c
LM_API lm_bool_t LM_CALL
LM_FreeMemoryEx(const lm_process_t *process,
		lm_address_t        alloc,
		lm_size_t           size);
```

# Description
The function `LM_FreeMemoryEx` deallocates memory that was previously allocated with `LM_AllocMemoryEx`
on a given process.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process that the memory will be allocated to.
 - `alloc`: The `alloc` parameter in the `LM_FreeMemoryEx` function represents the address of the
memory block that was previously allocated and needs to be freed.
 - `size`: The `size` parameter in the `LM_FreeMemoryEx` function represents the size of the memory
block that was previously allocated and now needs to be freed. If the `size` parameter is set to 0,
the function will use the system's page size as the default size for freeing the memory.

# Return Value
The function `LM_FreeMemoryEx` returns a boolean value (`LM_TRUE` or `LM_FALSE`) indicating
whether the memory deallocation operation was successful or not.
