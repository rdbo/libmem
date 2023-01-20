# LM_FreeMemoryEx

```c
LM_API lm_bool_t
LM_FreeMemoryEx(lm_process_t *pproc,
        lm_address_t  alloc,
        lm_size_t     size);
```

# Description

Frees `size` bytes of allocated memory in a remote process.

# Parameters

- pproc: pointer to a valid process that will have be deallocated.
- alloc: virtual address of the allocated memory.
- size: the size of the region to deallocate.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

