# LM_FreeMemory

```c
LM_API lm_bool_t
LM_FreeMemory(lm_address_t alloc,
          lm_size_t    size);
```

# Description

Frees `size` bytes of allocated memory in the calling process.

# Parameters

- alloc: virtual address of the allocated memory.
- size: the size of the region deallocate.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

