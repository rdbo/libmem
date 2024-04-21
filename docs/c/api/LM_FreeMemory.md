# LM_FreeMemory

```c
LM_API lm_bool_t LM_CALL
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size);
```

# Description
The function `LM_FreeMemory` deallocates memory that was previously allocated with `LM_AllocMemory`.

# Parameters
 - `alloc`: The `alloc` parameter is the address of the memory block that was previously allocated.
 - `size`: The `size` parameter represents the size of the memory block that was previously
allocated. If the size is 0, the function will use the system's page size for unmapping the memory.

# Return Value
The function `LM_FreeMemory` returns `LM_TRUE` if the memory deallocation operation is
successful, and `LM_FALSE` if the operation fails.
