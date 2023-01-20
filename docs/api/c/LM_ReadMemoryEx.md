# LM_ReadMemoryEx

```c
LM_API lm_size_t
LM_ReadMemoryEx(lm_process_t *pproc,
        lm_address_t  src,
        lm_byte_t    *dst,
        lm_size_t     size);
```

# Description

Reads `size` bytes of memory from a remote process at a virtual address (`src`) into `dst`.

# Parameters

- pproc: pointer to a valid process which will be accessed for memory reading.
- src: the address which will be read `size` bytes from.
- dst: a buffer that will receive `size` bytes from `src` (make sure it is at least `size` bytes long!)
- size: the amount of bytes to read

# Return Value

On success, it returns the amount of bytes read, which should be equal to `size`. On failure, it returns `0`.

