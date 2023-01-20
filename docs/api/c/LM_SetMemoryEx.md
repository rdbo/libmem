# LM_SetMemoryEx

```c
LM_API lm_size_t
LM_SetMemoryEx(lm_process_t *pproc,
           lm_address_t  dst,
           lm_byte_t     byte,
           lm_size_t     size);
```

# Description

Sets `size` bytes of `dst` as `byte` in a remote process.

# Parameters

- pproc: pointer to a valid process that will be accessed for memory writing.
- dst: virtual address that will be set to `byte` for `size` bytes.
- byte: the byte to set `size` bytes of `dst` as.
- size: the amount of bytes to set

# Return Value

On success, it returns the amount of bytes written, which should be equal to `size`. On failure, it returns `0`.

