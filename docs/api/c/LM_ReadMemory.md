# LM_ReadMemory

```c
LM_API lm_size_t
LM_ReadMemory(lm_address_t src,
          lm_byte_t   *dst,
          lm_size_t    size);
```

# Description

Reads `size` bytes of memory in the calling process from a virtual address (`src`) into `dst`.

# Parameters

- src: the address which will be read `size` bytes from.
- dst: a buffer that will receive `size` bytes from `src` (make sure it is at least `size` bytes long!)
- size: the amount of bytes to read

# Return Value

On success, it returns the amount of bytes read, which should be equal to `size`. On failure, it returns `0`.

