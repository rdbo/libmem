# LM_WriteMemory

```c
LM_API lm_size_t
LM_WriteMemory(lm_address_t dst,
           lm_bytearr_t src,
           lm_size_t    size);
```

# Description

Writes `size` bytes of memory in the calling process into the virtual address (`dst`) from `src`.

# Parameters

- dst: virtual address that will receive `size` bytes from `src`.
- src: buffer from which will be written `size` bytes into `dst` (make sure it is at least `size` bytes long!).
- size: the amount of bytes to read

# Return Value

On success, it returns the amount of bytes written, which should be equal to `size`. On failure, it returns `0`.

