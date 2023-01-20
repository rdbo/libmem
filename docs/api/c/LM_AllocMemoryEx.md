# LM_AllocMemoryEx

```c
LM_API lm_address_t
LM_AllocMemoryEx(lm_process_t *pproc,
         lm_size_t     size,
         lm_prot_t     prot);
```

# Description

Allocates `size` bytes of memory with protection flags `prot` in a remote process.

# Parameters

- pproc: pointer to a valid process which will have memory be allocated.
- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`).

# Return Value

On success, it returns a valid `lm_address_t`. On failure, it returns `LM_ADDRESS_BAD`.

