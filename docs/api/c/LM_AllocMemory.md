# LM_AllocMemory

```c
LM_API lm_address_t
LM_AllocMemory(lm_size_t size,
           lm_prot_t prot);
```

# Description

Allocates `size` bytes of memory with protection flags `prot` in the calling process.

# Parameters

- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`).

# Return Value

On success, it returns a valid `lm_address_t`. On failure, it returns `LM_ADDRESS_BAD`.

