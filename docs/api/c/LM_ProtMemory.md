# LM_ProtMemory

```c
LM_API lm_bool_t
LM_ProtMemory(lm_address_t addr,
          lm_size_t    size,
          lm_prot_t    prot,
          lm_prot_t   *oldprot);
```

# Description

Changes the protection flag from `addr` for `size` bytes to the protection `prot` in the calling process. It can save the old protection into `oldprot`.

# Parameters

- addr: the virtual address to change the protection flags.
- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`).
- oldprot: optional parameter to save the old protection flags. Pass `LM_NULLPTR` to ignore.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

