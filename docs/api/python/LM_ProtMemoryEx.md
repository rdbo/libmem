# LM_ProtMemory

```python
def LM_ProtMemoryEx(pproc : lm_process_t, addr : int, size : int, prot : lm_prot_t)
```

# Description

Changes the protection flag from `addr` for `size` bytes to the protection `prot` in a remote process. Returns the old protection flags.

# Parameters

- pproc: valid process that will have its protection flags changed.
- addr: the virtual address to change the protection flags.
- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`).

# Return Value

On success, it returns a valid `lm_prot_t` containing the old protection flags before changing. On failure, it returns `None`.

