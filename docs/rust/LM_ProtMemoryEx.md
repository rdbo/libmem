# LM_ProtMemoryEx

```rust
pub fn LM_ProtMemoryEx(pproc : &lm_process_t, addr : lm_address_t, size : lm_size_t, prot : lm_prot_t) -> Option<lm_prot_t>
```

# Description

Changes the protection flag from `addr` for `size` bytes to the protection `prot` in a remote process. Returns the old protection flags.

# Parameters

- pproc: immutable reference to a valid process which will have its protection flags changed.
- addr: the virtual address to change the protection flags.
- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`)

# Return Value

On success, it returns `Some(protection)`, where `protection` is a valid `lm_prot_t` containing the old protection flags before changing. On failure, it returns `None`.

