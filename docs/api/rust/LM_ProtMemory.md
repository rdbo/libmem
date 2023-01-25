# LM_ProtMemory

```rust
pub unsafe fn LM_ProtMemory(addr : lm_address_t, size : lm_size_t, prot : lm_prot_t) -> Option<lm_prot_t>
```

# Description

Changes the protection flag from `addr` for `size` bytes to the protection `prot` in the calling process. Returns the old protection flags.

# Parameters

- addr: the virtual address to change the protection flags.
- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`).

# Return Value

On success, it returns `Some(protection)`, where `protection` is a valid `lm_prot_t` containing the old protection flags before changing. On failure, it returns `None`.

