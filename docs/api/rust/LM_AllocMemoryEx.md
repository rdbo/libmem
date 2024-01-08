# LM_AllocMemoryEx

```rust
pub fn LM_AllocMemoryEx(pproc : &lm_process_t, size : lm_size_t, prot : lm_prot_t) -> Option<lm_address_t>
```

# Description

Allocates `size` bytes of memory with protection flags `prot` in a remote process.

# Parameters

- pproc: immutable reference to a process which will have memory be allocated.
- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`).

# Return Value

On success, it returns `Some(address)`, where `address` is a valid `lm_address_t`. On failure, it returns `None`.

