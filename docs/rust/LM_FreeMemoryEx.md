# LM_FreeMemoryEx

```rust
pub fn LM_FreeMemoryEx(pproc : &lm_process_t, alloc : lm_address_t, size : lm_size_t) -> Option<()>
```

# Description

Frees `size` bytes of allocated memory in a remote process.

# Parameters

- pproc: immutable reference to a valid process which will have memory be deallocated.
- alloc: virtual address of the allocated memory.
- size: the size of the region to deallocate.

# Return Value

On success, it returns `Some(())`. On failure, it returns `None`.

