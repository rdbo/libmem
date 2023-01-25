# LM_FreeMemory

```rust
pub unsafe fn LM_FreeMemory(alloc : lm_address_t, size : lm_size_t) -> Option<()>
```

# Description

Frees `size` bytes of allocated memory in the calling process.

# Parameters

- alloc: virtual address of the allocated memory.
- size: the size of the region to deallocate.

# Return Value

On success, it returns `Some(())`. On failure, it returns `None`.

