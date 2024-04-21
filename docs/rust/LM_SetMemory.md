# LM_SetMemory

```rust
pub unsafe fn LM_SetMemory(dst : lm_address_t, byte : lm_byte_t, size : lm_size_t) -> Option<()>
```

# Description

Sets `size` bytes of `dst` as `byte` in the calling process.

# Parameters

- dst: virtual address that will be set to `byte` for `size` bytes.
- byte: the byte to set `size` bytes of `dst` as.
- size: the amount of bytes to set

# Return Value

On success, it returns `Some(())`. On failure, it returns `None`.

