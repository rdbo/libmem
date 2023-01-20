# LM_SetMemoryEx

```rust
pub fn LM_SetMemoryEx(pproc : &lm_process_t, dst : lm_address_t, byte : lm_byte_t, size : lm_size_t) -> Option<()>
```

# Description

Sets `size` bytes of `dst` as `byte` in a remote process.

# Parameters

- pproc: immutable reference to a valid process which will be accessed for writing memory.
- dst: virtual address that will be set to `byte` for `size` bytes.
- byte: the byte to set `size` bytes of `dst` as.
- size: the amount of bytes to set

# Return Value

On success, it returns `Some(())`. On failure, it returns `None`.

