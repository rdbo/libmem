# LM_WriteMemoryEx

```rust
pub fn LM_WriteMemoryEx<T>(pproc : &lm_process_t, dst : lm_address_t, value : &T) -> Option<()>
```

# Description

Writes a variable of generic type `T` in a remote process into a virtual address (`dst`).

# Parameters

- pproc: immutable reference to a valid process which will be accessed for writing memory.
- dst: the address which will be written a variable of type `T` into.

# Return Value

On success, it returns `Some(())`. On failure, it returns `None`.

