# LM_WriteMemory

```rust
pub fn LM_WriteMemory<T>(dst : lm_address_t, value : &T) -> Option<()>
```

# Description

Writes a variable of generic type `T` in the calling process into a virtual address (`dst`).

# Parameters

- dst: the address which will be written a variable of type `T` into.

# Return Value

On success, it returns `Some(())`. On failure, it returns `None`.

