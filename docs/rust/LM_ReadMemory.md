# LM_ReadMemory

```rust
pub unsafe fn LM_ReadMemory<T>(src : lm_address_t) -> Option<T>
```

# Description

Reads a variable of generic type `T` in the calling process from a virtual address (`src`).

# Parameters

- src: the address which will be read a variable of type `T` from.

# Return Value

On success, it returns `Some(var)`, where `var` is a variable of type `T` containing the bytes from `src`. On failure, it returns `None`.

