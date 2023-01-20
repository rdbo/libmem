# LM_ReadMemoryEx

```rust
pub fn LM_ReadMemoryEx<T>(pproc : &lm_process_t, src : lm_address_t) -> Option<T>
```

# Description

Reads a variable of generic type `T` from a remote process at a virtual address (`src`).

# Parameters

- pproc: immutable reference to a valid process which will be accessed for memory reading.
- src: the address which will be read a variable of type `T` from.

# Return Value

On success, it returns `Some(var)`, where `var` is a variable of type `T` containing the bytes from `src`. On failure, it returns `None`.

