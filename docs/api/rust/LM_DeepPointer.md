# LM_DeepPointer

```rust
pub unsafe fn LM_DeepPointer<T>(base: lm_address_t, offsets: Vec<lm_address_t>) -> Option<*mut T>
```

# Description

Dereferences a deep pointer in the current process, generally result of a pointer scan or pointer map.

# Parameters

- base: the base address of the deep pointer
- offsets: vector containing the offsets that will be used to dereference and increment the base pointer

# Return Value

On success, it returns `Some(address)` where `address` is a valid `*mut T`. On failure, it returns `None`.

