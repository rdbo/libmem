# LM_DeepPointerEx

```rust
pub fn LM_DeepPointerEx(
    pproc: &lm_process_t,
    base: lm_address_t,
    offsets: Vec<lm_address_t>,
) -> Option<lm_address_t> {
```

# Description

Dereferences a deep pointer in a remote process, generally result of a pointer scan or pointer map.

# Parameters

- pproc: immutable reference to a valid process
- base: the base address of the deep pointer
- offsets: vector containing the offsets that will be used to dereference and increment the base pointer

# Return Value

On success, it returns `Some(address)` where `address` is a valid `lm_address_t`. On failure, it returns `None`.

