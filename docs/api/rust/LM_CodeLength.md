# LM_CodeLength

```rust
pub unsafe fn LM_CodeLength(code : lm_address_t, minlength : lm_size_t) -> Option<lm_size_t>
```

# Description

Gets the minimum instruction aligned length for `minlength` bytes from `code` in the calling process.

# Parameters

- code: virtual address of the code to get the minimum aligned length from.
- minlength: the minimum length to align to an instruction length.

# Return Value

On success, it returns `Some(length)`, where `length` is an `lm_size_t` containing the minimum instruction aligned length for `minlength` bytes from `code`. On failure, it returns `None`.

