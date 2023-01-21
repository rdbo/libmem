# LM_CodeLength

```c
LM_API lm_size_t
LM_CodeLength(lm_address_t code,
          lm_size_t    minlength);
```

# Description

Gets the minimum instruction aligned length for `minlength` bytes from `code` in the calling process.

# Parameters

- code: virtual address of the code to get the minimum aligned length from.
- minlength: the minimum length to align to an instruction length.

# Return Value

On success, it returns the minimum instruction aligned length for `minlength` bytes from `code`. On failure, it returns `0`.

