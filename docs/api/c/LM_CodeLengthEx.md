# LM_CodeLengthEx

```c
LM_API lm_size_t
LM_CodeLengthEx(lm_process_t *pproc,
        lm_address_t  code,
        lm_size_t     minlength);
```

# Description

Gets the minimum instruction aligned length for `minlength` bytes from `code` in a remote process.

# Parameters

- pproc: pointer to a valid process to get the aligned length from.
- code: virtual address of the code to get the minimum aligned length from.
- minlength: the minimum length to align to an instruction length.

# Return Value

On success, it returns the minimum instruction aligned length for `minlength` bytes from `code`. On failure, it returns `0`.

