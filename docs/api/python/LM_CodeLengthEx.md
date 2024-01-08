# LM_CodeLengthEx

```python
def LM_CodeLengthEx(pproc : lm_process_t : pproc : lm_process_t, code : int : code : int, minlength : int : minlength : int) -> Optional[None]:
```

# Description

Gets the minimum instruction aligned length for `minlength` bytes from `code` in a remote process.

# Parameters

- pproc: valid process to get the aligned length from.
- code: virtual address of the code to get the minimum aligned length from.
- minlength: the minimum length to align to an instruction length.

# Return Value

On success, it returns an `int` containing the minimum instruction aligned length for `minlength` bytes from `code`. On failure, it returns `None`.

