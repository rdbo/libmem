# LM_CodeLength

```python
def LM_CodeLength(code : int, minlength : int)
```

# Description

Gets the minimum instruction aligned length for `minlength` bytes from `code` in the calling process.

# Parameters

- code: virtual address of the code to get the minimum aligned length from.
- minlength: the minimum length to align to an instruction length.

# Return Value

On success, it returns an `int` containing the minimum instruction aligned length for `minlength` bytes from `code`. On failure, it returns `None`.

