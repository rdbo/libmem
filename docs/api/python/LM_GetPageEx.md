# LM_GetPageEx

```python
def LM_GetPageEx(pproc : lm_process_t, addr : int)
```

# Description

Gets a page in a remote process from a virtual address.

# Parameters

- pproc: valid process which the page will be taken from.
- addr: the virtual address that the page will be looked up from.

# Return Value

On success, it returns a valid `lm_page_t`. On failure, it returns `None`.

