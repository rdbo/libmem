# LM_GetPage

```python
def LM_GetPage(addr : int)
```

# Description

Gets a page in the calling process from a virtual address.

# Parameters

- addr: the virtual address that the page will be looked up from.

# Return Value

On success, it returns a valid `lm_page_t`. On failure, it returns `None`.

