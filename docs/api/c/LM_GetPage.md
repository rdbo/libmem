# LM_GetPage

```c
LM_API lm_bool_t
LM_GetPage(lm_address_t addr,
	   lm_page_t   *pagebuf);
```

# Description

Gets a page in the calling process from a virtual address.

# Parameters

- addr: the virtual address that the page will be looked up from.
- pagebuf: pointer to an `lm_page_t` variable that will receive the information about the page.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

