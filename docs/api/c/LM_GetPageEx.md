# LM_GetPageEx

```c
LM_API lm_bool_t
LM_GetPageEx(lm_process_t *pproc,
         lm_address_t  addr,
         lm_page_t    *pagebuf);
```

# Description

Gets a page in a remote process from a virtual address.

# Parameters

- pproc: pointer to a valid process which the page will the taken from.
- addr: the virtual address that the page will be looked up from.
- pagebuf: pointer to an `lm_page_t` variable that will receive the information about the page.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

