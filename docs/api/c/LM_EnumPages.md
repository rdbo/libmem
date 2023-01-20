# LM_EnumPages

```c
LM_API lm_bool_t
LM_EnumPages(lm_bool_t(*callback)(lm_page_t *ppage,
                  lm_void_t *arg),
         lm_void_t *arg);
```

# Description

Enumerates all the pages in the calling process, sending them to a callback function.

# Parameters

- callback: pointer to a function that will be called for every page found (received in the parameter `ppage`). It can return either `LM_TRUE` to continue searching for modules or `LM_FALSE` to stop the search.
- arg: An optional extra argument that will be passed into the callback function (use `LM_NULL` to ignore it).

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

