# LM_EnumThreads

```c
LM_API lm_bool_t
LM_EnumThreads(lm_bool_t(*callback)(lm_thread_t *pthr,
                    lm_void_t   *arg),
           lm_void_t *arg);
```

# Description

Enumerates all the threads in the calling processes, sending them to a callback function.

# Parameters

- callback: pointer to a function that will be called for every thread found (received in the parameter `pthr`). It can return either `LM_TRUE` to continue searching for threads or `LM_FALSE` to stop the search.
- arg: An optional extra argument that will be passed into the callback function (use `LM_NULL` to ignore it)

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

