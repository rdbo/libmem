# LM_EnumSymbols

```c
LM_API lm_bool_t
LM_EnumSymbols(lm_module_t *pmod,
           lm_bool_t  (*callback)(lm_symbol_t *psymbol,
                      lm_void_t   *arg),
           lm_void_t   *arg);
```

# Description

Enumerates all the symbols in a module, sending them to a callback function.

# Parameters

- pmod: pointer to a valid module which the symbols will be searched from.
- callback: pointer to a function that will be called for every symbol found (received in the parameter `psymbol`). It can return either `LM_TRUE` to continue searching for modules or `LM_FALSE` to stop the search.
- arg: An optional extra argument that will be passed into the callback function (use `LM_NULL` to ignore it).

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

