# LM_LoadModule

```c
LM_API lm_bool_t
LM_LoadModule(lm_string_t  path,
          lm_module_t *modbuf);
```

# Description

Loads a module into the calling process from its path.

# Parameters

- path: string containing a relative/absolute path, like `"bin/lib/gamemodule.dll"`, or `"/usr/lib/libc.so"`.
- modbuf: pointer to an `lm_module_t` variable that will receive the loaded module information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

