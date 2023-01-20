# LM_FindModule

```c
LM_API lm_bool_t
LM_FindModule(lm_string_t  name,
          lm_module_t *modbuf);
```

# Description

Searches for a module in the calling process based on it's name or path.

# Parameters

- name: string containing the name of the module, such as `"gamemodule.dll"` or `"gamemodule.so"`. It may also be a relative/absolute path, like `"bin/lib/gamemodule.dll"`, or `"/usr/lib/libc.so"`.
- modbuf: pointer to an `lm_module_t` variable that will receive the module information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

