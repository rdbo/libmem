# LM_EnumModules

```python
def LM_EnumModulesEx(pproc : lm_process_t : pproc : lm_process_t) -> Optional[None]:
```

# Description

Enumerates all the modules in a remote process, returning them on a list.

# Parameters

- pproc: valid process that will be searched for modules

#  Return Value

On success, it returns a `list` of `lm_module_t` containing all valid modules. On failure, it returns `None`.

