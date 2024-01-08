# LM_EnumModules

```python
def LM_EnumModules() -> Optional[None]:
```

# Description

Enumerates all the modules in the calling process, returning them on a list.

#  Return Value

On success, it returns a `list` of `lm_module_t` containing all valid modules. On failure, it returns `None`.

