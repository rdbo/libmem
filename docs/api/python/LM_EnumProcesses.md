# LM_EnumProcesses

```python
def LM_EnumProcesses() -> Optional[List[lm_process_t]]
```

# Description

Enumerates all the current existing processes, returning them on a list.

#  Return Value

On success, it returns a `list` of `lm_process_t` containing all valid processes. On failure, it returns `None`.

