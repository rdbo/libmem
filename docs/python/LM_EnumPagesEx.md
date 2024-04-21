# LM_EnumPagesEx

```python
def LM_EnumPagesEx(pproc: lm_process_t) -> Optional[List[lm_page_t]]
```

# Description

Enumerates all the pages in a remote process, returning them on a vector.

# Parameters

- pproc: immutable reference to a valid process which the pages will be queried from

# Return Value

On success, it returns a `Some(page_list)`, where `page_list` is a vector containing all valid pages; On failure, it returns `None`.

