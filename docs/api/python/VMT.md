# VMT

```python
class lm_vmt_t:
    def __init__(self, vtable : int)

    def hook(self, index : int, dst : int);

    def unhook(self, index : int);

    def get_original(self, index : int) -> int;

    def reset(self);
}
```

# Description

APIs to interact with Virtual Method Tables (VMTs) from OOP objects.

- `new`: Creates a new VMT manager from the VMT at `vtable`.
- `hook`: Hooks the VMT function at index `index`, changing it to `dst`.
- `unhook`: Unhooks the VMT function at index `index`.
- `reset`: Resets all the VMT functions back to their original addresses.

