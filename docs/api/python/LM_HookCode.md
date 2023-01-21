# LM_HookCode

```python
def LM_HookCode(from : int, to : int)
```

# Description

Places a hook/detour onto the address `from`, redirecting it to the address `to` in the calling process. It returns a trampoline and the hook size; the trampoline can be used to call the original function.

# Parameters

- from: the address where the hooked will be placed.
- to: the address where the hook will jump to.

# Return Value

On success, it returns `(trampoline_address, hook_size)`, where `trampoline_address` is an address (`int`) where there is a trampoline/gateway that you can use to call the original function; `size` is the amount of bytes occupied by the hook (aligned to the nearest instruction). On failure, it returns `None`.

