# LM_HookCode

```c
LM_API lm_size_t
LM_HookCode(lm_address_t  from,
        lm_address_t  to,
        lm_address_t *ptrampoline);
```

# Description

Places a hook/detour onto the address `from`, redirecting it to the address `to` in the calling process. Optionally, it generates a trampoline in `ptrampoline` to call the original function.

# Parameters

- from: the address where the hooked will be placed.
- to: the address where the hook will jump to.
- ptrampoline: optional pointer to an `lm_address_t` variable that will receive a trampoline/gateway to call the original function.

# Return Value

On success, it returns the amount of bytes occupied by the hook (aligned to the nearest instruction). On failure, it returns `0`.

