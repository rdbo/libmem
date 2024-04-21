# LM_GetArchitecture

```c
LM_API lm_arch_t LM_CALL
LM_GetArchitecture();
```

# Description
The function returns the current architecture.

# Parameters
The function does not have parameters

# Return Value
The function returns the architecture of the system. It can be one of:
- `LM_ARCH_X86` for 32-bit x86.
- `LM_ARCH_AMD64` for 64-bit x86.
- Others (check the enum for `lm_arch_t`)
