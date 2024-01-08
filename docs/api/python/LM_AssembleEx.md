# LM_AssembleEx

```python
def LM_AssembleEx(code : str : code : str, bits : int : bits : int, runtime_addr : int : runtime_addr : int) -> Optional[None]:
```

# Description

Assembles one or more instructions into machine code.

# Parameters

- code: a string of the instructions to be assembled. Example: `"mov eax, ebx ; jmp eax"`.
- bits: the bits of the architecture to be assembled. It can be `32` or `64`.
- runtime_addr: the runtime address to resolve the functions (for example, relative jumps will be resolved using this address).

# Return Value

On success, a `bytearray` containing the assembled instructions. On failure, it returns `None`.

