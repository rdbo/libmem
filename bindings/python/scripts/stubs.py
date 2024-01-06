# TODO - New stub generation method:
#   - Make the documentation declaration be exactly like how it would be on `.pyi`
#   - Get the lines between the two ``` for each API in the documentation and place them directly in the `.pyi`

import os
import re

text = """from typing import *


lm_address_t = TypeVar('lm_address_t', bound=int)
lm_size_t = TypeVar('lm_size_t', bound=int)
lm_pid_t = TypeVar('lm_pid_t', bound=int)
lm_tid_t = TypeVar('lm_tid_t', bound=int)
lm_prot_t = TypeVar('lm_prot_t', bound=int)
lm_inst_t = TypeVar('lm_inst_t', bound=int)


LM_PATH_MAX = 260
LM_CHARSET_UC = 1
LM_PROT_NONE = 0
LM_PROT_X = (1 << 0)
LM_PROT_R = (1 << 1)
LM_PROT_W = (1 << 2)
LM_PROT_XR = LM_PROT_X | LM_PROT_R
LM_PROT_XW = LM_PROT_X | LM_PROT_W
LM_PROT_RW = LM_PROT_R | LM_PROT_W
LM_PROT_XRW = LM_PROT_X | LM_PROT_R | LM_PROT_W

class lm_module_t:
    base: lm_address_t
    end: lm_address_t
    size: lm_size_t
    path: str
    name: str

class lm_process_t:
    pid: lm_pid_t
    ppid: lm_pid_t
    bits: lm_size_t
    start_time: lm_size_t
    path: str
    name: str
    
class lm_page_t:
    base: lm_address_t
    end: lm_address_t
    size: lm_size_t
    prot: lm_prot_t

class lm_thread_t:
    tid: lm_tid_t
    
class lm_symbol_t:
    addr: lm_address_t
    name: str
    
"""

doc_path = "../../../docs/api/python"
files = os.listdir(doc_path)
files = [f for f in files if f.endswith(".md")]


def extract_return_types(file_name):
    file_path = os.path.join(doc_path, file_name)
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    for i, line in enumerate(lines):
        if line.strip() == "# Return Value":
            type_line = lines[i + 2].strip()
            all_types = re.findall(r'`([^`]+)`', type_line)
            extracted_types = []
            for type_str in all_types:
                if ' of ' in type_str:
                    container, inner_type = type_str.split(' of ')
                    extracted_types.append(container.strip())
                    extracted_types.append(inner_type.strip())
                else:
                    extracted_types.append(type_str.strip())
            return ', '.join(extracted_types)

    return 'Any'


def get_function_def(files):
    function_defs = []
    for f in files:
        data = open(os.path.join(doc_path, f)).readlines()
        for i, line in enumerate(data):
            if i == 3 and line.startswith("def"):
                function_defs.append((f, line.strip()))
    return function_defs


def write_stub():
    with open("libmem.pyi", "w") as f:
        f.write(text)
        for file_name, defi in get_function_def(files):
            return_type = extract_return_types(file_name).split(",")[0]
            if return_type == "Any" and "Module" in defi:
                return_type = "List[lm_module_t]"
            if return_type == "Any" and "Process" in defi:
                return_type = "List[lm_process_t]"
            if return_type == "Any" and "Page" in defi:
                return_type = "List[lm_page_t]"
            if return_type == "Any" and "Thread" in defi:
                return_type = "List[lm_thread_t]"
            if return_type == "Any" and "Symbol" in defi:
                return_type = "List[lm_symbol_t]"
            if return_type == "(trampoline_address":
                return_type = "int"
            if return_type == "true" or return_type == "false":
                return_type = "bool"
            if return_type == "":
                continue
            if "from :" in defi:
                f.write(f"{defi.replace('from :', '_from:')} -> {return_type}: ...\n")
                continue

            f.write(f"{defi} -> {return_type}: ...\n")


if __name__ == '__main__':
    write_stub()
