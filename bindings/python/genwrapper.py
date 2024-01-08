import os
from pathlib import Path

script_dir = os.path.dirname(os.path.realpath(__file__))
docs_dir = Path(script_dir).parent.parent / "docs" / "api" / "python"

print("Documentation directory: " + str(docs_dir))

header = '''
#  ----------------------------------
# |         libmem - by rdbo         |
# |      Memory Hacking Library      |
#  ----------------------------------
#
# Copyright (C) 2024    Rdbo
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License version 3
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import libmem._libmem as _libmem
from libmem._libmem import lm_process_t, lm_thread_t, lm_module_t, lm_symbol_t, lm_prot_t, lm_page_t, lm_inst_t, lm_vmt_t
from typing import Optional, List, Tuple
'''
header = header[1:] # skip first new line

wrapper = open("src/libmem/__init__.py", "w")
wrapper.write(header)

def lines_between(text: str, begin: str, end: str):
    begin_idx = text.find(begin)
    if begin_idx == -1:
        return None

    begin_idx += len(begin)
    if begin_idx >= len(text):
        return None
    
    end_idx = text.find(end, begin_idx)
    if end_idx == -1:
        return None

    return text[begin_idx:end_idx]

def parse_args(decl: str):
    args_start = decl.find("(")
    if args_start == -1:
        return None

    args_start += 1
    if args_start >= len(decl):
        return None
    
    args_end = decl.find(")", args_start)
    if args_end == -1:
        return None

    args_text = decl[args_start:args_end]
    arg_list = []

    if args_end == args_start + 1:
        return arg_list

    # WARN: this loop does not do error checking!
    while True:
        colon = args_text.find(":")
        ident = args_text[:colon]
        arg_list.append(ident)

        next_colon = args_text.find(":", colon + 1)
        if next_colon == -1:
            break
        
        next_str = ", "
        next_idx = args_text.rfind(next_str, 0, next_colon)
        args_text = args_text[next_idx + len(next_str):]

    return arg_list

# TODO: exit on error
for doc in os.listdir(docs_dir):
    if not doc.startswith("LM_"):
        continue

    method = doc[:-3] # Remove file extension
    print(f"Generating {method} wrapper...")
    file = open(docs_dir / doc)

    decl = lines_between(file.read(), '```python\n', '\n```')
    args = parse_args(decl)
    args_exp = ', '.join(args)

    wrapper.write("\n")
    wrapper.write(decl + ":\n")
    wrapper.write(f"    return _libmem.{method}({args_exp})\n")

    file.close()

wrapper.close()
