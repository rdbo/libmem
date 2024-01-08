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
from typing import Optional

def LM_FindModuleEx(pproc: lm_process_t, name: str) -> Optional[lm_module_t]:
    return _libmem.LM_FindModuleEx(pproc, name)