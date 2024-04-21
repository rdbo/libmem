import os
from pathlib import Path
import re

root_dir = Path(os.path.dirname(os.path.realpath(__file__))).parent
print(f"[*] Root dir: {root_dir}")

header_file = open((root_dir / "include" / "libmem" / "libmem.h"), "r")
header = header_file.read()
header_file.close()

outdir = root_dir / "docs" / "c" / "api"
outdir.mkdir(parents=True, exist_ok=True)

offset = 0
while True:
    docstart = header.find("/**", offset)
    if docstart == -1:
        break
    docend = header.index("*/", docstart)

    content = header[docstart + 4:docend - 2]
    content = content.replace(" *\n", "\n").replace(" * \n", "\n")
    content = re.sub(r"\s{0,1}[*]\s*", "", content)

    fn_signature_end = header.index(");", docend) + 2
    fn_signature_start = header.rindex("LM_API", 0, fn_signature_end)
    fn_signature = header[fn_signature_start:fn_signature_end]

    fn_name_end = fn_signature.index("(")
    fn_name_start = fn_signature.rindex("LM_", 0, fn_name_end)
    fn_name = fn_signature[fn_name_start:fn_name_end]

    description = content[:content.index("\n\n")]

    params = "The function does not have parameters"
    params_start = content.find("@param")
    if params_start != -1:
        # NOTE: If params_end is not found, it will be the last
        #       character (-1) anyways, which is what we want.
        params_end = content.find("\n\n", params_start)
        params = content[params_start:params_end]
        params = re.sub("@param\s+([a-zA-Z_]+)", " - `\\1`:", params)

    retval = "The function does not return a value"
    retval_start = content.find("@return")
    if retval_start != -1:
        # NOTE: The return value goes until the end of the content
        retval = content[retval_start:]
        retval = retval.replace("@return ", "")

    markdown_doc = f"""# {fn_name}

```c
{fn_signature}
```

# Description
{description}

# Parameters
{params}

# Return Value
{retval}
"""

    print(markdown_doc)
    print("--------------------------------")

    with open(outdir / f"{fn_name}.md", "w") as docfile:
        docfile.write(markdown_doc)

    offset = docend + 2
