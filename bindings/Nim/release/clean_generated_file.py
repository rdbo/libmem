import re

gen_file = "nimlibmem.nim"


def replace_comments():
    regex = r"##.*"
    subst = ""
    with open(gen_file, "r") as file:
        data = file.read()
    data = re.sub(regex, subst, data, 0)
    with open(gen_file, "w") as file:
        file.write(data)


def replace_proc_pragmas():
    regex = r"\{.cdecl,.*?\}|\{.\n....cdecl,.*?\}"

    with open(gen_file, "r") as file:
        data = file.read()
    match = re.finditer(regex, data, re.DOTALL | re.MULTILINE)
    outfile = open("nimlibmem.nim", "w")
    for m in match:
        newstr = m.group().strip().replace("\n", " ").replace("     ", "").replace(" i", "i").replace("{.cdecl,importc", "{.dynlib: libname, cdecl, importc")
        data = data.replace(m.group(), newstr)
    outfile.write(data)
    outfile.close()




def insert_libname():
    with open(gen_file, "r+") as file:
        file_data = file.read()
    with open(gen_file, "w") as file:
        file.write('const\n  libname = "src/libmem.dll"\n\n' + file_data)


replace_comments()
replace_proc_pragmas()
insert_libname()
