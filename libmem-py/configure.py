import os
import shutil

project_dir = os.curdir
project_src_dir = f"{project_dir}{os.sep}src/libmem-py"

project_files = [
	f"{os.pardir}{os.sep}README.md",
	f"{os.pardir}{os.sep}LOGO.png",
	f"{os.pardir}{os.sep}LICENSE"
]
project_src_files = [
	f"{os.pardir}{os.sep}libmem{os.sep}libmem.h",
	f"{os.pardir}{os.sep}libmem{os.sep}libmem.c"
]

for f in project_files:
	shutil.copy(f, project_dir)

for f in project_src_files:
	shutil.copy(f, project_src_dir)
