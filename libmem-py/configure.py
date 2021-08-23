import os
import shutil

root_dir = os.pardir
libmem_dir = f"{root_dir}{os.sep}libmem"
project_dir = os.curdir
project_src_dir = f"{project_dir}{os.sep}src/libmem-py"

print("[+] Configuring files...")

project_files = {
	# (src_dir : dst_dir) [ files ]
	(root_dir, project_dir) : [
		"README.md",
		"LOGO.png",
		"LICENSE"
	],

	(libmem_dir, project_src_dir) : [
		"libmem.h",
		"libmem.c"
	]
}

for i in project_files:
	src_dir = i[0]
	dst_dir = i[1]
	files = project_files[i]

	print(f"[*] Source Directory: {src_dir}")
	print(f"[*] Destination Directory: {dst_dir}")
	print(f"[*] Files: {files}")

	for f in files:
		shutil.copy(f"{src_dir}{os.sep}{f}", dst_dir)

	print("====================")

print("[-] Configuration complete")
