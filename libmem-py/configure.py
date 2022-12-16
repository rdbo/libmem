import os
import shutil
import json

root_dir = os.pardir
libmem_dir = f"{root_dir}{os.sep}libmem"
project_dir = os.curdir
project_src_dir = f"{project_dir}{os.sep}src/libmem-py"
libmem_root_dir = f"{project_src_dir}/libmem"
clean_script = "clean.py"

print(f"[+] Creating '{clean_script}'...")

keep_dirs = []
keep_files = []

for (path, dirs, files) in os.walk(os.curdir):
	keep_dirs.append(path)
	keep_files.extend([f"{path}{os.sep}{f}" for f in files])

json_dict = {
	"dirs" : keep_dirs,
	"files" : keep_files
}

json_data = json.dumps(json_dict)
with open("tree.json", "w") as tree_file:
	tree_file.write(json_data)
	tree_file.close()

print(f"[-] Creation complete")
print("[+] Configuring files...")

project_files = {
	# (src_dir : dst_dir) [ files/subdirs ]
	(root_dir, project_dir) : [
		"README.md",
		"LICENSE"
	],

    (root_dir, libmem_root_dir) : [
        "libmem",
        "capstone",
        "keystone",
        "CMakeLists.txt"
    ]
}

for i in project_files:
	src_dir = i[0]
	dst_dir = i[1]
	files = project_files[i]

	print(f"[*] Source Directory: {src_dir}")
	print(f"[*] Destination Directory: {dst_dir}")
	print(f"[*] Files: {files}")

	if not os.path.isdir(dst_dir):
		os.mkdir(dst_dir)

	for f in files:
		srcpath = f"{src_dir}{os.sep}{f}"
		if os.path.isdir(srcpath):
			shutil.copytree(f"{srcpath}", f"{dst_dir}{os.sep}{f}")
		else:
			shutil.copy(f"{srcpath}", dst_dir)

	print("====================")

print("[-] Configuration complete")
