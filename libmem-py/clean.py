import os
import shutil
import json

print("[+] Cleaning...")

with open("tree.json", "r") as f:
	json_str = f.read()
	json_data = json.loads(json_str)
	f.close()

for (path, dirs, files) in os.walk(os.curdir):
	if path not in json_data["dirs"]:
		shutil.rmtree(path)
	else:
		for f in files:
			f = f"{path}{os.sep}{f}"
			if f not in json_data["files"]:
				os.remove(f)

print("[-] Finished cleaning")
