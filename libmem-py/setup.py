from setuptools import setup, Extension, find_packages
from sys import platform
import os

src_dir = f"src{os.sep}libmem-py"
libs = []
readme = ""

with open("README.md", "r") as f:
	readme = f.read()
	f.close()

if platform == "win32":
	libs.append("user32")
	libs.append("psapi")
elif platform.startswith("linux"):
	libs.append("dl")
elif platform.find("bsd") != -1:
	libs.append("dl")
	libs.append("kvm")
	libs.append("procstat")
	libs.append("elf")

libmem = Extension(name = "libmem",
		   include_dirs = [ src_dir ],
		   sources = [ f"{src_dir}{os.sep}libmem-py.c", f"{src_dir}{os.sep}libmem.c" ],
		   libraries = libs)

setup(name = "libmem",
      version = "0.1.1",
      description = "Process and Memory Hacking Library",
      long_description = readme,
      long_description_content_type = "text/markdown",
      author = "rdbo",
      url = "https://github.com/rdbo/libmem",
      project_urls = { "Bug Tracker" : "https://github.com/rdbo/libmem/issues" },
      package_dir = { "" : "src" },
      packages = find_packages(where="src"),
      python_requires = ">=3.6",
      ext_modules = [libmem])
