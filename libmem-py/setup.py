from setuptools import setup, Extension
from sys import platform
import os

libmem_dir = f"{os.pardir}{os.sep}libmem"
libs = []

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
		   include_dirs = [ libmem_dir ],
		   sources = [ "libmem-py.c", f"{libmem_dir}{os.sep}libmem.c" ],
		   libraries = libs)

setup(name = "libmem",
      version = "4.0",
      description = "Process and Memory Hacking Library",
      author = "rdbo",
      ext_modules = [libmem])
