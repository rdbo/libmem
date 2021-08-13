from distutils.core import setup, Extension
from sysconfig import get_paths
import os

libmem_dir = f"{os.pardir}{os.sep}libmem"

libmem = Extension(name = "libmem",
		   include_dirs = [ libmem_dir ],
		   sources = [ "libmem-py.c", f"{libmem_dir}{os.sep}libmem.c" ])

setup(name = "libmem",
      version = "4.0",
      description = "Process and Memory Hacking Library",
      author = "rdbo",
      ext_modules = [libmem])
