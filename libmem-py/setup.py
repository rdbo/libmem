from distutils.core import setup, Extension
from sysconfig import get_paths
import os

python_include_dir = get_paths()["include"]
libmem_dir = os.path.dirname(os.path.realpath(__file__)) + os.sep + os.pardir + os.sep + "libmem"

print(f"[*] Python Include Dir: {python_include_dir}")
print(f"[*] Libmem Dir: {libmem_dir}")

libmem = Extension("libmem",
		   include_dirs = [ python_include_dir, libmem_dir ],
		   sources = [ "libmem-py.c", libmem_dir + os.sep + "libmem.c" ])

setup(name="libmem",
      version="4.0",
      description="Process and Memory Hacking Library",
      author="rdbo",
      ext_modules=[libmem])
