from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext
from sys import platform
import pathlib
import os

libmem_lib = ""
if platform == "win32":
    libmem_lib = "libmem.lib"
else:
    libmem_lib = "libmem.a"

class CMakeExtension(Extension):
	def __init__(self, name, cmake_args=[]):
		self.cmake_args = cmake_args
		super().__init__(name, sources=[], language="cmake")

class CMakeBuildExt(build_ext):
	def run(self):
		for i in range(len(self.extensions)):
			if self.extensions[i].language == "cmake":
				self.build_cmake(self.extensions[i])
			else:
				self.extensions[i].library_dirs.append(self.build_temp)
				self.extensions[i].extra_objects.append(f"{self.build_temp}{os.sep}{libmem_lib}")
				self.extensions[i].extra_objects.append(f"{self.build_temp}{os.sep}capstone-engine-prefix{os.sep}src{os.sep}capstone-engine-build{os.sep}libcapstone.a")
				self.extensions[i].extra_objects.append(f"{self.build_temp}{os.sep}keystone-engine-prefix{os.sep}src{os.sep}keystone-engine-build{os.sep}llvm{os.sep}lib{os.sep}libkeystone.a")
		super().run()

	def build_cmake(self, ext):
		cwd = pathlib.Path().absolute()
		cmake_dir = f"{str(cwd)}{os.sep}{ext.name}"
		build_temp = pathlib.Path(self.build_temp)
		build_temp.mkdir(parents=True, exist_ok=True)
		extdir = pathlib.Path(self.get_ext_fullpath(ext.name))
		extdir.mkdir(parents=True, exist_ok=True)

		config = 'Debug' if self.debug else 'Release'
		cmake_args = [
			'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=' + str(extdir.parent.absolute()),
			'-DCMAKE_BUILD_TYPE=' + config
		] + ext.cmake_args

		build_args = [
		    '--', '-j4'
		]

		os.chdir(str(build_temp))
		self.spawn(['cmake', str(cmake_dir)] + cmake_args)
		if not self.dry_run:
			self.spawn(['cmake', '--build', '.'] + build_args)
		os.chdir(str(cwd))

src_dir = f"src{os.sep}libmem-py"
libmem_root_dir = f"{src_dir}{os.sep}libmem"
libs = ["stdc++"]
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

libmem = CMakeExtension(f"{libmem_root_dir}", [])

libmem_py = Extension(
	name = "libmem",
	include_dirs = [ f"{libmem_root_dir}{os.sep}libmem{os.sep}include" ],
	sources = [f"{src_dir}{os.sep}libmem-py.c"],
	libraries = libs
)

setup(
	name = "libmem",
	version = "0.1.4",
	description = "Process and Memory Hacking Library",
	long_description = readme,
	long_description_content_type = "text/markdown",
	author = "rdbo",
	url = "https://github.com/rdbo/libmem",
	project_urls = {
		"Bug Tracker" : "https://github.com/rdbo/libmem/issues",
		"Discord Server" : "https://discord.com/invite/Qw8jsPD99X"
	},
	package_dir = { "" : "src" },
	packages = find_packages(where="src"),
	python_requires = ">=3.6",
	ext_modules = [libmem, libmem_py],
	cmdclass = {
		"build_ext" : CMakeBuildExt
	}
)
