from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext
from sys import platform
import pathlib
import os
import sysconfig

def get_version():
	return "5.0.0-pre0"

def readme():
	f = open("README.md", "r")
	content = f.read()
	f.close()
	return content

def search_installed_libmem():
	libmem_libs = ["liblibmem.so", "liblibmem.a", "libmem.lib", "libmem.dll"]
	lib_dirs = [sysconfig.get_config_var("LIBDIR")]

	print(f"Library dirs: {lib_dirs}")

	for dir in lib_dirs:
		for file in os.listdir(dir):
			if file in libmem_libs:
				print(f"Found installed libmem: {dir}{os.sep}{file}")
				return True

	print("Unable to find installed libmem")

	return False

def platform_libs():
	libs = []
	if platform == "win32":
		libs.extend(["user32", "psapi"])
	elif platform.startswith("linux"):
		libs.append("dl")
	elif platform.find("bsd") != -1:
		libs.extend(["dl", "kvm", "procstat", "elf"])

	if search_installed_libmem():
		libs.append("libmem")
	
	return libs

def get_sources(src_dir):
    sources = []
    for file in os.listdir(src_dir):
        if file.endswith(".c"):
            sources.append(os.path.join(src_dir, file))
    print(f"libmem-py sources: {sources}")
    return sources

libmem_py = Extension(
	name = "libmem",
	sources = get_sources(f"src{os.sep}libmem-py"),
	libraries = platform_libs()
)

setup(
	name = "libmem",
	version = get_version(),
	description = "Advanced Game Hacking Library (Windows/Linux/FreeBSD)",
	long_description = readme(),
	long_description_content_type = "text/markdown",
	author = "rdbo",
	url = "https://github.com/rdbo/libmem",
	project_urls = {
        "Documentation" : "https://github.com/rdbo/libmem/blob/master/docs/DOCS.md",
		"Bug Tracker" : "https://github.com/rdbo/libmem/issues",
		"Discord Server" : "https://discord.com/invite/Qw8jsPD99X"
	},
    keywords="gamehacking memory process hooking detouring hacking winapi linux freebsd",
    license_files = ("LICENSE"),
	package_dir = { "" : "src" },
	packages = find_packages(where="src"),
	python_requires = ">=3.6",
	ext_modules = [libmem_py],
)
