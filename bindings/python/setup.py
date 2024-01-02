from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext
import sys
import pathlib
import os
import sysconfig
import platform

def get_version():
	return "5.0.0-pre0"

def get_operating_system():
	if sys.platform.find("bsd") != -1:
		return "bsd"

	if sys.platform == "win32":
		return "windows"

	return sys.platform

def get_target():
	machine = platform.machine()
	operating_system = get_operating_system()
	target = f"{machine}-{operating_system}"
	return target

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

def download_and_extract_libmem():
	print("Downloading libmem binary release...")
	cache_dir = "build"
	os.mkdir(cache_dir)

	version = get_version()
	target = get_target()
	libmem_archive = f"libmem-{version}-{target}"
	print(f"Download archive name: {libmem_archive}")

def platform_libs():
	libs = ["libmem"]
	operating_system = get_operating_system()
	os_libs = {
		"windows": ["user32", "psapi"],
		"linux": ["dl"],
		"bsd": ["dl", "kvm", "procstat", "elf"]
	}

	if operating_system in os_libs:
		libs.extend(os_libs[operating_system])

	if not search_installed_libmem():
		download_and_extract_libmem()
	
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
