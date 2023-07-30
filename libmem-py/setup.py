from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext
from sys import platform
import pathlib
import os

src_dir = f"src{os.sep}libmem-py"
libs = ["libmem"]
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

def get_sources(src_dir):
    sources = []
    for file in os.listdir(src_dir):
        if file.endswith(".c"):
            sources.append(os.path.join(src_dir, file))
    print(sources)
    return sources

libmem_py = Extension(
	name = "libmem",
	sources = get_sources(src_dir),
	libraries = libs
)

setup(
	name = "libmem",
	version = "4.2.0",
	description = "Advanced Game Hacking Library (Windows/Linux/FreeBSD)",
	long_description = readme,
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
