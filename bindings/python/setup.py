from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext
import sys
import pathlib
import os
import sysconfig
import platform
from urllib.request import urlretrieve
import tarfile

additional_include_dirs = []
additional_library_dirs = []

def get_version():
    return "5.0.0"

def get_operating_system():
    if sys.platform.find("bsd") != -1:
        return "bsd"

    if sys.platform == "win32":
        return "windows"

    return sys.platform

def readme():
    f = open("README.md", "r")
    content = f.read()
    f.close()
    return content

def search_installed_libmem():
    libmem_libs = ["liblibmem.so", "liblibmem.a", "libmem.lib", "libmem.dll"]
    lib_dirs = []
    
    var_libdir = sysconfig.get_config_var("LIBDIR")
    if var_libdir != None:
        lib_dirs.append(var_libdir)

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
    cache_dir = "build/libmem-release"
    pathlib.Path(cache_dir).mkdir(parents=True, exist_ok=True)

    version = get_version()
    machine = platform.machine() if platform.machine() != "AMD64" else "x86_64"
    operating_system = get_operating_system()
    build_type = ""

    if operating_system == "windows":
        build_type = "msvc-static-mt"
    elif operating_system == "linux":
        build_type = "musl-static"

    libmem_fullname = f"libmem-{version}-{machine}-{operating_system}-{build_type}"
    libmem_archive = f"{libmem_fullname}.tar.gz"
    print(f"Download archive name: {libmem_archive}")

    download_url=f"https://github.com/rdbo/libmem/releases/download/{version}/{libmem_archive}"
    archive_path=f"{cache_dir}{os.sep}{libmem_archive}"

    if os.path.exists(archive_path):
        print("Archive already downloaded, skipping...")
    else:
        print(f"Fetching libmem archive...")
        urlretrieve(download_url, archive_path)

    extract_dir = f"{cache_dir}{os.sep}{libmem_fullname}"
    if os.path.exists(extract_dir):
        print("Archive already extracted, skipping...")
    else:
        print("Extracting archive...")
        tar = tarfile.open(archive_path, "r:gz")
        tar.extractall(path=cache_dir)

    include_dir = f"{extract_dir}/include"
    lib_dir = f"{extract_dir}/lib"
    if operating_system == "windows":
        lib_dir = f"{lib_dir}/release"
    additional_include_dirs.append(include_dir)
    additional_library_dirs.append(lib_dir)

def platform_libs():
    libs = ["libmem"]
    operating_system = get_operating_system()
    os_libs = {
        "windows": ["user32", "psapi", "shell32", "ntdll"],
        "linux": ["dl", "stdc++"],
        "bsd": ["dl", "kvm", "procstat", "elf", "stdc++"]
    }

    if operating_system in os_libs:
        libs.extend(os_libs[operating_system])

    if not search_installed_libmem() and "clean" not in sys.argv:
        download_and_extract_libmem()
    
    return libs

def get_sources(src_dir):
    sources = []
    for file in os.listdir(src_dir):
        if file.endswith(".c"):
            sources.append(os.path.join(src_dir, file))
    print(f"libmem-py sources: {sources}")
    return sources

libmem_raw_py = Extension(
    name = "_libmem",
    sources = get_sources(f"src{os.sep}libmem{os.sep}_libmem"),
    libraries = platform_libs(),
    include_dirs = additional_include_dirs,
    library_dirs = additional_library_dirs
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
    ext_package = "libmem",
    ext_modules = [libmem_raw_py],
)
