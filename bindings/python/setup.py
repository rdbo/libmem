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

def get_operating_system():
    if sys.platform.find("bsd") != -1:
        return "bsd"
    if sys.platform == "win32":
        return "windows"
    return sys.platform

operating_system = get_operating_system()
extension_extra_args = {
    "extra_compile_args": ["/MT", "/DLM_EXPORT"]
} if operating_system == "windows" else {}

def get_version():
    return "5.1.2"

def readme():
    open("README.md", "r").read()

def search_installed_libmem():
    libmem_libs = ["liblibmem.so", "liblibmem.a", "libmem.lib", "libmem.dll"]
    lib_dirs = []

    var_libdir = sysconfig.get_config_var("LIBDIR")
    if var_libdir:
        lib_dirs.append(var_libdir)

    print(f"Library dirs: {lib_dirs}")

    for dir in lib_dirs:
        for file in os.listdir(dir):
            if file in libmem_libs:
                print(f"Found installed libmem: {dir}{os.sep}{file}")
                if file == "libmem.dll":
                    extension_extra_args = {}
                return True

    print("Unable to find installed libmem")
    return False

def download_and_extract_libmem():
    print("Downloading libmem binary release...")

    # Get the directory where the current script (build.py) is located
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Construct the absolute path for cache_dir relative to the script's directory
    cache_dir = os.path.join(script_dir, "build", "libmem-release")
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

    download_url = (
        f"https://github.com/rdbo/libmem/releases/download/{version}/{libmem_archive}"
    )
    archive_path = os.path.join(cache_dir, libmem_archive)

    if os.path.exists(archive_path):
        print("Archive already downloaded, skipping...")
    else:
        print(f"Fetching libmem archive...")
        urlretrieve(download_url, archive_path)

    extract_dir = os.path.join(cache_dir, libmem_fullname)
    if os.path.exists(extract_dir):
        print("Archive already extracted, skipping...")
    else:
        print("Extracting archive...")
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=cache_dir)

    additional_include_dirs.append(os.path.join(extract_dir, "include"))
    additional_library_dirs.append(os.path.join(extract_dir, "lib", "release"))
    print(f"Include directories: {additional_include_dirs}")
    print(f"Library directories: {additional_library_dirs}")

def platform_libs():
    libs = ["libmem"]
    operating_system = get_operating_system()
    os_libs = {
        "windows": ["user32", "psapi", "shell32", "ntdll"],
        "linux": ["dl", "stdc++"],
        "bsd": ["dl", "kvm", "procstat", "elf", "stdc++"],
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
    name="_libmem",
    sources=get_sources(os.path.join("src", "libmem", "_libmem")),
    libraries=platform_libs(),
    include_dirs=additional_include_dirs,
    library_dirs=additional_library_dirs,
    **(extension_extra_args),
)

setup(
    name="libmem",
    version=get_version(),
    description="Advanced Game Hacking Library (Windows/Linux/FreeBSD)",
    long_description=readme(),
    long_description_content_type="text/markdown",
    author="rdbo",
    url="https://github.com/rdbo/libmem",
    project_urls={
        "Documentation": "https://github.com/rdbo/libmem/blob/master/docs/DOCS.md",
        "Bug Tracker": "https://github.com/rdbo/libmem/issues",
        "Discord Server": "https://discord.com/invite/Qw8jsPD99X",
    },
    keywords="gamehacking memory process hooking detouring hacking winapi linux freebsd",
    license_files=("LICENSE"),
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.6",
    ext_package="libmem",
    ext_modules=[libmem_raw_py],
)
