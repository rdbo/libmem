-- Set project name and version
set_project("libmem")
set_version("5.0.2")
set_languages("c17", "c++20")


if is_plat("windows") then
    set_toolset("make", "nmake") -- Use NMAKE as the make tool
end

-- Set options
option("build_tests", {description = "Build tests", default = false, showmenu = true})
option("deep_tests", {description = "Enable deep testing", default = false, showmenu = true})
option("build_static", {description = "Build static library", default = true, showmenu = true})

set_arch(os.arch())

-- Set Capstone, Keystone, and LLVM directories (adjust as needed)
local external_dependencies_dir = path.join(os.projectdir(), "external")
local capstone_dir = path.join(external_dependencies_dir, "capstone")
local keystone_dir = path.join(external_dependencies_dir, "keystone")
local llvm_dir = path.join(external_dependencies_dir, "llvm")

-- Set external dependencies
add_includedirs(path.join(capstone_dir, "include"))
add_includedirs(path.join(keystone_dir, "include"))
add_includedirs(path.join(llvm_dir, "include"))

-- Define source directories
local libmem_dir = os.projectdir()
local internal_dir = path.join(libmem_dir, "internal")
local common_dir = path.join(libmem_dir, "src", "common")

-- Add source files based on platform
local libmem_src = {}

if is_plat("windows") then
    libmem_src = {
        path.join(libmem_dir, "src/win/*.c"),
        path.join(common_dir, "*.c"),
        path.join(common_dir, "*.cpp"),
        path.join(internal_dir, "winutils/*.c"),
        path.join(internal_dir, "demangler/*.cpp")
    }
elseif is_plat("linux") then
    if is_arch("x86_64") then
        libmem_src = {
            path.join(common_dir, "arch/x86.c"),
            path.join(libmem_dir, "src/linux/ptrace/x64/*.c"),
            path.join(libmem_dir, "src/linux/*.c"),
            path.join(common_dir, "*.c"),
            path.join(common_dir, "*.cpp"),
            path.join(internal_dir, "posixutils/*.c"),
            path.join(internal_dir, "elfutils/*.c"),
            path.join(internal_dir, "demangler/*.cpp")
        }
    elseif is_arch("i386") then
        libmem_src = {
            path.join(common_dir, "arch/x86.c"),
            path.join(libmem_dir, "src/linux/ptrace/x86/*.c"),
            path.join(libmem_dir, "src/linux/*.c"),
            path.join(common_dir, "*.c"),
            path.join(common_dir, "*.cpp"),
            path.join(internal_dir, "posixutils/*.c"),
            path.join(internal_dir, "elfutils/*.c"),
            path.join(internal_dir, "demangler/*.cpp")
        }
    end
elseif is_plat("freebsd") then
    if is_arch("x86_64") then
        libmem_src = {
            path.join(common_dir, "arch/x86.c"),
            path.join(libmem_dir, "src/freebsd/ptrace/x64/*.c"),
            path.join(libmem_dir, "src/freebsd/*.c"),
            path.join(common_dir, "*.c"),
            path.join(common_dir, "*.cpp"),
            path.join(internal_dir, "posixutils/*.c"),
            path.join(internal_dir, "elfutils/*.c"),
            path.join(internal_dir, "demangler/*.cpp")
        }
    elseif is_arch("i386") then
        libmem_src = {
            path.join(common_dir, "arch/x86.c"),
            path.join(libmem_dir, "src/freebsd/ptrace/x86/*.c"),
            path.join(libmem_dir, "src/freebsd/*.c"),
            path.join(common_dir, "*.c"),
            path.join(common_dir, "*.cpp"),
            path.join(internal_dir, "posixutils/*.c"),
            path.join(internal_dir, "elfutils/*.c"),
            path.join(internal_dir, "demangler/*.cpp")
        }
    end
end

-- Add target for libmem
target("libmem")
    if has_config("build_static") then
        set_kind("static")
    else
        set_kind("shared")
    end

    add_files(libmem_src)
    add_includedirs(path.join(libmem_dir, "include"))
    add_includedirs(path.join(libmem_dir, "src"))
    add_includedirs(internal_dir)
    add_includedirs(common_dir)

    -- Link against external libraries
    add_links("capstone", "keystone", "llvm")

    -- Platform-specific dependencies
    if is_plat("windows") then
        add_syslinks("user32", "psapi", "ntdll", "shell32")
    elseif is_plat("linux") then
        add_syslinks("dl", "stdc++", "m")
    elseif is_plat("freebsd") then
        add_syslinks("dl", "kvm", "procstat", "elf", "stdc++", "m")
    end

    -- Define for export symbol
    add_defines("LM_EXPORT")

-- Optionally build tests
if has_config("build_tests") then
    target("libmem_tests")
        set_kind("binary")
        add_files(path.join(libmem_dir, "tests/*.cpp"))
        add_deps("libmem")
end
