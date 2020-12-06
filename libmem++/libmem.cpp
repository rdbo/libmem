/* libmem++ - C++ version of libmem
 * by rdbo
 * ---------------------------------
 * https://github.com/rdbo/libmem
 * ---------------------------------
 */

#include "libmem.hpp"

#if defined(MEM_COMPATIBLE)

//mem::process_t
mem::process_t::process_t()
{

}

mem::process_t::~process_t()
{
#	if defined(MEM_WIN)
	if (this->handle != INVALID_HANDLE_VALUE)
		CloseHandle(this->handle);
#	elif defined(MEM_LINUX)
#	endif
}

mem::bool_t mem::process_t::operator==(mem::process_t& process)
{
	return (bool_t)(
#		if defined(MEM_WIN)
		this->handle == process.handle &&
#		elif defined(MEM_LINUX)
#		endif
		this->name == process.name &&
		this->pid == process.pid
	);
}

mem::bool_t mem::process_t::is_valid()
{
	return (bool_t)(
#		if defined(MEM_WIN)
		this->handle != INVALID_HANDLE_VALUE &&
#		elif defined(MEM_LINUX)
#		endif
		this->name != "" &&
		this->pid  != (pid_t)-1
	);
}

//mem::module_t

mem::module_t::module_t()
{

}

mem::module_t::~module_t()
{
#	if defined(MEM_WIN)
	if (this->handle)
		CloseHandle(this->handle);
#	elif defined(MEM_LINUX)
#	endif
}

mem::bool_t mem::module_t::operator==(module_t& mod)
{
	return (bool_t)(
		this->name   == mod.name   &&
		this->path   == mod.path   &&
		this->base   == mod.base   &&
		this->end    == mod.end    &&
		this->size   == mod.size   &&
		this->handle == mod.handle
	);
}

mem::bool_t mem::module_t::is_valid()
{
	return (bool_t)(
		this->name != "" &&
		this->path != "" &&
		this->base != (voidptr_t)-1 &&
		this->end  != (voidptr_t)-1 &&
		this->size != (uintptr_t)-1 &&
		this->handle != (module_handle_t)-1
	);
}

//mem::page_t

mem::page_t::page_t()
{

}

mem::page_t::~page_t()
{

}

mem::bool_t mem::page_t::is_valid()
{
	return (bool_t)(
		base  != (voidptr_t)-1   &&
		size  != (uintptr_t)-1   &&
		end   != (voidptr_t)-1   &&
		flags != (flags_t)-1     &&
		protection != (prot_t)-1
	);
}

//mem::alloc_t

mem::alloc_t::alloc_t()
{
#	if defined(MEM_WIN)
	this->protection = PAGE_EXECUTE_READWRITE;
	this->type = MEM_COMMIT | MEM_RESERVE;
#	elif defined(MEM_LINUX)
	this->protection = PROT_EXEC | PROT_READ | PROT_WRITE;
	this->type = MAP_ANON | MAP_PRIVATE;
#	endif
}

mem::alloc_t::alloc_t(mem::prot_t prot)
{
#	if defined(MEM_WIN)
	this->protection = prot;
	this->type = MEM_COMMIT | MEM_RESERVE;
#	elif defined(MEM_LINUX)
	this->protection = prot;
	this->type = MAP_ANON | MAP_PRIVATE;
#	endif
}

mem::alloc_t::alloc_t(mem::prot_t prot, mem::alloc_type_t type)
{
	this->protection = prot;
	this->type = type;
}

mem::alloc_t::~alloc_t()
{

}

mem::bool_t mem::alloc_t::is_valid()
{
	return (bool_t)(
		this->protection != (prot_t)-1 &&
		this->type != (alloc_type_t)-1
	);
}

//mem::lib_t

mem::lib_t::lib_t()
{
#	if defined(MEM_WIN)
#	elif defined(MEM_LINUX)
	this->mode = RTLD_LAZY;
#	endif
}

mem::lib_t::lib_t(string_t path)
{
	this->path = path;
#	if defined(MEM_WIN)
#	elif defined(MEM_LINUX)
	this->mode = RTLD_LAZY;
#	endif
}

mem::lib_t::lib_t(string_t path, int_t mode)
{
	this->path = path;
#	if defined(MEM_WIN)
#	elif defined(MEM_LINUX)
	this->mode = mode;
#	endif
}

//mem::vtable_t

mem::vtable_t::vtable_t(voidptr_t* vtable)
{
	this->table = std::make_shared<voidptr_t>(vtable);
}

mem::vtable_t::~vtable_t()
{

}

mem::bool_t mem::vtable_t::is_valid()
{
	return (bool_t)(
		this->table.get() != (voidptr_t*)-1
	);
}

mem::bool_t mem::vtable_t::hook(size_t index, voidptr_t dst)
{
	if (!this->is_valid()) return false;
	this->orig_table.insert(std::pair<size_t, voidptr_t>(index, this->table.get()[index]));
	this->table.get()[index] = dst;
	return true;
}

mem::bool_t mem::vtable_t::restore(size_t index)
{
	if (!this->is_valid()) return false;

	for (auto i = this->orig_table.begin(); i != this->orig_table.end(); i++)
	{
		if (i->first == index)
		{
			this->table.get()[index] = i->second;
			return true;
		}
	}

	return false;
}

mem::bool_t mem::vtable_t::restore_all()
{
	if (!this->is_valid()) return false;

	for (auto i = this->orig_table.begin(); i != this->orig_table.end(); i++)
		this->table.get()[i->first] = i->second;

	return true;
}

//libmem

mem::string_t  mem::parse_mask(string_t mask)
{
	for (::size_t i = 0; i < mask.length(); i++)
	{
		if (mask[i] == MEM_STR('X'))
		{
			mask[i] = std::tolower(mask[i]);;
			break;
		}

		if (mask[i] != MEM_STR('x'))
		{
			mask[i] = MEM_STR('?');
			break;
		}
	}

	return mask;
}

mem::uintptr_t mem::get_page_size()
{
	uintptr_t page_size = (uintptr_t)MEM_BAD;
#	if defined(MEM_WIN)
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	page_size = (uintptr_t)si.dwPageSize;
#	elif defined(MEM_LINUX)
	page_size = (uintptr_t)sysconf(_SC_PAGE_SIZE);
#	endif

	return page_size;
}

//ex

mem::pid_t mem::ex::get_pid(string_t process_name)
{
	pid_t pid = (pid_t)MEM_BAD;
#	if defined(MEM_WIN)
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!MEM_STR_CMP(procEntry.szExeFile, process_name.c_str()))
				{
					pid = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));

		}
	}
	CloseHandle(hSnap);
#	elif defined(MEM_LINUX)
	DIR* pdir = opendir("/proc");
	if (!pdir)
		return pid;

	struct dirent* pdirent = (struct dirent*)0;
	while (pid < 0 && (pdirent = readdir(pdir)))
	{
		pid_t id = atoi(pdirent->d_name);
		if (id > 0)
		{
			string_t proc_name = ex::get_process_name(id);
			if (process_name == proc_name)
			{
				pid = id;
				break;
			}
		}
	}
	closedir(pdir);
#	endif
	return pid;
}

mem::string_t mem::ex::get_process_name(pid_t pid)
{
	string_t process_name = "";
#	if defined(MEM_WIN)
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (pid == procEntry.th32ProcessID)
				{
					process_name = procEntry.szExeFile;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
#	elif defined(MEM_LINUX)
	char path[64];
	memset(path, 0x0, sizeof(path));
	snprintf(path, sizeof(path), "/proc/%i/exe", pid);

	char buffer[PATH_MAX];
	memset(buffer, 0x0, sizeof(buffer));
	readlink(path, buffer, sizeof(buffer));
	char* temp = buffer;
	char* proc_name = (char*)0;
	while ((temp = strstr(temp, "/")) && temp != (char*)-1)
	{
		proc_name = &temp[1];
		temp = proc_name;
	}

	if (!proc_name || proc_name == (char*)-1)
		return process_name;

	process_name = proc_name;
#	endif

	return process_name;
}

mem::process_t mem::ex::get_process(pid_t pid)
{
	process_t process = process_t();
	process.pid = pid;
	process.name = ex::get_process_name(process.pid);
#	if defined(MEM_WIN)
	process.handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
#	elif defined(MEM_LINUX)
#	endif

	return process;
}

mem::process_t mem::ex::get_process(string_t process_name)
{
	process_t process = process_t();
	pid_t pid = ex::get_pid(process_name);
	if (pid != (pid_t)MEM_BAD)
		process = ex::get_process(pid);

	return process;
}

mem::process_list_t mem::ex::get_process_list()
{
	process_list_t proc_list = process_list_t();
#	if defined(MEM_WIN)
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				process_t process = ex::get_process(procEntry.th32ProcessID);
				if(process.is_valid())
					proc_list.push_back(process);
			} while (Process32Next(hSnap, &procEntry));

		}
	}
	CloseHandle(hSnap);
#	elif defined(MEM_LINUX)
	DIR* pdir = opendir("/proc");
	if (!pdir)
		return pid;

	struct dirent* pdirent = (struct dirent*)0;
	while (pid < 0 && (pdirent = readdir(pdir)))
	{
		pid_t id = (pid_t)atoi(pdirent->d_name);
		if (id > 0)
		{
			process_t process = ex::get_process(id);
			if(process.is_valid())
				proc_list.push_back(process);
		}
	}
	closedir(pdir);
#	endif

	return proc_list;
}

mem::module_t mem::ex::get_module(process_t process, string_t module_name)
{
	module_t mod = module_t();

#	if defined(MEM_WIN)
	MODULEENTRY32 module_info;
	module_info.dwSize = sizeof(MODULEENTRY32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process.pid);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!MEM_STR_CMP(modEntry.szModule, module_name.c_str()) || !MEM_STR_CMP(modEntry.szExePath, module_name.c_str()))
				{
					module_info = modEntry;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}

	CloseHandle(hSnap);

	mod.base = (voidptr_t)module_info.modBaseAddr;
	mod.size = (size_t)module_info.modBaseSize;
	mod.end  = (voidptr_t)((uintptr_t)mod.base + mod.size);
	mod.handle = (module_handle_t)module_info.hModule;
	mod.path = module_info.szExePath;
	mod.name = module_info.szModule;
#	elif defined(MEM_LINUX)
	//WIP
#	endif

	return mod;
}

mem::module_list_t mem::ex::get_module_list(process_t process)
{
	module_list_t mod_list = module_list_t();
#	if defined(MEM_WIN)
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process.pid);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				module_t mod = module_t();
				mod.base = (voidptr_t)modEntry.modBaseAddr;
				mod.size = (uintptr_t)modEntry.modBaseSize;
				mod.end =  (voidptr_t)((uintptr_t)mod.base + mod.size);
				mod.name = modEntry.szModule;
				mod.path = modEntry.szExePath;
				mod.handle = modEntry.hModule;

				mod_list.push_back(mod);
			} while (Module32Next(hSnap, &modEntry));
		}
	}

	CloseHandle(hSnap);
#	elif defined(MEM_LINUX)
	//WIP
#	endif

	return mod_list;
}

#endif //MEM_COMPATIBLE