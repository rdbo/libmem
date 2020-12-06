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

#endif //MEM_COMPATIBLE