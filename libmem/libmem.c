//Made by rdbo
//https://github.com/rdbo/libmem

#include "libmem.h"
#if defined(MEM_COMPATIBLE)

//mem_string_t
struct _mem_string_t mem_string_init()
{
	struct _mem_string_t _string;
	mem_size_t _size = sizeof(mem_char_t) * 1;
	_string.buffer = (mem_char_t*)malloc(_size);
	_string.npos = (mem_size_t)-1;
	_string.is_valid = &mem_string_is_valid;
	_string.clear    = &mem_string_clear;
	_string.empty    = &mem_string_empty;
	_string.size     = &mem_string_size;
	_string.resize   = &mem_string_resize;
	_string.length   = &mem_string_length;
	_string.begin    = &mem_string_begin;
	_string.end      = &mem_string_end;
	_string.find     = &mem_string_find;
	_string.rfind    = &mem_string_rfind;
	_string.count    = &mem_string_count;
	_string.rcount   = &mem_string_rcount;
	_string.at       = &mem_string_at;
	_string.c_set    = &mem_string_c_set;
	_string.value    = &mem_string_value;
	_string.insert   = &mem_string_insert;
	_string.replace  = &mem_string_replace;
	_string.reverse  = &mem_string_reverse;
	_string.c_str    = &mem_string_c_str;
	_string.to_lower = &mem_string_to_lower;
	_string.to_upper = &mem_string_to_upper;
	_string.substr   = &mem_string_substr;
	_string.compare  = &mem_string_compare;
	_string.is_initialized = (mem_bool_t)(mem_true && (_string.buffer));
	if (!_string.is_initialized) return _string;
	memset(_string.buffer, 0x0, _size);
	return _string;
}

struct _mem_string_t mem_string_new(const mem_char_t* c_string)
{
	struct _mem_string_t _str = mem_string_init();
	mem_string_empty(&_str);
	mem_size_t size = (mem_size_t)(MEM_STR_LEN(c_string) + 1) * sizeof(mem_char_t);
	_str.buffer = (mem_char_t*)malloc(size);
	if (!_str.buffer)
	{
        //_str = mem_string_init();
		_str.is_initialized = mem_false;
		return _str;
	}
	memset(_str.buffer, 0x0, size);
	memcpy(_str.buffer, c_string, size);
	_str.buffer[((size / sizeof(mem_char_t)) - 1)] = MEM_STR('\0');
	return _str;
}

mem_bool_t mem_string_is_valid(struct _mem_string_t* p_string)
{
	return (mem_bool_t)(
		p_string &&
		p_string->is_initialized == mem_true &&
        p_string->buffer &&
		MEM_STR_CMP(p_string->buffer, MEM_STR(""))
	);
}

mem_void_t mem_string_clear(struct _mem_string_t* p_string)
{
	if (p_string->is_initialized == mem_true && p_string->buffer)
		memset((void*)p_string->buffer, (int)0x0, (size_t)mem_string_size(p_string));
}

mem_void_t mem_string_empty(struct _mem_string_t* p_string)
{
	if (p_string && p_string->buffer)
	{
		free(p_string->buffer);
		p_string->buffer = (mem_char_t*)NULL;
	}
}

mem_size_t mem_string_size(struct _mem_string_t* p_string)
{
	mem_size_t ret = (mem_size_t)MEM_BAD_RETURN;
	if (p_string->is_initialized)
	{
		ret = (mem_size_t)((mem_uintptr_t)mem_string_end(p_string) - (mem_uintptr_t)mem_string_begin(p_string));
	}

	return ret;
}

mem_void_t mem_string_resize(struct _mem_string_t* p_string, mem_size_t size)
{
	if (p_string->is_initialized != mem_true || !p_string->buffer || size == 0) return;
	size = (size + 1) * sizeof(mem_char_t);
	mem_char_t* _buffer = (mem_char_t*)malloc(size);
	if (!_buffer) return;
	mem_size_t old_size = mem_string_size(p_string);
	if (p_string->buffer)
	{
		memcpy((void*)_buffer, (void*)p_string->buffer, (size_t)(size > old_size ? old_size : size - 1 * sizeof(mem_char_t)));
		free(p_string->buffer);
	}
	_buffer[size / sizeof(mem_char_t) - 1] = MEM_STR('\0');
	p_string->buffer = _buffer;
}

mem_size_t mem_string_length(struct _mem_string_t* p_string)
{
	return (mem_size_t)(p_string->is_initialized == mem_true ? MEM_STR_LEN(p_string->buffer) : (mem_size_t)MEM_BAD_RETURN);
}

mem_char_t* mem_string_begin(struct _mem_string_t* p_string)
{
	return (mem_char_t*)p_string->buffer;
}

mem_char_t* mem_string_end(struct _mem_string_t* p_string)
{
	return (mem_char_t*)((mem_uintptr_t)p_string->buffer + mem_string_length(p_string) * sizeof(mem_char_t));
}

mem_size_t mem_string_find(struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset)
{
	mem_size_t ret = (mem_size_t)MEM_BAD_RETURN;
	if (p_string->is_initialized != mem_true) return ret;
	mem_size_t str_len = mem_string_length(p_string) + 1;
	mem_size_t substr_len = (mem_size_t)MEM_STR_LEN(substr);
	for (; offset + substr_len <= str_len; offset++)
	{
		if (!MEM_STR_N_CMP((mem_char_t*)((mem_uintptr_t)p_string->buffer + offset * sizeof(mem_char_t)), substr, substr_len))
		{
			ret = offset;
			break;
		}
	}

	return ret;
}

mem_size_t mem_string_rfind(struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset)
{
	mem_size_t ret = (mem_size_t)MEM_BAD_RETURN;
	if(!mem_string_is_valid(p_string)) return ret;
	if (offset == (mem_size_t)-1) offset = mem_string_length(p_string) + 1;
	if (!p_string || p_string->is_initialized != mem_true || !substr) return ret;
	mem_size_t str_len = mem_string_length(p_string) + 1;
	mem_size_t substr_len = (mem_size_t)MEM_STR_LEN(substr);
	for (; str_len > substr_len && offset >= substr_len && (mem_intptr_t)((offset - substr_len) * sizeof(mem_char_t)) >= 0; offset--)
	{
		if (!MEM_STR_N_CMP((mem_char_t*)((mem_uintptr_t)p_string->buffer + (offset - substr_len) * sizeof(mem_char_t)), substr, substr_len))
		{
			ret = offset - 1;
			break;
		}
	}

	return ret;
}

mem_size_t mem_string_count(struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset)
{
	mem_size_t count = 0;
	for (mem_size_t next = offset; (next = mem_string_find(p_string, substr, next)) != (mem_size_t)MEM_BAD_RETURN; next++)
		count++;
	return count;
}

mem_size_t mem_string_rcount(struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset)
{
	mem_size_t count = 0;
	for (mem_size_t next = offset; (next = mem_string_rfind(p_string, substr, next)) != (mem_size_t)MEM_BAD_RETURN; next--)
		count++;
	return count;
}

mem_char_t mem_string_at(struct _mem_string_t* p_string, mem_size_t pos)
{
	mem_char_t c = '\xFF';
	if (pos < mem_string_length(p_string))
		c = mem_string_c_str(p_string)[pos];
	return c;
}

mem_void_t mem_string_insert(struct _mem_string_t* p_string, const mem_char_t* str)
{
	mem_size_t old_length = mem_string_length(p_string);
	mem_string_resize(p_string, old_length + (mem_size_t)MEM_STR_LEN(str));
	memcpy((void*)(p_string->buffer + old_length * sizeof(mem_char_t)), str, MEM_STR_LEN(str) * sizeof(mem_char_t));
}

mem_void_t mem_string_value(struct _mem_string_t* p_string, const mem_char_t* new_str)
{
	if (!p_string || !p_string->is_initialized || !new_str) return;
	mem_size_t size = (mem_size_t)(MEM_STR_LEN(new_str) + 1) * sizeof(mem_char_t);
	mem_char_t* _buffer = (mem_char_t*)malloc(size);
	if (_buffer == 0) return;
	memcpy(_buffer, new_str, size - 1 * sizeof(mem_char_t));
	_buffer[size / sizeof(mem_char_t) - 1] = MEM_STR('\0');
	mem_string_empty(p_string);
	p_string->buffer = _buffer;
}

mem_void_t mem_string_replace(struct _mem_string_t* p_string, const mem_char_t* old_str, const mem_char_t* new_str)
{
	mem_size_t length = mem_string_length(p_string);
	mem_size_t old_str_len = (mem_size_t)MEM_STR_LEN(old_str);
	mem_size_t new_str_len = (mem_size_t)MEM_STR_LEN(new_str);
	for (mem_size_t i = 0; (i = mem_string_find(p_string, old_str, i)) != p_string->npos && i != (mem_size_t)MEM_BAD_RETURN && i < length; i += new_str_len)
	{
		mem_string_t holder = mem_string_substr(p_string, i + old_str_len, length);
		mem_string_resize(p_string, i);
		mem_string_insert(p_string, new_str);
		mem_string_insert(p_string, mem_string_c_str(&holder));
		length = mem_string_length(p_string);
		mem_string_free(&holder);
	}
}

mem_void_t mem_string_reverse (struct _mem_string_t* p_string)
{
	if(!mem_string_is_valid(p_string)) return;

	mem_size_t size   = mem_string_size(p_string);
	mem_size_t length = mem_string_length(p_string);

	mem_char_t* buf = (mem_char_t*)malloc(size);

	for(mem_size_t i = 0; i < length; i++)
	{
		buf[i] = p_string->buffer[length - i - 1];
	}

	if(p_string->buffer)
		free(p_string->buffer);

	p_string->buffer = buf;
}

mem_char_t* mem_string_c_str(struct _mem_string_t* p_string)
{
	return p_string->buffer;
}

mem_void_t mem_string_c_set(struct _mem_string_t* p_string, mem_size_t pos, mem_char_t c)
{
	if (pos <= mem_string_length(p_string))
		p_string->buffer[pos] = c;
}

mem_bool_t mem_string_compare(struct _mem_string_t* p_string, struct _mem_string_t str)
{
	return (mem_bool_t)(MEM_STR_CMP(mem_string_c_str(p_string), mem_string_c_str(&str)) == 0);
}

struct _mem_string_t* mem_string_to_lower(struct _mem_string_t* p_string)
{
	if (!mem_string_is_valid(p_string)) return p_string;

	for (mem_size_t i = 0; i < mem_string_length(p_string); i++)
		mem_string_c_set(p_string, i, tolower(mem_string_at(p_string, i)));

	return p_string;
}

struct _mem_string_t* mem_string_to_upper(struct _mem_string_t* p_string)
{
	if (!mem_string_is_valid(p_string)) return p_string;

	for (mem_size_t i = 0; i < mem_string_length(p_string); i++)
		mem_string_c_set(p_string, i, toupper(mem_string_at(p_string, i)));

	return p_string;
}

struct _mem_string_t mem_string_substr(struct _mem_string_t* p_string, mem_size_t start, mem_size_t end)
{
	struct _mem_string_t new_str = mem_string_init();
	if (!mem_string_is_valid(p_string)) return new_str;
	if (end == (mem_size_t)-1) end = mem_string_length(p_string) + 1;
	mem_size_t len = end - start;
	if (end > start && mem_string_length(p_string) > len)
	{
		mem_size_t buffer_size = (len + 1) * sizeof(mem_char_t);
		mem_char_t* _buffer = (mem_char_t*)malloc(buffer_size);
		if (_buffer == 0) return new_str;
		memcpy((void*)_buffer, (void*)((mem_uintptr_t)p_string->buffer + start * sizeof(mem_char_t)), (size_t)(len * sizeof(mem_char_t)));
		_buffer[len] = MEM_STR('\0');
        if(new_str.buffer)
        {
            free(new_str.buffer);
        }
		new_str.buffer = _buffer;
	}

	return new_str;
}

mem_void_t mem_string_free(struct _mem_string_t* p_string)
{
	if(!mem_string_is_valid(p_string)) return;
	p_string->is_initialized = mem_false;

	if(p_string->buffer)
	{
		free(p_string->buffer);
		p_string->buffer = (mem_char_t*)NULL;
	}
}

//mem_process_t

struct _mem_process_t mem_process_init()
{
	struct _mem_process_t _process;
	_process.name     = mem_string_init();
	_process.pid      = (mem_pid_t)MEM_BAD_RETURN;
	_process.is_valid = &mem_process_is_valid;
	_process.compare  = &mem_process_compare;
	_process.is_initialized = mem_true;
	return _process;
}

mem_bool_t mem_process_is_valid(struct _mem_process_t* p_process)
{
	return (mem_bool_t)(
		p_process->is_initialized == mem_true &&
		MEM_STR_CMP(mem_string_c_str(&p_process->name), MEM_STR("")) &&
		p_process->pid != (mem_pid_t)MEM_BAD_RETURN
	);
}

mem_bool_t mem_process_compare(struct _mem_process_t* p_process, struct _mem_process_t process)
{
	return (mem_bool_t)(
		mem_string_compare(&p_process->name, process.name) == mem_true &&
		p_process->pid == process.pid
	);
}

mem_void_t mem_process_free(struct _mem_process_t* p_process)
{
	if(!mem_process_is_valid(p_process)) return;
	p_process->is_initialized = mem_false;
	free(p_process->name.buffer);
}

//mem_process_list_t

mem_process_list_t mem_process_list_init()
{
	mem_process_list_t proc_list;

	proc_list._length  = 0;
	proc_list._buffer  = NULL;
	proc_list.at       = &mem_process_list_at;
	proc_list.is_valid = &mem_process_list_is_valid;
	proc_list.buffer   = &mem_process_list_buffer;
	proc_list.length   = &mem_process_list_length;
	proc_list.resize   = &mem_process_list_resize;
	proc_list.size     = &mem_process_list_size;
	proc_list.append   = &mem_process_list_append;
	proc_list.is_initialized = mem_true;

	return proc_list;
}

mem_process_t mem_process_list_at(struct _mem_process_list_t* p_process_list, mem_size_t pos)
{
	mem_process_t ret = mem_process_init();
	mem_size_t    length = mem_process_list_length(p_process_list);
	ret.is_initialized = mem_false;

	if(pos < length) ret = mem_process_list_buffer(p_process_list)[pos];

	return ret;
}

mem_bool_t mem_process_list_is_valid(struct _mem_process_list_t* p_process_list)
{
	return (mem_bool_t)(
		p_process_list != NULL &&
		p_process_list->is_initialized
	);
}

mem_size_t mem_process_list_length(struct _mem_process_list_t* p_process_list)
{
	if(!mem_process_list_is_valid(p_process_list)) return (mem_size_t)MEM_BAD_RETURN;
	return p_process_list->_length;
}

mem_process_t* mem_process_list_buffer(struct _mem_process_list_t* p_process_list)
{
	if(!mem_process_list_is_valid(p_process_list)) return (mem_process_t*)MEM_BAD_RETURN;
	return p_process_list->_buffer;
}

mem_size_t mem_process_list_size(struct _mem_process_list_t* p_process_list)
{
	return mem_process_list_length(p_process_list) * sizeof(mem_process_t);
}

mem_void_t mem_process_list_resize(struct _mem_process_list_t* p_process_list, mem_size_t size)
{
	if(!mem_process_list_is_valid(p_process_list) || size == 0) return;
	mem_size_t old_size = mem_process_list_size(p_process_list);
	mem_size_t length = size;
	size *= sizeof(mem_process_t);

	mem_process_t* _buffer = (mem_process_t*)malloc(size);

	if(p_process_list->_buffer)
	{
		memcpy((void*)_buffer, (void*)p_process_list->_buffer, (size > old_size ? old_size : size));
		free(p_process_list->_buffer);
	}

	p_process_list->_buffer = _buffer;
	p_process_list->_length = length;
}

mem_void_t mem_process_list_append(struct _mem_process_list_t* p_process_list, mem_process_t process)
{
	mem_size_t old_length = mem_process_list_length(p_process_list);
	mem_process_list_resize(p_process_list, old_length + 1);

	p_process_list->_buffer[old_length] = process;
}

mem_void_t mem_process_list_free(struct _mem_process_list_t* p_process_list)
{
	if(!p_process_list || !p_process_list->is_initialized) return;

	p_process_list->is_initialized = mem_false;

	if(p_process_list->_buffer)
	{
		for(mem_size_t i = 0; i < p_process_list->_length; i++)
		{
			mem_process_free(&p_process_list->_buffer[i]);
		}

		free(p_process_list->_buffer);
		p_process_list->_buffer = NULL;
	}
}

//mem_module_t

struct _mem_module_t mem_module_init()
{
	struct _mem_module_t _mod;
	_mod.name     = mem_string_init();
	_mod.path     = mem_string_init();
	_mod.base     = (mem_voidptr_t)MEM_BAD_RETURN;
	_mod.size     = (mem_uintptr_t)MEM_BAD_RETURN;
	_mod.end      = (mem_voidptr_t)MEM_BAD_RETURN;
	_mod.is_valid = &mem_module_is_valid;
	_mod.compare  = &mem_module_compare;
	_mod.is_initialized = mem_true;
	return _mod;
}

mem_bool_t mem_module_is_valid(struct _mem_module_t* p_mod)
{
	return (mem_bool_t)(
		p_mod->is_initialized                         &&
		MEM_STR_CMP(mem_string_c_str(&p_mod->name), MEM_STR("")) &&
		MEM_STR_CMP(mem_string_c_str(&p_mod->path), MEM_STR("")) &&
		p_mod->base != (mem_voidptr_t)MEM_BAD_RETURN  &&
		p_mod->size != (mem_uintptr_t)MEM_BAD_RETURN     &&
		p_mod->end != (mem_voidptr_t)MEM_BAD_RETURN
	);
}

mem_bool_t mem_module_compare(struct _mem_module_t* p_mod, struct _mem_module_t mod)
{
	return (mem_bool_t)(
		mem_string_compare(&p_mod->name, mod.name) &&
		mem_string_compare(&p_mod->path, mod.path) &&
		p_mod->base == mod.base                    &&
		p_mod->size == mod.size                    &&
		p_mod->end == mod.end
	);
}

mem_void_t mem_module_free(struct _mem_module_t* p_mod)
{
	if(!mem_module_is_valid(p_mod)) return;
	p_mod->is_initialized = mem_false;
	free(p_mod->name.buffer);
	free(p_mod->path.buffer);
}

//mem_module_list_t

mem_module_list_t mem_module_list_init()
{
	mem_module_list_t mod_list;
	mod_list._length  = 0;
	mod_list._buffer  = NULL;
	mod_list.at       = &mem_module_list_at;
	mod_list.is_valid = &mem_module_list_is_valid;
	mod_list.length   = &mem_module_list_length;
	mod_list.buffer   = &mem_module_list_buffer;
	mod_list.size     = &mem_module_list_size;
	mod_list.resize   = &mem_module_list_resize;
	mod_list.append   = &mem_module_list_append;
	mod_list.is_initialized = mem_true;

	return mod_list;
}

mem_module_t mem_module_list_at(struct _mem_module_list_t* p_module_list, mem_size_t pos)
{
	mem_module_t ret = mem_module_init();
	ret.is_initialized = mem_false;
	if(!mem_module_list_is_valid(p_module_list)) return ret;
	mem_size_t   length = mem_module_list_length(p_module_list);

	if(pos < length) ret = mem_module_list_buffer(p_module_list)[pos];

	return ret;
}

mem_bool_t mem_module_list_is_valid(struct _mem_module_list_t* p_module_list)
{
	return (mem_bool_t)(
		p_module_list != NULL &&
		p_module_list->is_initialized
	);
}

mem_size_t mem_module_list_length  (struct _mem_module_list_t* p_module_list)
{
	if(!mem_module_list_is_valid(p_module_list)) return (mem_size_t)MEM_BAD_RETURN;
	return p_module_list->_length;
}

mem_module_t* mem_module_list_buffer(struct _mem_module_list_t* p_module_list)
{
	if(!mem_module_list_is_valid(p_module_list)) return (mem_module_t*)MEM_BAD_RETURN;
	return p_module_list->_buffer;
}

mem_size_t mem_module_list_size(struct _mem_module_list_t* p_module_list)
{
	return mem_module_list_length(p_module_list) * sizeof(mem_module_t);
}

mem_void_t mem_module_list_resize(struct _mem_module_list_t* p_module_list, mem_size_t size)
{
	if(!mem_module_list_is_valid(p_module_list) || size == 0) return;
	mem_size_t old_size = mem_module_list_size(p_module_list);
	mem_size_t length = size;
	size *= sizeof(mem_module_t);

	mem_module_t* _buffer = (mem_module_t*)malloc(size);

	if(p_module_list->_buffer)
	{
		memcpy((void*)_buffer, (void*)p_module_list->_buffer, (size > old_size ? old_size : size));
		free(p_module_list->_buffer);
	}

	p_module_list->_buffer = _buffer;
	p_module_list->_length = length;
}

mem_void_t mem_module_list_append(struct _mem_module_list_t* p_module_list, mem_module_t mod)
{
	mem_size_t old_length = mem_module_list_length(p_module_list);
	mem_module_list_resize(p_module_list, old_length + 1);

	p_module_list->_buffer[old_length] = mod;
}

mem_void_t mem_module_list_free(struct _mem_module_list_t* p_module_list)
{
	if(!p_module_list || !p_module_list->is_initialized) return;

	p_module_list->is_initialized = mem_false;

	if(p_module_list->_buffer)
	{
		for(mem_size_t i = 0; i < p_module_list->_length; i++)
		{
			mem_module_free(&p_module_list->_buffer[i]);
		}

		free(p_module_list->_buffer);
		p_module_list->_buffer = NULL;
	}
}

//mem_page_t

struct _mem_page_t mem_page_init()
{
	struct _mem_page_t page;
    page.base = (mem_voidptr_t)MEM_BAD_RETURN;
    page.size = (mem_uintptr_t)MEM_BAD_RETURN;
    page.end  = (mem_voidptr_t)MEM_BAD_RETURN;
    page.protection = (mem_prot_t)0;
	page.flags      = (mem_flags_t)0;

	page.is_valid = &mem_page_is_valid;

	page.is_initialized = mem_true;

    return page;
}

mem_bool_t mem_page_is_valid(struct _mem_page_t* p_page)
{
	return (mem_bool_t)(
		p_page &&
		p_page->is_initialized &&
		p_page->base != (mem_voidptr_t)MEM_BAD_RETURN &&
		p_page->size != (mem_uintptr_t)MEM_BAD_RETURN &&
		p_page->end  != (mem_voidptr_t)MEM_BAD_RETURN &&
		p_page->protection != (mem_prot_t)0           &&
		p_page->flags      != (mem_flags_t)0
	);
}

//mem_alloc_t

struct _mem_alloc_t mem_alloc_init()
{
	struct _mem_alloc_t _alloc;
#   if defined(MEM_WIN)
	_alloc.protection = PAGE_EXECUTE_READWRITE;
	_alloc.type       = MEM_COMMIT | MEM_RESERVE;
#   elif defined(MEM_LINUX)
	_alloc.protection = PROT_EXEC | PROT_READ | PROT_WRITE;
	_alloc.type       = MAP_ANON | MAP_PRIVATE;
#   endif

	_alloc.is_valid   = &mem_alloc_is_valid;
	_alloc.is_initialized = mem_true;
	return _alloc;
}

mem_bool_t mem_alloc_is_valid(struct _mem_alloc_t* p_alloc)
{
	return (mem_bool_t)(
		p_alloc->is_initialized == mem_true &&
		p_alloc->protection != (mem_prot_t)MEM_BAD_RETURN &&
		p_alloc->type != (mem_prot_t)MEM_BAD_RETURN
	);
}

//mem_lib_t

struct _mem_lib_t mem_lib_init()
{
	struct _mem_lib_t _lib;
	_lib.path     = mem_string_init();
	_lib.is_valid = &mem_lib_is_valid;
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
	_lib.mode = (mem_int_t)RTLD_LAZY;
#   endif
	_lib.is_initialized = mem_true;
	return _lib;
}

struct _mem_lib_t  mem_lib_new(mem_string_t path, mem_int_t mode)
{
    struct _mem_lib_t _lib = mem_lib_init();
	mem_lib_free(&_lib);
	_lib.path = mem_string_new(mem_string_c_str(&path));
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
	_lib.mode = (mem_int_t)mode;
#   endif
	_lib.is_initialized = mem_true;
	return _lib;
}

struct _mem_lib_t  mem_lib_new2(mem_char_t* path, mem_int_t mode)
{
	struct _mem_lib_t _lib = mem_lib_init();
	mem_lib_free(&_lib);
	_lib.path = mem_string_new(path);
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
	_lib.mode = (mem_int_t)mode;
#   endif
	_lib.is_initialized = mem_true;
	return _lib;
}

mem_bool_t mem_lib_is_valid(struct _mem_lib_t* p_lib)
{
	return (mem_bool_t)(
		p_lib &&
		p_lib->is_initialized &&
		MEM_STR_CMP(mem_string_c_str(&p_lib->path), MEM_STR(""))
	);
}

mem_void_t mem_lib_free(struct _mem_lib_t* p_lib)
{
	if(!p_lib || !p_lib->is_initialized) return;

	p_lib->is_initialized = mem_false;

	if(mem_string_is_valid(&p_lib->path))
	{
		mem_string_free(&p_lib->path);
	}
}

//libmem

mem_string_t  mem_parse_mask(mem_string_t mask)
{
	mem_size_t size = mem_string_length(&mask);
	mem_string_t new_mask = mem_string_init();
	mem_string_resize(&new_mask, size + 1);
	for (mem_size_t i = 0; i <= size; i++)
	{
		mem_char_t c = mem_string_at(&mask, i);
		mem_string_c_set(&new_mask, i, (c == MEM_KNOWN_BYTE || c == toupper(MEM_KNOWN_BYTE) ? MEM_KNOWN_BYTE : MEM_UNKNOWN_BYTE));
	}

	mem_string_c_set(&new_mask, size, MEM_STR('\0'));
	return new_mask;
}

mem_uintptr_t mem_get_page_size()
{
	mem_uintptr_t pagesize = (mem_uintptr_t)MEM_BAD_RETURN;
#	if defined(MEM_WIN)
	SYSTEM_INFO si;
    GetSystemInfo(&si);
	pagesize = (mem_uintptr_t)si.dwPageSize;
#	elif defined(MEM_LINUX)
	pagesize = (mem_uintptr_t)sysconf(_SC_PAGE_SIZE);
#	endif

	return pagesize;
}

//ex

mem_pid_t mem_ex_get_pid(mem_string_t process_name)
{
	mem_pid_t pid = (mem_pid_t)MEM_BAD_RETURN;
#   if defined(MEM_WIN)
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!MEM_STR_CMP(procEntry.szExeFile, mem_string_c_str(&process_name)))
				{
					pid = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));

		}
	}
	CloseHandle(hSnap);
#   elif defined(MEM_LINUX)
	DIR* pdir = opendir("/proc");
	if (!pdir)
		return pid;

	struct dirent* pdirent;
	while (pid < 0 && (pdirent = readdir(pdir)))
	{
		mem_pid_t id = atoi(pdirent->d_name);
		if (id > 0)
		{
			mem_string_t proc_name = mem_ex_get_process_name(id);
			if (mem_string_compare(&process_name, proc_name))
				pid = id;
			
			mem_string_free(&proc_name);
		}
	}
	closedir(pdir);
#   endif
	return pid;
}

mem_pid_t mem_ex_get_pid2(mem_char_t* process_name)
{
    mem_string_t process_name_str = mem_string_new(process_name);
    mem_pid_t    pid = mem_ex_get_pid(process_name_str);
    mem_string_free(&process_name_str);
    return pid;
}

mem_string_t mem_ex_get_process_name(mem_pid_t pid)
{
	mem_string_t process_name = mem_string_init();
#   if defined(MEM_WIN)
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
					mem_string_value(&process_name, procEntry.szExeFile);
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
#   elif defined(MEM_LINUX)
    /*
	char path_buffer[64];
	snprintf(path_buffer, sizeof(path_buffer) - 1, "/proc/%i/cmdline", pid);
	int fd = open(path_buffer, O_RDONLY);
	if (fd == -1) return process_name;
	mem_string_t file_buffer = mem_string_init();
	mem_size_t   file_size = 0;
	int read_check = 0;
	for (char c; (read_check = read(fd, &c, 1)) != -1 && read_check != 0; file_size++)
	{
		mem_string_resize(&file_buffer, file_size);
		mem_string_c_set(&file_buffer, file_size, c);
	}

	mem_size_t process_name_end = mem_string_length(&file_buffer);
	mem_size_t process_name_pos = mem_string_rfind(&file_buffer, "/", process_name_end) + 1;
	if (process_name_end == (mem_size_t)MEM_BAD_RETURN || process_name_pos == (mem_size_t)MEM_BAD_RETURN || process_name_pos == (mem_size_t)(MEM_BAD_RETURN + 1)) return process_name;
	process_name = mem_string_substr(&file_buffer, process_name_pos, process_name_end);
	mem_string_free(&file_buffer);
	close(fd);
    */

    char path_buffer[64];
	snprintf(path_buffer, sizeof(path_buffer) - 1, "/proc/%i/maps", pid);
	int fd = open(path_buffer, O_RDONLY);
	if (fd == -1) return process_name;
	mem_string_t file_buffer = mem_string_init();
	mem_size_t   file_size = 1;
	int read_check = 0;
	for (char c; (read_check = read(fd, &c, 1)) != -1 && read_check != 0; file_size++)
	{
		mem_string_resize(&file_buffer, file_size);
		mem_string_c_set(&file_buffer, file_size, c);
		if (file_size > 0 && mem_string_at(&file_buffer, file_size) == '\n' && mem_string_rfind(&file_buffer, "/", file_size - 1) != (mem_size_t)MEM_BAD_RETURN) break;
	}

	mem_size_t process_name_end = mem_string_find(&file_buffer, "\n", mem_string_find(&file_buffer, "/", 0));
	mem_size_t process_name_pos = mem_string_rfind(&file_buffer, "/", process_name_end) + 1;
	if (process_name_end == (mem_size_t)MEM_BAD_RETURN || process_name_pos == (mem_size_t)MEM_BAD_RETURN || process_name_pos == (mem_size_t)(MEM_BAD_RETURN + 1)) return process_name;
	process_name = mem_string_substr(&file_buffer, process_name_pos, process_name_end);
	mem_string_empty(&file_buffer);
	close(fd);

#   endif
	return process_name;
}

mem_process_t mem_ex_get_process(mem_pid_t pid)
{
	mem_process_t process = mem_process_init();
	process.pid = pid;
	process.name = mem_ex_get_process_name(process.pid);
#	if defined(MEM_WIN)
	process.handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
#	elif defined(MEM_LINUX)
#	endif
	return process;
}

mem_process_t mem_ex_get_process2(mem_string_t process_name)
{
    mem_pid_t pid = mem_ex_get_pid(process_name);
    mem_process_t process = mem_ex_get_process(pid);
    return process;
}

mem_process_t mem_ex_get_process3(mem_char_t* process_name)
{
    mem_pid_t pid = mem_ex_get_pid2(process_name);
    mem_process_t process = mem_ex_get_process(pid);
    return process;
}

mem_process_list_t mem_ex_get_process_list()
{
	mem_process_list_t proc_list = mem_process_list_init();

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
				if (1)
				{
					mem_pid_t pid = procEntry.th32ProcessID;
					mem_string_t process_name = mem_ex_get_process_name(pid);
					mem_process_t process = mem_process_init();
					process.pid  = pid;
					process.name = process_name;

					mem_process_list_append(&proc_list, process);
				}
			} while (Process32Next(hSnap, &procEntry));

		}
	}
	CloseHandle(hSnap);
#	elif defined(MEM_LINUX)
	DIR* pdir = opendir("/proc");
	if (!pdir) return proc_list;

	struct dirent* pdirent;
	while ((pdirent = readdir(pdir)))
	{
		mem_pid_t id = atoi(pdirent->d_name);
		if (id > 0)
		{
			mem_string_t proc_name = mem_ex_get_process_name(id);
			if (1)
			{
				mem_process_t process = mem_process_init();
				process.pid  = id;
				process.name = proc_name;

				mem_process_list_append(&proc_list, process);
			}
		}
	}
	closedir(pdir);
#	endif

	return proc_list;
}

mem_module_t mem_ex_get_module(mem_process_t process, mem_string_t module_name)
{
	mem_module_t modinfo = mem_module_init();
	if (!mem_process_is_valid(&process)) return modinfo;
#   if defined(MEM_WIN)

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
				if (!MEM_STR_CMP(modEntry.szModule, mem_string_c_str(&module_name)) || !MEM_STR_CMP(modEntry.szExePath, mem_string_c_str(&module_name)))
				{
					module_info = modEntry;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}

	CloseHandle(hSnap);

	modinfo.base = (mem_voidptr_t)module_info.modBaseAddr;
	modinfo.size = (size_t)module_info.modBaseSize;
	modinfo.end = (mem_voidptr_t)((uintptr_t)modinfo.base + modinfo.size);
	modinfo.handle = (mem_module_handle_t)module_info.hModule;
	modinfo.path = mem_string_new(module_info.szExePath);
	modinfo.name = mem_string_new(module_info.szModule);
	//modinfo.name = mem_string_substr(&modinfo.path, mem_string_rfind(&modinfo.path, MEM_STR("\\"), -1), -1);
#   elif defined(MEM_LINUX)
	char path_buffer[64];
	snprintf(path_buffer, sizeof(path_buffer), "/proc/%i/maps", process.pid);
	int fd = open(path_buffer, O_RDONLY);
	if (fd == -1) return modinfo;
	mem_string_t file_buffer = mem_string_init();
	mem_size_t   file_size = 0;
	int read_check = 0;
	for (char c; (read_check = read(fd, &c, 1)) != -1 && read_check != 0; file_size++)
	{
		mem_string_resize(&file_buffer, file_size);
		mem_string_c_set(&file_buffer, file_size, c);
	}

	mem_size_t module_name_pos = 0;
	mem_size_t module_name_end = 0;
	mem_size_t next = 0;
	mem_string_t module_name_str = mem_string_init();
	while ((next = mem_string_find(&file_buffer, mem_string_c_str(&module_name), module_name_end)) != file_buffer.npos && (module_name_pos = mem_string_find(&file_buffer, "/", next)) != file_buffer.npos)
	{
		module_name_end = mem_string_find(&file_buffer, "\n", module_name_pos);
		module_name_pos = mem_string_rfind(&file_buffer, "/", module_name_end) + 1;
		module_name_str = mem_string_substr(&file_buffer, module_name_pos, module_name_end);
		if (mem_string_length(&module_name_str) >= mem_string_length(&module_name))
		{
			if (!MEM_STR_N_CMP(mem_string_c_str(&module_name_str), mem_string_c_str(&module_name), mem_string_length(&module_name)))
				break;
		}
	}

	if (module_name_pos == 0 || module_name_end == 0 || module_name_pos == file_buffer.npos || module_name_end == file_buffer.npos) return modinfo;
	mem_size_t module_name_str_match_size = mem_string_length(&module_name_str) + 2;
	mem_char_t* module_name_str_match = (mem_char_t*)malloc(module_name_str_match_size);
	module_name_str_match[0] = '/';
	memcpy((void*)(module_name_str_match + 1), (void*)mem_string_c_str(&module_name_str), module_name_str_match_size - 2);
	module_name_str_match[module_name_str_match_size - 1] = '\n';
	module_name_str_match[module_name_str_match_size] = '\0';

	mem_size_t   base_address_pos = mem_string_rfind(&file_buffer, "\n", mem_string_find(&file_buffer, module_name_str_match, 0)) + 1;
	if (!MEM_STR_CMP(mem_string_c_str(&module_name_str), mem_string_c_str(&process.name)) || base_address_pos > (mem_size_t)-256) base_address_pos = 0;
	mem_size_t   base_address_end = mem_string_find(&file_buffer, "-", base_address_pos);
	if (base_address_pos == file_buffer.npos || base_address_end == file_buffer.npos) return modinfo;
	mem_string_t base_address_str = mem_string_substr(&file_buffer, base_address_pos, base_address_end);

	mem_size_t   end_address_pos = mem_string_rfind(&file_buffer, "\n", mem_string_rfind(&file_buffer, module_name_str_match, mem_string_length(&file_buffer)));
	end_address_pos = mem_string_find(&file_buffer, "-", end_address_pos) + 1;
	mem_size_t   end_address_end = mem_string_find(&file_buffer, " ", end_address_pos);
	if (end_address_pos == file_buffer.npos || end_address_end == file_buffer.npos) return modinfo;
	mem_string_t end_address_str = mem_string_substr(&file_buffer, end_address_pos, end_address_end);

	mem_size_t   module_path_pos = mem_string_find(&file_buffer, "/", end_address_end);
	mem_size_t   module_path_end = mem_string_find(&file_buffer, "\n", module_path_pos);
	if (module_path_pos == 0 || module_path_end == 0 || module_path_pos == file_buffer.npos || module_path_end == file_buffer.npos) return modinfo;
	mem_string_t module_path_str = mem_string_substr(&file_buffer, module_path_pos, module_path_end);

	mem_uintptr_t base_address = (mem_uintptr_t)MEM_BAD_RETURN;
	mem_uintptr_t end_address = (mem_uintptr_t)MEM_BAD_RETURN;

#   if defined(MEM_86)
	base_address = strtoul(mem_string_c_str(&base_address_str), NULL, 16);
	end_address = strtoul(mem_string_c_str(&end_address_str), NULL, 16);
#   elif defined(MEM_64)
	base_address = strtoul(mem_string_c_str(&base_address_str), NULL, 16);
	end_address = strtoul(mem_string_c_str(&end_address_str), NULL, 16);
#   endif

	mem_module_handle_t handle = (mem_module_handle_t)MEM_BAD_RETURN;
    /*
	if (MEM_STR_CMP(mem_string_c_str(&process.name), mem_string_c_str(&module_name_str)))
		handle = (mem_module_handle_t)dlopen(mem_string_c_str(&module_path_str), RTLD_LAZY);
    */

	modinfo.name   = module_name_str;
	modinfo.base   = (mem_voidptr_t)base_address;
	modinfo.end    = (mem_voidptr_t)end_address;
	modinfo.size   = end_address - base_address;
	modinfo.path   = module_path_str;
	modinfo.handle = handle;

	free(module_name_str_match);
	mem_string_free(&end_address_str);
	mem_string_free(&base_address_str);
	mem_string_free(&file_buffer);
	close(fd);

#   endif
	return modinfo;
}

mem_module_t mem_ex_get_module2(mem_process_t process, mem_char_t*  module_name)
{
    mem_string_t module_name_str = mem_string_new(module_name);
    mem_module_t mod = mem_ex_get_module(process, module_name_str);
    mem_string_free(&module_name_str);
    return mod;
}

mem_module_list_t mem_ex_get_module_list(mem_process_t process)
{
	mem_module_list_t mod_list = mem_module_list_init();

#	if defined(MEM_WIN)
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process.pid);
	if(hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(MODULEENTRY32);

		if(Module32First(hSnap, &modEntry))
		{
			do
			{
				mem_module_t modinfo = mem_module_init();
				mem_module_free(&modinfo);
				modinfo.base = (mem_voidptr_t)modEntry.modBaseAddr;
				modinfo.size = (mem_uintptr_t)modEntry.modBaseSize;
				modinfo.end  = (mem_voidptr_t)((mem_uintptr_t)modinfo.base + modinfo.size);
				modinfo.name = mem_string_new(modEntry.szModule);
				modinfo.path = mem_string_new(modEntry.szExePath);
				modinfo.handle = modEntry.hModule;

				mem_module_list_append(&mod_list, modinfo);
			} while(Module32Next(hSnap, &modEntry));
		}
	}

	CloseHandle(hSnap);
#	elif defined(MEM_LINUX)
	char path_buffer[64];
	snprintf(path_buffer, sizeof(path_buffer), "/proc/%i/maps", process.pid);
	int fd = open(path_buffer, O_RDONLY);
	if (fd == -1) return mod_list;
	mem_string_t file_buffer = mem_string_init();
	mem_size_t   file_size = 0;
	int read_check = 0;
	for (char c; (read_check = read(fd, &c, 1)) != -1 && read_check != 0; file_size++)
	{
		mem_string_resize(&file_buffer, file_size);
		mem_string_c_set(&file_buffer, file_size, c);
	}

	mem_size_t module_path_pos = 0;
	mem_size_t module_path_end = 0;
	mem_size_t next = 0;
	while((module_path_pos = mem_string_find(&file_buffer, "/", next)) && module_path_pos != (mem_size_t)MEM_BAD_RETURN && module_path_pos != file_buffer.npos)
	{
		module_path_end = mem_string_find(&file_buffer, "\n", module_path_pos);
		mem_string_t module_path_str = mem_string_substr(&file_buffer, module_path_pos, module_path_end);

		mem_size_t module_name_pos = mem_string_rfind(&file_buffer, "/", module_path_end) + 1;
		mem_size_t module_name_end = module_path_end;
		mem_string_t module_name_str = mem_string_substr(&file_buffer, module_name_pos, module_name_end);

		mem_size_t base_address_pos = mem_string_rfind(&file_buffer, "\n", module_path_pos) + 1;
		mem_size_t base_address_end = mem_string_find(&file_buffer, "-", base_address_pos);
		mem_string_t base_address_str = mem_string_substr(&file_buffer, base_address_pos, base_address_end);

		mem_size_t   end_address_pos = mem_string_rfind(&file_buffer, "\n", mem_string_rfind(&file_buffer, mem_string_c_str(&module_path_str), -1));
		end_address_pos = mem_string_find(&file_buffer, "-", end_address_pos) + 1;
		mem_size_t   end_address_end = mem_string_find(&file_buffer, " ", end_address_pos);
		mem_string_t end_address_str = mem_string_substr(&file_buffer, end_address_pos, end_address_end);

		mem_uintptr_t base_address = (mem_uintptr_t)MEM_BAD_RETURN;
		mem_uintptr_t end_address = (mem_uintptr_t)MEM_BAD_RETURN;

#		if defined(MEM_86)
		base_address = strtoul(mem_string_c_str(&base_address_str), NULL, 16);
		end_address = strtoul(mem_string_c_str(&end_address_str), NULL, 16);
#   	elif defined(MEM_64)
		base_address = strtoul(mem_string_c_str(&base_address_str), NULL, 16);
		end_address = strtoul(mem_string_c_str(&end_address_str), NULL, 16);
#   	endif

		mem_module_handle_t handle = (mem_module_handle_t)MEM_BAD_RETURN;
		
		/*
		if (MEM_STR_CMP(mem_string_c_str(&process.name), mem_string_c_str(&module_name_str)))
			handle = (mem_module_handle_t)dlopen(mem_string_c_str(&module_path_str), RTLD_LAZY);
		*/

		mem_module_t modinfo = mem_module_init();
		mem_module_free(&modinfo);
		modinfo.name = module_name_str;
		modinfo.path = module_path_str;
		modinfo.base = (mem_voidptr_t)base_address;
		modinfo.end = (mem_voidptr_t)end_address;
		modinfo.size = end_address - base_address;
		modinfo.handle = handle;

		mem_module_list_append(&mod_list, modinfo);

		next = mem_string_find(&file_buffer, "\n", end_address_end);

		if(next == (mem_size_t)MEM_BAD_RETURN || next == file_buffer.npos) break;

	}

	mem_string_free(&file_buffer);
	close(fd);

#	endif

	return mod_list;
}

mem_page_t mem_ex_get_page(mem_process_t process, mem_voidptr_t src)
{
    mem_page_t    page = mem_page_init();
    mem_uintptr_t page_size  = mem_get_page_size();
    mem_voidptr_t page_base  = (mem_voidptr_t)((mem_intptr_t)src & -(mem_intptr_t)page_size);
    mem_voidptr_t page_end   = (mem_voidptr_t)((mem_uintptr_t)page_base + page_size);
    mem_flags_t   page_flags = 0;
    mem_prot_t    page_prot  = 0;

#   if defined(MEM_WIN)
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQueryEx(process.handle, src, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	page_base = mbi.BaseAddress;
	page_size = mbi.RegionSize;
	page_end = (mem_voidptr_t)((mem_uintptr_t)page_base + page_size);
	page_prot = mbi.Protect;
	page_flags = mbi.Type;
#   elif defined(MEM_LINUX)

    mem_char_t page_base_str[64];
    mem_size_t page_base_pos = (mem_size_t)MEM_BAD_RETURN;
#   if defined(MEM_86)
    snprintf(page_base_str, sizeof(page_base_str), "%x-", (mem_uintptr_t)page_base);
#   elif defined(MEM_64)
    snprintf(page_base_str, sizeof(page_base_str), "%llx-", (mem_uintptr_t)page_base);
#   endif

    char path_buffer[64];
	snprintf(path_buffer, sizeof(path_buffer), "/proc/%i/maps", process.pid);
	int fd = open(path_buffer, O_RDONLY);
	if (fd == -1) return page;
	mem_string_t file_buffer = mem_string_init();
	mem_size_t   file_size = 0;
	int read_check = 0;
	mem_uintptr_t virt_start = (mem_uintptr_t)MEM_BAD_RETURN;
	for (char c; (read_check = read(fd, &c, 1)) != -1 && read_check != 0; file_size++)
	{
		mem_string_resize(&file_buffer, file_size);
		mem_string_c_set(&file_buffer, file_size, c);
		if(c == '-' && virt_start == (mem_uintptr_t)MEM_BAD_RETURN)
		{
			mem_string_t virt_start_str = mem_string_substr(&file_buffer, 0, file_size);
#			if defined(MEM_86)
			virt_start = (mem_uintptr_t)strtoul(mem_string_c_str(&virt_start_str), NULL, 16);
#			elif defined(MEM_64)
			virt_start = (mem_uintptr_t)strtoull(mem_string_c_str(&virt_start_str), NULL, 16);
#			endif

			if((mem_uintptr_t)src < virt_start) return page;
		}

        if(c == '\n' && (page_base_pos = mem_string_find(&file_buffer, page_base_str, 0), page_base_pos != file_buffer.npos && page_base_pos != (mem_size_t)MEM_BAD_RETURN)) break;
	}


    if(page_base_pos == (mem_size_t)MEM_BAD_RETURN || page_base_pos == file_buffer.npos) return page;

    mem_size_t start = mem_string_find(&file_buffer, " ", page_base_pos) + 1;
    mem_size_t end   = start + 4;

    for(mem_size_t i = start; i < end; i++)
    {
        mem_char_t c = mem_string_at(&file_buffer, i);

        switch(c)
        {
            case 'r':
            page_prot |= PROT_READ;
            break;

            case 'w':
            page_prot |= PROT_WRITE;
            break;

            case 'x':
            page_prot |= PROT_EXEC;
            break;

            case 'p':
            page_flags = MAP_PRIVATE;
            break;

            case 's':
            page_flags = MAP_SHARED;
            break;
        }
    }


#   endif

    page.base = page_base;
    page.size = page_size;
    page.end  = page_end;
    page.protection = page_prot;
    page.flags = page_flags;

    return page;
}

mem_bool_t mem_ex_is_process_running(mem_process_t process)
{
	mem_bool_t ret = mem_false;
	if (!mem_process_is_valid(&process)) return ret;
#   if defined(MEM_WIN)
	DWORD exit_code;
	GetExitCodeProcess(process.handle, &exit_code);
	ret = (mem_bool_t)(exit_code == STILL_ACTIVE);
#   elif defined(MEM_LINUX)
	struct stat sb;
	char path_buffer[64];
	snprintf(path_buffer, sizeof(path_buffer), "/proc/%i", process.pid);
	stat(path_buffer, &sb);
	ret = (mem_bool_t)S_ISDIR(sb.st_mode);
#   endif

	return ret;
}

mem_int_t mem_ex_read(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size)
{
	mem_int_t ret = (mem_int_t)MEM_BAD_RETURN;
	if (!mem_process_is_valid(&process)) return ret;
#   if defined(MEM_WIN)
	ret = (mem_int_t)(ReadProcessMemory(process.handle, (LPCVOID)src, (LPVOID)dst, (SIZE_T)size, NULL) != 0 ? !MEM_BAD_RETURN : MEM_BAD_RETURN);
#   elif defined(MEM_LINUX)
	struct iovec iosrc;
	struct iovec iodst;
	iodst.iov_base = dst;
	iodst.iov_len = size;
	iosrc.iov_base = src;
	iosrc.iov_len = size;
	ret = (mem_int_t)((mem_size_t)process_vm_readv(process.pid, &iodst, 1, &iosrc, 1, 0) == size ? !MEM_BAD_RETURN : MEM_BAD_RETURN);
#   endif

	return ret;
}

mem_int_t mem_ex_write(mem_process_t process, mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size)
{
	mem_int_t ret = (mem_int_t)MEM_BAD_RETURN;
	if (!mem_process_is_valid(&process)) return ret;
#   if defined(MEM_WIN)
	ret = (mem_int_t)(WriteProcessMemory(process.handle, (LPVOID)dst, (LPCVOID)src, (SIZE_T)size, NULL) != 0 ? !MEM_BAD_RETURN : MEM_BAD_RETURN);
#   elif defined(MEM_LINUX)
	struct iovec iosrc;
	struct iovec iodst;
	iosrc.iov_base = src;
	iosrc.iov_len = size;
	iodst.iov_base = dst;
	iodst.iov_len = size;
	ret = (mem_int_t)((mem_size_t)process_vm_writev(process.pid, &iosrc, 1, &iodst, 1, 0) == size ? !MEM_BAD_RETURN : MEM_BAD_RETURN);
#   endif

	return ret;
}

mem_int_t mem_ex_set(mem_process_t process, mem_voidptr_t dst, mem_byte_t byte, mem_size_t size)
{
	mem_int_t ret = (mem_int_t)MEM_BAD_RETURN;
	if (!mem_process_is_valid(&process)) return ret;
	mem_byte_t* data = (mem_byte_t*)malloc(size);
	if (data == 0) return ret;
	memset((void*)data, (int)byte, (size_t)size);
	ret = mem_ex_write(process, dst, data, size);
	free(data);
	return ret;
}

mem_voidptr_t mem_ex_syscall(mem_process_t process, mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5)
{
    mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD_RETURN;
    if(!mem_process_is_valid(&process)) return ret;
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)

    int status;
    struct user_regs_struct old_regs, regs;
    mem_voidptr_t injection_addr = (mem_voidptr_t)MEM_BAD_RETURN;
    mem_byte_t injection_buf[] =
    {
#       if defined(MEM_86)
        0xcd, 0x80, //int80 (syscall)
#       elif defined(MEM_64)
        0x0f, 0x05, //syscall
#       endif
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90  //nop
    };

    mem_uintptr_t old_data;
	mem_uintptr_t injection_buffer;
	memcpy(&injection_buffer, injection_buf, sizeof(injection_buffer));
    ptrace(PTRACE_ATTACH, process.pid, NULL, NULL);
    wait(&status);

    ptrace(PTRACE_GETREGS, process.pid, NULL, &old_regs);
    regs = old_regs;

#   if defined(MEM_86)
    regs.eax = (mem_uintptr_t)syscall_n;
    regs.ebx = (mem_uintptr_t)arg0;
    regs.ecx = (mem_uintptr_t)arg1;
    regs.edx = (mem_uintptr_t)arg2;
    regs.esi = (mem_uintptr_t)arg3;
    regs.edi = (mem_uintptr_t)arg4;
    regs.ebp = (mem_uintptr_t)arg5;
    injection_addr = (mem_voidptr_t)regs.eip;
#   elif defined(MEM_64)
    regs.rax = (mem_uintptr_t)syscall_n;
    regs.rdi = (mem_uintptr_t)arg0;
    regs.rsi = (mem_uintptr_t)arg1;
    regs.rdx = (mem_uintptr_t)arg2;
    regs.r10 = (mem_uintptr_t)arg3;
    regs.r8  = (mem_uintptr_t)arg4;
    regs.r9  = (mem_uintptr_t)arg5;
    injection_addr = (mem_voidptr_t)regs.rip;
#   endif

	old_data = (mem_uintptr_t)ptrace(PTRACE_PEEKDATA, process.pid, (void*)((mem_uintptr_t)injection_addr), NULL);
	ptrace(PTRACE_POKEDATA, process.pid, (void*)((mem_uintptr_t)injection_addr), (injection_buffer));

    ptrace(PTRACE_SETREGS, process.pid, NULL, &regs);
    ptrace(PTRACE_SINGLESTEP, process.pid, NULL, NULL);
    waitpid(process.pid, &status, WSTOPPED);
    ptrace(PTRACE_GETREGS, process.pid, NULL, &regs);
#   if defined(MEM_86)
    ret = (mem_voidptr_t)regs.eax;
#   elif defined(MEM_64)
    ret = (mem_voidptr_t)regs.rax;
#   endif

	ptrace(PTRACE_POKEDATA, process.pid, (void*)((mem_uintptr_t)injection_addr), (old_data));

    ptrace(PTRACE_SETREGS, process.pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, process.pid, NULL, NULL);
#   endif
    return ret;
}

mem_int_t mem_ex_protect(mem_process_t process, mem_voidptr_t src, mem_size_t size, mem_prot_t protection)
{
	mem_int_t ret = (mem_int_t)MEM_BAD_RETURN;
	if (!mem_process_is_valid(&process)) return ret;
#	if defined(MEM_WIN)
	DWORD old_protect;
	if (process.handle == (HANDLE)INVALID_HANDLE_VALUE || src <= (mem_voidptr_t)NULL || size == 0 || protection <= 0) return ret;
	ret = (mem_int_t)(VirtualProtectEx(process.handle, (LPVOID)src, (SIZE_T)size, (DWORD)protection, &old_protect) != 0 ? !MEM_BAD_RETURN : MEM_BAD_RETURN);
#	elif defined(MEM_LINUX)
	ret = (mem_int_t)(mem_ex_syscall(process, __NR_mprotect, src, (mem_voidptr_t)size, (mem_voidptr_t)(mem_uintptr_t)protection, NULL, NULL, NULL) == 0 ? !MEM_BAD_RETURN : MEM_BAD_RETURN);
#	endif
	return ret;
}

mem_voidptr_t mem_ex_allocate(mem_process_t process, mem_size_t size, mem_prot_t protection)
{
	mem_voidptr_t alloc_addr = (mem_voidptr_t)MEM_BAD_RETURN;
	if (!mem_process_is_valid(&process) || protection == 0) return alloc_addr;
#   if defined(MEM_WIN)
	alloc_addr = (mem_voidptr_t)VirtualAllocEx(process.handle, NULL, size, MEM_COMMIT | MEM_RESERVE, protection);
#   elif defined(MEM_LINUX)
    mem_int_t syscall_n = -1;
    
#   if defined(MEM_86)
    syscall_n = __NR_mmap2;
#   elif defined(MEM_64)
    syscall_n = __NR_mmap;
#   endif

	alloc_addr = (mem_voidptr_t)(mem_ex_syscall(process, syscall_n, (mem_voidptr_t)0, (mem_voidptr_t)size, (mem_voidptr_t)(mem_uintptr_t)protection, (mem_voidptr_t)(MAP_PRIVATE | MAP_ANON), (mem_voidptr_t)-1, (mem_voidptr_t)0));
	if((mem_uintptr_t)alloc_addr >= (mem_uintptr_t)-100) //error check
	{
		alloc_addr = (mem_voidptr_t)MEM_BAD_RETURN;
	}

#   endif
	return alloc_addr;
}

mem_int_t mem_ex_deallocate(mem_process_t process, mem_voidptr_t src, mem_size_t size)
{
	mem_int_t ret = MEM_BAD_RETURN;
	if (!mem_process_is_valid(&process)) return ret;
#   if defined(MEM_WIN)
	ret = (mem_int_t)(VirtualFreeEx(process.handle, src, 0, MEM_RELEASE) != 0 ? !MEM_BAD_RETURN : MEM_BAD_RETURN);
#   elif defined(MEM_LINUX)
	ret = (mem_int_t)(mem_ex_syscall(process, __NR_munmap, src, (mem_voidptr_t)size, NULL, NULL, NULL, NULL) != MAP_FAILED ? !MEM_BAD_RETURN : MEM_BAD_RETURN);
#   endif

	return ret;
}

mem_voidptr_t mem_ex_scan(mem_process_t process, mem_byte_t* data, mem_voidptr_t begin, mem_voidptr_t end, mem_size_t size)
{
	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD_RETURN;
	mem_byte_t* buffer = (mem_byte_t*)malloc(size);
	for (mem_uintptr_t i = 0; (mem_uintptr_t)begin + i + size< (mem_uintptr_t)end; i++)
	{
		if (
			mem_ex_read(process, (mem_voidptr_t)((mem_uintptr_t)begin + i), buffer, size) != MEM_BAD_RETURN && 
			mem_in_compare(data, (mem_voidptr_t)buffer, size)
		)
		{
			ret = (mem_voidptr_t)((mem_uintptr_t)begin + i);
			break;
		}
	}

	free(buffer);

	return ret;
}

mem_voidptr_t mem_ex_pattern_scan(mem_process_t process, mem_byte_t* pattern, mem_string_t mask, mem_voidptr_t begin, mem_voidptr_t end)
{
	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD_RETURN;
	if (!mem_process_is_valid(&process) || (mem_uintptr_t)begin > (mem_uintptr_t)end) return ret;
	mask = mem_parse_mask(mask);
	mem_size_t pattern_size = mem_string_length(&mask);
	mem_uintptr_t page_size = mem_get_page_size();
	mem_byte_t* page = (mem_byte_t*)malloc(page_size);

	for(mem_uintptr_t i = (mem_uintptr_t)((mem_uintptr_t)begin & -(mem_intptr_t)page_size); i < (mem_uintptr_t)end + page_size; i += page_size)
	{
		if(mem_ex_read(process, (mem_voidptr_t)i, page, page_size) == MEM_BAD_RETURN) continue;

		for(mem_uintptr_t j = 0; i + j >= (mem_uintptr_t)begin && i + j < (mem_uintptr_t)end && j + pattern_size < page_size; j++)
		{
			mem_int_t found = mem_true;

			for(mem_uintptr_t k = 0; k < pattern_size; k++)
			{
				found &= ((mem_byte_t)pattern[k] == page[j + k] || mem_string_at(&mask, k) == MEM_UNKNOWN_BYTE);

				if(!found) break;
			}

			if(found)
			{
				ret = (mem_voidptr_t)(i + j);
				break;
			}
		}
	}

	return ret;
}

mem_voidptr_t mem_ex_pattern_scan2(mem_process_t process, mem_byte_t* pattern, mem_char_t*  mask, mem_voidptr_t begin, mem_voidptr_t end)
{
    mem_string_t mask_str = mem_string_new(mask);
    mem_voidptr_t scan = mem_ex_pattern_scan(process, pattern, mask_str, begin, end);
    mem_string_free(&mask_str);
    return scan;
}

mem_int_t mem_ex_detour(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_byte_t** stolen_bytes)
{
	mem_int_t ret = (mem_int_t)MEM_BAD_RETURN;
	mem_size_t detour_size = mem_in_detour_length(method);
	mem_prot_t protection;
#	if defined(MEM_WIN)
	protection = PAGE_EXECUTE_READWRITE;
#	elif defined(MEM_LINUX)
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif
	if (!mem_process_is_valid(&process) || detour_size == (mem_size_t)MEM_BAD_RETURN || size < detour_size || mem_ex_protect(process, src, size, protection) == MEM_BAD_RETURN) return ret;

	mem_byte_t* detour_buffer = (mem_byte_t*)mem_in_allocate(detour_size, protection);
	mem_in_set(detour_buffer, 0x0, detour_size);
	mem_in_detour(detour_buffer, dst, size, method, NULL);
	if (stolen_bytes != NULL)
	{
		mem_ex_read(process, src, (mem_voidptr_t)stolen_bytes, size);
	}

	mem_ex_write(process, src, detour_buffer, detour_size);

	ret = (mem_int_t)MEM_RETURN;
	return ret;
}

mem_voidptr_t mem_ex_detour_trampoline(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_byte_t** stolen_bytes)
{
	mem_voidptr_t gateway = (mem_voidptr_t)MEM_BAD_RETURN;
	mem_size_t detour_size = mem_in_detour_length(method);
	mem_prot_t protection;
#   if defined(MEM_WIN)
	protection = PAGE_EXECUTE_READWRITE;
#   elif defined(MEM_LINUX)
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;;
#   endif

	if (!mem_process_is_valid(&process) || detour_size == (mem_size_t)MEM_BAD_RETURN || size < detour_size || mem_in_protect(src, size, protection) == MEM_BAD_RETURN) return gateway;
	mem_size_t gateway_size = size + detour_size;
	gateway = mem_ex_allocate(process, gateway_size, protection);
	if (!gateway || gateway == (mem_voidptr_t)MEM_BAD_RETURN) return (mem_voidptr_t)MEM_BAD_RETURN;
	mem_ex_set(process, gateway, 0x0, gateway_size);
	mem_ex_write(process, gateway, src, size);
	mem_ex_detour(process, (mem_voidptr_t)((mem_uintptr_t)gateway + size), (mem_voidptr_t)((mem_uintptr_t)src + size), detour_size, method, NULL);
	mem_ex_detour(process, src, dst, size, method, stolen_bytes);

	return gateway;
}

mem_void_t mem_ex_detour_restore(mem_process_t process, mem_voidptr_t src, mem_byte_t* stolen_bytes, mem_size_t size)
{
	mem_prot_t protection;
#   if defined(MEM_WIN)
	protection = PAGE_EXECUTE_READWRITE;
#   elif defined(MEM_LINUX)
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#   endif
	if (mem_ex_protect(process, src, size, protection) != MEM_BAD_RETURN)
		mem_ex_write(process, src, (mem_voidptr_t)stolen_bytes, (mem_size_t)size);
}

mem_module_t mem_ex_load_library(mem_process_t process, mem_lib_t lib)
{
	mem_module_t mod = mem_module_init();
	if (!mem_process_is_valid(&process) || !mem_lib_is_valid(&lib)) return mod;
#   if defined(MEM_WIN)
	mem_size_t buffer_size = (mem_size_t)((mem_string_length(&lib.path) + 1) * sizeof(mem_char_t));
	mem_prot_t protection = PAGE_READWRITE;
	mem_voidptr_t libpath_ex = mem_ex_allocate(process, buffer_size, protection);
	if (!libpath_ex || libpath_ex == (mem_voidptr_t)-1) return mod;
	mem_ex_set(process, libpath_ex, 0x0, buffer_size);
	mem_ex_write(process, libpath_ex, (mem_voidptr_t)mem_string_c_str(&lib.path), buffer_size);
	HANDLE h_thread = (HANDLE)CreateRemoteThread(process.handle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, libpath_ex, 0, 0);
	if (!h_thread || h_thread == INVALID_HANDLE_VALUE) return mod;
	WaitForSingleObject(h_thread, -1);
	CloseHandle(h_thread);
	VirtualFreeEx(process.handle, libpath_ex, 0, MEM_RELEASE);
    mem_module_free(&ret);
	ret = mem_ex_get_module(process, lib.path);
#   elif defined(MEM_LINUX)

	mem_string_t libc_str = mem_string_new("/libc.");
    mem_module_t libc_ex;
    mem_bool_t   retry = mem_false;
    
    L_GET_LIBC_MOD:
    libc_ex = mem_ex_get_module(process, libc_str);
    mem_string_free(&libc_str);
    if(!mem_module_is_valid(&libc_ex))
    {
        if(!retry)
        {
            retry = mem_true;
            libc_str = mem_string_new("/libc-");
            goto L_GET_LIBC_MOD;
        }

        else
        {
            mem_module_free(&libc_ex);
            return mod;
        }
    }

    mem_lib_t libc_load = mem_lib_new(libc_ex.path, RTLD_LAZY);
    mem_module_t libc_in = mem_in_load_library(libc_load);
    if(!mem_module_is_valid(&libc_in))
    {
        mem_module_free(&libc_in);
        return mod;
    }

    mem_voidptr_t dlopen_ex = (mem_voidptr_t)(
        (mem_uintptr_t)libc_ex.base +
        (mem_uintptr_t)mem_in_get_symbol(libc_in, "__libc_dlopen_mode") - (mem_uintptr_t)libc_in.base
    );

    mem_module_free(&libc_in);
    mem_module_free(&libc_ex);

    //---

    mem_byte_t inj_buf[] =
    {
#       if defined(MEM_86)
        0x51,       //push ecx
        0x53,       //push ebx
        0xFF, 0xD0, //call eax
        0xCC,       //int3 (SIGTRAP)
#       elif defined(MEM_64)
        0xFF, 0xD0, //call rax
        0xCC,       //int3 (SIGTRAP)
#       endif
    };

    mem_size_t path_size = mem_string_size(&lib.path);
    mem_size_t inj_size  = sizeof(inj_buf) + path_size + 10;
    mem_voidptr_t inj_addr = mem_ex_allocate(process, inj_size, PROT_EXEC | PROT_READ | PROT_WRITE);
    if(inj_addr == (mem_voidptr_t)MEM_BAD_RETURN) return mod;
    mem_voidptr_t path_addr = (mem_voidptr_t)((mem_uintptr_t)inj_addr + sizeof(inj_buf));
    mem_ex_write(process, inj_addr, (mem_voidptr_t)inj_buf, sizeof(inj_buf));
    mem_ex_write(process, path_addr, (mem_voidptr_t)mem_string_c_str(&lib.path), path_size);

    int status;
    struct user_regs_struct old_regs, regs;
    mem_module_handle_t handle = (mem_voidptr_t)-1;

    ptrace(PTRACE_ATTACH, process.pid, NULL, NULL);
    wait(&status);
    ptrace(PTRACE_GETREGS, process.pid, NULL, &old_regs);

#   if defined(MEM_86)
    regs.eax = (mem_uintptr_t)dlopen_ex;
    regs.ebx = (mem_uintptr_t)path_addr;
    regs.ecx = (mem_uintptr_t)lib.mode;
    regs.eip = (mem_uintptr_t)inj_addr;
#   elif defined(MEM_64)
    regs.rax = (mem_uintptr_t)dlopen_ex;
    regs.rdi = (mem_uintptr_t)path_addr;
    regs.rsi = (mem_uintptr_t)lib.mode;
    regs.rip = (mem_uintptr_t)inj_addr;
#   endif

    ptrace(PTRACE_SETREGS, process.pid, NULL, &regs);
    ptrace(PTRACE_CONT, process.pid, NULL, NULL);
    waitpid(process.pid, &status, WSTOPPED);
    ptrace(PTRACE_GETREGS, process.pid, NULL, &regs);

#   if defined(MEM_86)
    handle = (mem_module_handle_t)regs.eax;
#   elif defined(MEM_64)
    handle = (mem_module_handle_t)regs.rax;
#   endif

    if(handle == (mem_module_handle_t)dlopen_ex || (mem_uintptr_t)handle > (mem_uintptr_t)-256)
        handle = (mem_module_handle_t)MEM_BAD_RETURN;

    ptrace(PTRACE_SETREGS, process.pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, process.pid, NULL, NULL);

    //---

    mem_ex_deallocate(process, inj_addr, inj_size);
    mem_module_free(&mod);
    mod = mem_ex_get_module(process, lib.path);
    mod.handle = handle;

#   endif
	return mod;
}

mem_voidptr_t mem_ex_get_symbol(mem_module_t mod, const char* symbol)
{
	mem_voidptr_t addr = (mem_voidptr_t)MEM_BAD_RETURN;
	if (!mem_module_is_valid(&mod)) return addr;
	mem_lib_t lib = mem_lib_init();
	mem_string_free(&lib.path);
	lib.path = mod.path;
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
	lib.mode = RTLD_LAZY;
#   endif

	mem_module_t mod_in;
	mod_in = mem_in_load_library(lib);
	if (!mem_module_is_valid(&mod_in)) return addr;
	mem_voidptr_t addr_in = mem_in_get_symbol(mod_in, symbol);
	if (!addr_in || addr_in == (mem_voidptr_t)MEM_BAD_RETURN) return addr;
	addr = (mem_voidptr_t)(
		(mem_uintptr_t)mod.base +
		((mem_uintptr_t)addr_in - (mem_uintptr_t)mod_in.base)
	);

	return addr;
}

//in

mem_pid_t mem_in_get_pid()
{
	mem_pid_t pid = (mem_pid_t)MEM_BAD_RETURN;
#   if defined(MEM_WIN)
	pid = (mem_pid_t)GetCurrentProcessId();
#   elif defined(MEM_LINUX)
	pid = (mem_pid_t)getpid();
#   endif
	return pid;
}

mem_process_t mem_in_get_process()
{
	mem_process_t process = mem_process_init();
	process.pid = mem_in_get_pid();
	process.name = mem_in_get_process_name();
#   if defined(MEM_WIN)
	process.handle = GetCurrentProcess();
#   elif defined(MEM_LINUX)
#   endif
	return process;
}

mem_string_t mem_in_get_process_name()
{
	mem_string_t process_name = mem_string_init();
#   if defined(MEM_WIN)
	mem_char_t buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, sizeof(buffer) / sizeof(mem_char_t));
	process_name = mem_string_new(buffer);
	process_name = mem_string_substr(&process_name, mem_string_rfind(&process_name, MEM_STR("\\"), mem_string_length(&process_name)) + 1, mem_string_length(&process_name));
#   elif defined(MEM_LINUX)
	process_name = mem_ex_get_process_name(mem_in_get_pid());
#   endif
	return process_name;
}

mem_module_t mem_in_get_module(mem_string_t module_name)
{
	mem_module_t modinfo = mem_module_init();
#   if defined(MEM_WIN)
	MODULEINFO module_info;
	HMODULE hmod = GetModuleHandle(mem_string_c_str(&module_name));
	HANDLE cur_handle = mem_in_get_process().handle;
	if (hmod == NULL) return modinfo;
	mem_char_t path_buffer[MAX_PATH];
	GetModuleInformation(cur_handle, hmod, &module_info, sizeof(module_info));
	GetModuleFileName(hmod, path_buffer, sizeof(path_buffer) / sizeof(mem_char_t));
	modinfo.path = mem_string_new(path_buffer);
	modinfo.name = mem_string_substr(&modinfo.path, mem_string_rfind(&modinfo.path, MEM_STR("\\"), -1) + 1, -1);
	modinfo.base = (mem_voidptr_t)module_info.lpBaseOfDll;
	modinfo.size = (mem_size_t)module_info.SizeOfImage;
	modinfo.end = (mem_voidptr_t)((uintptr_t)modinfo.base + modinfo.size);
	modinfo.handle = hmod;
#   elif defined(MEM_LINUX)
    mem_process_t process = mem_in_get_process();
	modinfo = mem_ex_get_module(process, module_name);
    mem_process_free(&process);
#   endif
	return modinfo;
}

mem_module_t mem_in_get_module2(mem_char_t* module_name)
{
    mem_string_t module_name_str = mem_string_new(module_name);
    mem_module_t mod = mem_in_get_module(module_name_str);
    mem_string_free(&module_name_str);
    return mod;
}

mem_module_list_t mem_in_get_module_list()
{
	return mem_ex_get_module_list(mem_in_get_process());
}

mem_page_t mem_in_get_page(mem_voidptr_t src)
{
    mem_page_t page = mem_page_init(); 
#   if defined(MEM_WIN)
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(src, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	page.base = mbi.BaseAddress;
	page.size = mbi.RegionSize;
	page.end = (mem_voidptr_t)((mem_uintptr_t)page.base + page.size);
	page.protection = mbi.Protect;
	page.flags = mbi.Type;
#   elif defined(MEM_LINUX)
    page = mem_ex_get_page(mem_in_get_process(), src);
#   endif
    return page;
}

mem_void_t mem_in_read(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size)
{
	memcpy(dst, src, size);
}

mem_void_t mem_in_write(mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size)
{
	memcpy(dst, src, size);
}

mem_void_t mem_in_set(mem_voidptr_t src, mem_byte_t byte, mem_size_t size)
{
	memset(src, byte, size);
}

mem_voidptr_t mem_in_syscall(mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5)
{
    mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD_RETURN;
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    ret = (mem_voidptr_t)syscall(syscall_n, arg0, arg1, arg2, arg3, arg4, arg5);
#   endif
    return ret;
}

mem_int_t mem_in_protect(mem_voidptr_t src, mem_size_t size, mem_prot_t protection)
{
	mem_int_t ret = (mem_int_t)MEM_BAD_RETURN;
	if (src == (mem_voidptr_t)MEM_BAD_RETURN || size == (mem_size_t)MEM_BAD_RETURN || size == 0 || protection == (mem_prot_t)MEM_BAD_RETURN) return ret;
#   if defined(MEM_WIN)
	mem_prot_t old_protection;
	ret = (mem_int_t)VirtualProtect((LPVOID)src, (SIZE_T)size, (DWORD)protection, &old_protection);
#   elif defined(MEM_LINUX)
	long pagesize = sysconf(_SC_PAGE_SIZE);
	mem_uintptr_t round = ((uintptr_t)src % pagesize);
	mem_uintptr_t src_page = (uintptr_t)src - round;
	ret = (mem_int_t)mprotect((void*)src_page, size + round, protection);
#   endif
	return ret;
}

mem_voidptr_t mem_in_allocate(mem_size_t size, mem_prot_t protection)
{
	mem_voidptr_t addr = (mem_voidptr_t)MEM_BAD_RETURN;
#   if defined(MEM_WIN)
	addr = (mem_voidptr_t)VirtualAlloc(NULL, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, protection);
#   elif defined(MEM_LINUX)
	addr = (mem_voidptr_t)mmap(NULL, size, protection, MAP_PRIVATE | MAP_ANON, -1, 0);
#   endif

	return addr;
}

mem_void_t mem_in_deallocate(mem_voidptr_t src, mem_size_t size)
{
	if (size == 0) return;
#   if defined(MEM_WIN)
	VirtualFree(src, 0, MEM_RELEASE);
#   elif defined(MEM_LINUX)
	munmap(src, size);
#   endif
}

mem_bool_t mem_in_compare(mem_voidptr_t pdata1, mem_voidptr_t pdata2, mem_size_t size)
{
	return (mem_bool_t)(memcmp(pdata1, pdata2, size) == 0);
}

mem_voidptr_t mem_in_scan(mem_voidptr_t data, mem_voidptr_t begin, mem_voidptr_t end, mem_size_t size)
{
	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD_RETURN;
	for (mem_uintptr_t i = 0; (mem_uintptr_t)begin + i + size < (mem_uintptr_t)end; i++)
	{
		if (mem_in_compare(data, (mem_voidptr_t)((mem_uintptr_t)begin + i), size))
		{
			ret = (mem_voidptr_t)((mem_uintptr_t)begin + i);
			break;
		}
	}

	return ret;
}

mem_voidptr_t mem_in_pattern_scan(mem_byte_t* pattern, mem_string_t mask, mem_voidptr_t begin, mem_voidptr_t end)
{
	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD_RETURN;
	mask = mem_parse_mask(mask);
	if((mem_uintptr_t)begin > (mem_uintptr_t)end) return ret;
	mem_size_t pattern_size = mem_string_length(&mask);

	for(mem_uintptr_t i = (mem_uintptr_t)begin; i + pattern_size < (mem_uintptr_t)end; i++)
	{
		mem_int_t found = mem_true;

		for(mem_uintptr_t j = 0; j < pattern_size; j++)
		{
			found &= ((mem_byte_t)pattern[j] == ((mem_byte_t*)i)[j] || mem_string_at(&mask, j) == MEM_UNKNOWN_BYTE);

			if(!found) break;
		}

		if(found)
		{
			ret = (mem_voidptr_t)i;
			break;
		}
	}

	return ret;
}

mem_voidptr_t mem_in_pattern_scan2(mem_byte_t* pattern, mem_char_t* mask, mem_voidptr_t begin, mem_voidptr_t end)
{
    mem_string_t mask_str = mem_string_new(mask);
    mem_voidptr_t scan = mem_in_pattern_scan(pattern, mask_str, begin, end);
    mem_string_free(&mask_str);
    return scan;
}

mem_size_t mem_in_detour_length(mem_detour_t method)
{
	mem_size_t ret = (mem_size_t)MEM_BAD_RETURN;
	switch (method)
	{
	case MEM_DT_M0: ret = CALC_ASM_LENGTH(_MEM_DETOUR_METHOD0); break;
	case MEM_DT_M1: ret = CALC_ASM_LENGTH(_MEM_DETOUR_METHOD1); break;
	case MEM_DT_M2: ret = CALC_ASM_LENGTH(_MEM_DETOUR_METHOD2); break;
	case MEM_DT_M3: ret = CALC_ASM_LENGTH(_MEM_DETOUR_METHOD3); break;
	case MEM_DT_M4: ret = CALC_ASM_LENGTH(_MEM_DETOUR_METHOD4); break;
	case MEM_DT_M5: ret = CALC_ASM_LENGTH(_MEM_DETOUR_METHOD5); break;
	}

	return ret;
}

mem_int_t mem_in_detour(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_byte_t** stolen_bytes)
{
	mem_int_t ret = (mem_int_t)MEM_BAD_RETURN;
	mem_size_t detour_size = mem_in_detour_length(method);
	mem_prot_t protection;
#	if defined(MEM_WIN)
	protection = PAGE_EXECUTE_READWRITE;
#	elif defined(MEM_LINUX)
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif
	if (detour_size == (mem_size_t)MEM_BAD_RETURN || size < detour_size || mem_in_protect(src, size, protection) == MEM_BAD_RETURN) return ret;

	if (stolen_bytes != NULL)
	{
		*stolen_bytes = (mem_byte_t*)malloc(size);
		mem_in_read(src, (mem_voidptr_t)*stolen_bytes, size);
	}

	switch (method)
	{
	case MEM_DT_M0:
	{
		mem_byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD0);
#		if defined(MEM_86)
		*(mem_uintptr_t*)((mem_uintptr_t)detour_buffer + 1) = (mem_uintptr_t)dst;
#		elif defined(MEM_64)
		*(mem_uintptr_t*)((mem_uintptr_t)detour_buffer + 2) = (mem_uintptr_t)dst;
#		endif
		mem_in_write(src, detour_buffer, sizeof(detour_buffer));
		break;
	}

	case MEM_DT_M1:
	{
		mem_byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD1);
		*(mem_dword_t*)((mem_uintptr_t)detour_buffer + 1) = (mem_dword_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		mem_in_write(src, detour_buffer, sizeof(detour_buffer));
		break;
	}

	case MEM_DT_M2:
	{
		mem_byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD2);
#		if defined(MEM_86)
		*(mem_uintptr_t*)((mem_uintptr_t)detour_buffer + 1) = (mem_uintptr_t)dst;
#		elif defined(MEM_64)
		*(mem_uintptr_t*)((mem_uintptr_t)detour_buffer + 2) = (mem_uintptr_t)dst;
#		endif
		mem_in_write(src, detour_buffer, sizeof(detour_buffer));
		break;
	}

	case MEM_DT_M3:
	{
		mem_byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD3);
		*(mem_dword_t*)((mem_uintptr_t)detour_buffer + 1) = (mem_dword_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		mem_in_write(src, detour_buffer, sizeof(detour_buffer));
		break;
	}

	case MEM_DT_M4:
	{
		mem_byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD4);
#		if defined(MEM_86)
		*(mem_uintptr_t*)((mem_uintptr_t)detour_buffer + 1) = (mem_uintptr_t)dst;
#		elif defined(MEM_64)
		*(mem_uintptr_t*)((mem_uintptr_t)detour_buffer + 2) = (mem_uintptr_t)dst;
#		endif
		mem_in_write(src, detour_buffer, sizeof(detour_buffer));
		break;
	}

	case MEM_DT_M5:
	{
		mem_byte_t detour_buffer[] = ASM_GENERATE(_MEM_DETOUR_METHOD5);
		*(mem_dword_t*)((mem_uintptr_t)detour_buffer + 1) = (mem_dword_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		mem_in_write(src, detour_buffer, sizeof(detour_buffer));
		break;
	}

	default:
	{
		return (mem_int_t)ret;
		break;
	}
	}

	ret = (mem_int_t)MEM_RETURN;
	return ret;
}

mem_voidptr_t mem_in_detour_trampoline(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_byte_t** stolen_bytes)
{
	mem_voidptr_t gateway = (mem_voidptr_t)MEM_BAD_RETURN;
	mem_size_t detour_size = mem_in_detour_length(method);
	mem_prot_t protection;
#   if defined(MEM_WIN)
	protection = PAGE_EXECUTE_READWRITE;
#   elif defined(MEM_LINUX)
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;;
#   endif

	if (detour_size == (mem_size_t)MEM_BAD_RETURN || size < detour_size || mem_in_protect(src, size, protection) == MEM_BAD_RETURN) return gateway;
	mem_size_t gateway_size = size + detour_size;
	gateway = mem_in_allocate(gateway_size, protection);
	if (!gateway || gateway == (mem_voidptr_t)MEM_BAD_RETURN) return (mem_voidptr_t)MEM_BAD_RETURN;
	mem_in_set(gateway, 0x0, gateway_size);
	mem_in_write(gateway, src, size);
	mem_in_detour((mem_voidptr_t)((mem_uintptr_t)gateway + size), (mem_voidptr_t)((mem_uintptr_t)src + size), detour_size, method, NULL);
	mem_in_detour(src, dst, size, method, stolen_bytes);

	return gateway;
}

mem_void_t mem_in_detour_restore(mem_voidptr_t src, mem_byte_t* stolen_bytes, mem_size_t size)
{
	mem_prot_t protection;
#   if defined(MEM_WIN)
	protection = PAGE_EXECUTE_READWRITE;
#   elif defined(MEM_LINUX)
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#   endif
	if (mem_in_protect(src, size, protection) != MEM_BAD_RETURN)
		mem_in_write(src, (mem_voidptr_t)stolen_bytes, (mem_size_t)size);
}

mem_module_t mem_in_load_library(mem_lib_t lib)
{
	mem_module_t mod = mem_module_init();
	if (!mem_lib_is_valid(&lib)) return mod;
    mem_module_free(&mod);
#   if defined(MEM_WIN)
	HMODULE h_mod = LoadLibrary(mem_string_c_str(&lib.path));
	mod = mem_in_get_module(mem_string_substr(&lib.path, mem_string_rfind(&lib.path, MEM_STR("\\"), mem_string_length(&lib.path)), mem_string_length(&lib.path)));
	mod.handle = h_mod;
#   elif defined(MEM_LINUX)
	void* h_mod = dlopen(mem_string_c_str(&lib.path), lib.mode);
	mod = mem_in_get_module(lib.path);
	mod.handle = h_mod;
#   endif

	return mod;
}

mem_void_t mem_in_unload_library(mem_module_t mod)
{
	if (!mem_module_is_valid(&mod)) return;

#   if defined(MEM_WIN)
	FreeLibrary(mod.handle);
#   elif defined(MEM_LINUX)
	dlclose(mod.handle);
#   endif
}

mem_voidptr_t mem_in_get_symbol(mem_module_t mod, const char* symbol)
{
	mem_voidptr_t addr = (mem_voidptr_t)MEM_BAD_RETURN;
	if (mem_module_is_valid(&mod) == mem_false)
		return addr;

#   if defined(MEM_WIN)
	addr = (mem_voidptr_t)GetProcAddress(mod.handle, symbol);
#   elif defined(MEM_LINUX)
	addr = (mem_voidptr_t)dlsym(mod.handle, symbol);
#   endif

	return addr;
}

#endif //MEM_COMPATIBLE