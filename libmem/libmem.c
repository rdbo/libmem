//Made by rdbo
//https://github.com/rdbo/libmem
//C-compatible version of https://github.com/rdbo/Memory

#include "libmem.h"
#if defined(MEM_COMPATIBLE)

//mem_string_t
struct _mem_string_t mem_string_init()
{
    struct _mem_string_t str;
    str.buffer = (char*)"";
    str.clear  = &mem_string_clear;
    str.size   = &mem_string_size;
    str.resize = &mem_string_resize;
    str.length = &mem_string_length;
    str.begin  = &mem_string_begin;
    str.end    = &mem_string_end;
    str.find   = &mem_string_find;
    str.str    = &mem_string_str;
    str.c_str  = &mem_string_c_str;
    str.substr = &mem_string_substr;
    str.is_initialized = mem_true;
    return str;
}

mem_void_t mem_string_clear(struct _mem_string_t* strptr)
{
    if(strptr->is_initialized == mem_false) return;
    memset((void*)strptr->buffer, (int)0x0, (size_t)mem_string_size(strptr));
}

mem_size_t mem_string_size(struct _mem_string_t* strptr)
{
    mem_size_t ret = (mem_size_t)MEM_BAD_RETURN;
    if(strptr->is_initialized)
    {
        ret = (mem_size_t)((mem_uintptr_t)mem_string_end(strptr) - (mem_uintptr_t)mem_string_begin(strptr));
    }

    return ret;
}

mem_void_t mem_string_resize(struct _mem_string_t* strptr, mem_size_t size)
{
    if(strptr->is_initialized != mem_true) return;
    size = size * sizeof(mem_char_t) + 1;
    mem_char_t* _buffer = (mem_char_t*)malloc(size);
    mem_size_t old_size = mem_string_size(strptr);
    memcpy((void*)_buffer, (void*)strptr->buffer, (size_t)(size > old_size ? old_size : size));
    _buffer[size - 1] = MEM_STR('\0');
    strptr->buffer = _buffer;
}

mem_size_t mem_string_length(struct _mem_string_t* strptr)
{
    return (strptr->is_initialized == mem_true ? MEM_STR_LEN(strptr->buffer) : MEM_BAD_RETURN);
}

mem_char_t* mem_string_begin(struct _mem_string_t* strptr)
{
    return (mem_char_t*)strptr->buffer;
}

mem_char_t* mem_string_end(struct _mem_string_t* strptr)
{
    return (mem_char_t*)((mem_uintptr_t)strptr->buffer + mem_string_length(strptr));
}

mem_size_t mem_string_find(struct _mem_string_t* strptr, const mem_char_t* substr)
{
    mem_size_t ret = (mem_size_t)MEM_BAD_RETURN;
    if(strptr->is_initialized != mem_true) return ret;
    mem_size_t str_len    = mem_string_length(strptr);
    mem_size_t substr_len = MEM_STR_LEN(substr);
    for(mem_size_t i = 0; i + substr_len <= str_len + 1; i++)
    {
        if(!MEM_STR_N_CMP(strptr->buffer + i, substr, substr_len))
        {
            ret = i;
            break;
        }
    }

    return ret;
}

mem_void_t mem_string_str(struct _mem_string_t* strptr, const mem_char_t* new_str)
{
    strptr->buffer = (mem_char_t*)new_str;
}

mem_char_t* mem_string_c_str(struct _mem_string_t* strptr)
{
    return strptr->buffer;
}

struct _mem_string_t mem_string_substr(struct _mem_string_t* strptr, mem_size_t start, mem_size_t end)
{
    struct _mem_string_t new_str = mem_string_init();
    mem_size_t size = end - start;
    if(end > start && mem_string_length(strptr) > size)
    {
        mem_size_t buffer_size = size * sizeof(mem_char_t) + 1;
        mem_char_t* _buffer = (mem_char_t*)malloc(buffer_size);
        memcpy((void*)_buffer, (void*)((mem_uintptr_t)strptr->buffer + start), (size_t)size);
        _buffer[buffer_size - 1] = MEM_STR('\0');
        new_str.buffer = _buffer;
    }

    return new_str;
}

#endif //MEM_COMPATIBLE