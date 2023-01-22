/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2022    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <libmem/libmem.h>
#include <Python.h>
#include <structmember.h>
#include "types.h"

/* make sure that 'pymod' and 'global' are declared before using DECL_GLOBAL_* */
#define DECL_GLOBAL_LONG(var) { \
	global = (PyObject *)PyLong_FromLong((long)var); \
	PyObject_SetAttrString(pymod, #var, global); \
	Py_DECREF(global); \
}

#define DECL_GLOBAL_PROT(var) { \
	global = PyObject_CallFunction((PyObject *)&py_lm_prot_t, "i", var); \
	PyObject_SetAttrString(pymod, #var, global); \
	Py_DECREF(global); \
}

static lm_bool_t
_py_LM_EnumProcessesCallback(lm_process_t *pproc,
			     lm_void_t    *arg)
{
	PyObject *pylist = (PyObject *)arg;
	py_lm_process_obj *pyproc;

	pyproc = (py_lm_process_obj *)PyObject_CallObject((PyObject *)&py_lm_process_t, NULL);
	pyproc->proc = *pproc;

	PyList_Append(pylist, (PyObject *)pyproc);

	return LM_TRUE;
}

static PyObject *
py_LM_EnumProcesses(PyObject *self,
		    PyObject *args)
{
	PyObject *pylist = PyList_New(0);
	if (!pylist)
		return NULL;

	if (!LM_EnumProcesses(_py_LM_EnumProcessesCallback, (lm_void_t *)pylist)) {
		Py_DECREF(pylist); /* destroy list */
		pylist = Py_BuildValue("");
	}

	return pylist;
}

/****************************************/

static PyObject *
py_LM_GetProcess(PyObject *self,
		 PyObject *args)
{
	lm_process_t proc;
	py_lm_process_obj *pyproc;

	if (!LM_GetProcess(&proc))
		return Py_BuildValue("");

	pyproc = (py_lm_process_obj *)PyObject_CallObject((PyObject *)&py_lm_process_t, NULL);
	pyproc->proc = proc;

	return (PyObject *)pyproc;
}

/****************************************/

static PyObject *
py_LM_GetProcessEx(PyObject *self,
		   PyObject *args)
{
	lm_pid_t pid;
	lm_process_t proc;
	py_lm_process_obj *pyproc;

	if (!PyArg_ParseTuple(args, "i", &pid))
		return NULL;

	if (!LM_GetProcessEx(pid, &proc))
		return Py_BuildValue("");

	pyproc = (py_lm_process_obj *)PyObject_CallObject((PyObject *)&py_lm_process_t, NULL);
	pyproc->proc = proc;

	return (PyObject *)pyproc;
}

/****************************************/

static PyObject *
py_LM_FindProcess(PyObject *self,
		  PyObject *args)
{
	lm_char_t         *procstr;
	lm_process_t       proc;
	py_lm_process_obj *pyproc;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "u", &procstr))
			return NULL;
#	else
	if (!PyArg_ParseTuple(args, "s", &procstr))
		return NULL;
#	endif

	if (!LM_FindProcess(procstr, &proc))
		return Py_BuildValue("");

	pyproc = (py_lm_process_obj *)PyObject_CallObject((PyObject *)&py_lm_process_t, NULL);
	pyproc->proc = proc;

	return (PyObject *)pyproc;
}

/****************************************/

static PyObject *
py_LM_IsProcessAlive(PyObject *self,
		     PyObject *args)
{
	py_lm_process_obj *pyproc;

	if (!PyArg_ParseTuple(args, "O", &pyproc))
		return NULL;

	if (LM_IsProcessAlive(&pyproc->proc))
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

/****************************************/

static PyObject *
py_LM_GetSystemBits(PyObject *self,
		    PyObject *args)
{
	return PyLong_FromSize_t(LM_GetSystemBits());
}

/****************************************/

static lm_bool_t
_py_LM_EnumThreadsCallback(lm_thread_t *pthr,
			   lm_void_t   *arg)
{
	PyObject *pylist = (PyObject *)arg;
	py_lm_thread_obj *pythread;

	pythread = (py_lm_thread_obj *)PyObject_CallObject((PyObject *)&py_lm_thread_t, NULL);
	pythread->thread = *pthr;

	PyList_Append(pylist, (PyObject *)pythread);

	return LM_TRUE;
}

static PyObject *
py_LM_EnumThreads(PyObject *self,
		  PyObject *args)
{
	PyObject *pylist = PyList_New(0);
	if (!pylist)
		return NULL;

	if (!LM_EnumThreads(_py_LM_EnumThreadsCallback, (lm_void_t *)pylist)) {
		Py_DECREF(pylist); /* destroy list */
		pylist = Py_BuildValue("");
	}

	return pylist;
}

/****************************************/

static PyObject *
py_LM_EnumThreadsEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	PyObject *pylist;

	if (!PyArg_ParseTuple(args, "O", &pyproc))
		return NULL;

	pylist = PyList_New(0);
	if (!pylist)
		return NULL;

	if (!LM_EnumThreadsEx(&pyproc->proc, _py_LM_EnumThreadsCallback, (lm_void_t *)pylist)) {
		Py_DECREF(pylist); /* destroy list */
		pylist = Py_BuildValue("");
	}

	return pylist;
}

/****************************************/

static PyObject *
py_LM_GetThread(PyObject *self,
		PyObject *args)
{
	lm_thread_t thread;
	py_lm_thread_obj *pythread;

	if (!LM_GetThread(&thread))
		return Py_BuildValue("");

	pythread = (py_lm_thread_obj *)PyObject_CallObject((PyObject *)&py_lm_thread_t, NULL);
	pythread->thread = thread;

	return (PyObject *)pythread;
}

/****************************************/

static PyObject *
py_LM_GetThreadEx(PyObject *self,
		  PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_thread_t thread;
	py_lm_thread_obj *pythread;

	if (!PyArg_ParseTuple(args, "O", &pyproc))
		return NULL;

	if (!LM_GetThreadEx(&pyproc->proc, &thread))
		return Py_BuildValue("");

	pythread = (py_lm_thread_obj *)PyObject_CallObject((PyObject *)&py_lm_thread_t, NULL);
	pythread->thread = thread;

	return (PyObject *)pythread;
}

/****************************************/

static PyObject *
py_LM_GetThreadProcess(PyObject *self,
		       PyObject *args)
{
	py_lm_thread_obj *pythread;
	lm_process_t proc;
	py_lm_process_obj *pyproc;

	if (!PyArg_ParseTuple(args, "O", &pythread))
		return NULL;

	if (!LM_GetThreadProcess(&pythread->thread, &proc))
		return Py_BuildValue("");

	pyproc = (py_lm_process_obj *)PyObject_CallObject((PyObject *)&py_lm_process_t, NULL);
	pyproc->proc = proc;

	return (PyObject *)pyproc;
}

/****************************************/

static lm_bool_t
_py_LM_EnumModulesCallback(lm_module_t *pmod,
			   lm_void_t   *arg)
{
	PyObject *pylist = (PyObject *)arg;
	py_lm_module_obj *pymodule;

	pymodule = (py_lm_module_obj *)PyObject_CallObject((PyObject *)&py_lm_module_t, NULL);
	pymodule->mod = *pmod;

	PyList_Append(pylist, (PyObject *)pymodule);

	return LM_TRUE;
}

static PyObject *
py_LM_EnumModules(PyObject *self,
		  PyObject *args)
{
	PyObject *pylist = PyList_New(0);
	if (!pylist)
		return NULL;

	if (!LM_EnumModules(_py_LM_EnumModulesCallback, (lm_void_t *)pylist)) {
		Py_DECREF(pylist); /* destroy list */
		pylist = Py_BuildValue("");
	}

	return pylist;
}

/****************************************/

static PyObject *
py_LM_EnumModulesEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	PyObject *pylist;

	if (!PyArg_ParseTuple(args, "O", &pyproc))
		return NULL;
       
	pylist = PyList_New(0);
	if (!pylist)
		return NULL;

	if (!LM_EnumModulesEx(&pyproc->proc, _py_LM_EnumModulesCallback, (lm_void_t *)pylist)) {
		Py_DECREF(pylist); /* destroy list */
		pylist = Py_BuildValue("");
	}

	return pylist;
}

/****************************************/

static PyObject *
py_LM_FindModule(PyObject *self,
		 PyObject *args)
{
	lm_char_t        *modstr;
	lm_module_t       mod;
	py_lm_module_obj *pymodule;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "u", &modstr))
			return NULL;
#	else
	if (!PyArg_ParseTuple(args, "s", &modstr))
		return NULL;
#	endif

	if (!LM_FindModule(modstr, &mod))
		return Py_BuildValue("");

	pymodule = (py_lm_module_obj *)PyObject_CallObject((PyObject *)&py_lm_module_t, NULL);
	pymodule->mod = mod;

	return (PyObject *)pymodule;
}

/****************************************/

static PyObject *
py_LM_FindModuleEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_char_t         *modstr;
	lm_module_t        mod;
	py_lm_module_obj  *pymodule;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "Ou", &pyproc, &modstr))
			return NULL;
#	else
	if (!PyArg_ParseTuple(args, "Os", &pyproc, &modstr))
		return NULL;
#	endif

	if (!LM_FindModuleEx(&pyproc->proc, modstr, &mod))
		return Py_BuildValue("");

	pymodule = (py_lm_module_obj *)PyObject_CallObject((PyObject *)&py_lm_module_t, NULL);
	pymodule->mod = mod;

	return (PyObject *)pymodule;
}

/****************************************/

static PyObject *
py_LM_LoadModule(PyObject *self,
		 PyObject *args)
{
	lm_char_t        *modpath;
	lm_module_t       mod;
	py_lm_module_obj *pymodule;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "u", &modpath))
			return NULL;
#	else
	if (!PyArg_ParseTuple(args, "s", &modpath))
		return NULL;
#	endif

	if (!LM_LoadModule(modpath, &mod))
		return Py_BuildValue("");

	pymodule = (py_lm_module_obj *)PyObject_CallObject((PyObject *)&py_lm_module_t, NULL);
	pymodule->mod = mod;

	return (PyObject *)pymodule;
}

/****************************************/

static PyObject *
py_LM_LoadModuleEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_char_t         *modpath;
	lm_module_t        mod;
	py_lm_module_obj  *pymodule;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "Ou", &pyproc, &modpath))
			return NULL;
#	else
	if (!PyArg_ParseTuple(args, "Os", &pyproc, &modpath))
		return NULL;
#	endif

	if (!LM_LoadModuleEx(&pyproc->proc, modpath, &mod))
		return Py_BuildValue("");

	pymodule = (py_lm_module_obj *)PyObject_CallObject((PyObject *)&py_lm_module_t, NULL);
	pymodule->mod = mod;

	return (PyObject *)pymodule;
}

/****************************************/

static PyObject *
py_LM_UnloadModule(PyObject *self,
		   PyObject *args)
{
	py_lm_module_obj *pymodule;

	if (!PyArg_ParseTuple(args, "O", &pymodule))
		return NULL;

	if (!LM_UnloadModule(&pymodule->mod))
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_UnloadModuleEx(PyObject *self,
		     PyObject *args)
{
	py_lm_process_obj *pyproc;
	py_lm_module_obj *pymodule;

	if (!PyArg_ParseTuple(args, "OO", &pyproc, &pymodule))
		return NULL;

	if (!LM_UnloadModuleEx(&pyproc->proc, &pymodule->mod))
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static lm_bool_t
_py_LM_EnumSymbolsCallback(lm_symbol_t *psym,
			   lm_void_t   *arg)
{
	PyObject *pylist = (PyObject *)arg;
	py_lm_symbol_obj *pysym;

	pysym = (py_lm_symbol_obj *)PyObject_CallObject((PyObject *)&py_lm_symbol_t, NULL);
	pysym->symbol = *psym;
	pysym->name = PyUnicode_FromString(pysym->symbol.name);

	PyList_Append(pylist, (PyObject *)pysym);

	return LM_TRUE;
}

static PyObject *
py_LM_EnumSymbols(PyObject *self,
		  PyObject *args)
{
	py_lm_module_obj *pymodule;
	PyObject *pylist;

	if (!PyArg_ParseTuple(args, "O", &pymodule))
		return NULL;

	pylist = PyList_New(0);
	if (!pylist)
		return NULL;

	if (!LM_EnumSymbols(&pymodule->mod, _py_LM_EnumSymbolsCallback, (lm_void_t *)pylist)) {
		Py_DECREF(pylist); /* destroy list */
		pylist = Py_BuildValue("");
	}

	return pylist;
}

/****************************************/

static PyObject *
py_LM_FindSymbolAddress(PyObject *self,
			PyObject *args)
{
	py_lm_module_obj *pymodule;
	lm_char_t        *symname;
	lm_address_t      symaddr;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "Ou", &pymodule, &symname))
			return NULL;
#	else
	if (!PyArg_ParseTuple(args, "Os", &pymodule, &symname))
		return NULL;
#	endif

	symaddr = LM_FindSymbolAddress(&pymodule->mod, symname);
	if (symaddr == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return (PyObject *)PyLong_FromSize_t(symaddr);
}

/****************************************/

static lm_bool_t
_py_LM_EnumPagesCallback(lm_page_t *ppage,
			 lm_void_t *arg)
{
	PyObject *pylist = (PyObject *)arg;
	py_lm_page_obj *pypage;

	pypage = (py_lm_page_obj *)PyObject_CallObject((PyObject *)&py_lm_page_t, NULL);
	pypage->page = *ppage;
	pypage->prot = (py_lm_prot_obj *)PyObject_CallFunction((PyObject *)&py_lm_prot_t, "i", pypage->page.prot);

	PyList_Append(pylist, (PyObject *)pypage);

	return LM_TRUE;
}

static PyObject *
py_LM_EnumPages(PyObject *self,
		PyObject *args)
{
	PyObject *pylist = PyList_New(0);
	if (!pylist)
		return NULL;

	if (!LM_EnumPages(_py_LM_EnumPagesCallback, (lm_void_t *)pylist)) {
		Py_DECREF(pylist); /* destroy list */
		pylist = Py_BuildValue("");
	}

	return pylist;
}

/****************************************/

static PyObject *
py_LM_EnumPagesEx(PyObject *self,
		  PyObject *args)
{
	py_lm_process_obj *pyproc;
	PyObject *pylist;

	if (!PyArg_ParseTuple(args, "O", &pyproc))
		return NULL;
	
	pylist = PyList_New(0);
	if (!pylist)
		return NULL;

	if (!LM_EnumPagesEx(&pyproc->proc, _py_LM_EnumPagesCallback, (lm_void_t *)pylist)) {
		Py_DECREF(pylist); /* destroy list */
		pylist = Py_BuildValue("");
	}

	return pylist;
}

/****************************************/

static PyObject *
py_LM_GetPage(PyObject *self,
	      PyObject *args)
{
	lm_address_t address;
	lm_page_t page;
	py_lm_page_obj *pypage;

	if (!PyArg_ParseTuple(args, "k", &address))
		return NULL;

	if (!LM_GetPage(address, &page))
		return Py_BuildValue("");

	pypage = (py_lm_page_obj *)PyObject_CallObject((PyObject *)&py_lm_page_t, NULL);
	pypage->page = page;
	pypage->prot = (py_lm_prot_obj *)PyObject_CallFunction((PyObject *)&py_lm_prot_t, "i", pypage->page.prot);

	return (PyObject *)pypage;
}

/****************************************/

static PyObject *
py_LM_GetPageEx(PyObject *self,
		PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t address;
	lm_page_t page;
	py_lm_page_obj *pypage;

	if (!PyArg_ParseTuple(args, "Ok", &pyproc, &address))
		return NULL;

	if (!LM_GetPageEx(&pyproc->proc, address, &page))
		return Py_BuildValue("");

	pypage = (py_lm_page_obj *)PyObject_CallObject((PyObject *)&py_lm_page_t, NULL);
	pypage->page = page;
	pypage->prot = (py_lm_prot_obj *)PyObject_CallFunction((PyObject *)&py_lm_prot_t, "i", pypage->page.prot);

	return (PyObject *)pypage;
}

/****************************************/

static PyObject *
py_LM_ReadMemory(PyObject *self,
		 PyObject *args)
{
	lm_address_t src;
	lm_size_t size;
	lm_byte_t *dst;
	PyObject *pybuf;

	if (!PyArg_ParseTuple(args, "kk", &src, &size))
		return NULL;

	dst = LM_MALLOC(size);
	if (!dst)
		return Py_BuildValue("");

	if (LM_ReadMemory(src, dst, size) == size) {
		pybuf = PyByteArray_FromStringAndSize((const char *)dst, size);
	} else {
		pybuf = Py_BuildValue("");
	}

	LM_FREE(dst);

	return pybuf;
}

/****************************************/

static PyObject *
py_LM_ReadMemoryEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t src;
	lm_size_t size;
	lm_byte_t *dst;
	PyObject *pybuf;

	if (!PyArg_ParseTuple(args, "Okk", &pyproc, &src, &size))
		return NULL;

	dst = LM_MALLOC(size);
	if (!dst)
		return Py_BuildValue("");

	if (LM_ReadMemoryEx(&pyproc->proc, src, dst, size) == size) {
		pybuf = PyByteArray_FromStringAndSize((const char *)dst, size);
	} else {
		pybuf = Py_BuildValue("");
	}

	LM_FREE(dst);

	return pybuf;
}

/****************************************/

static PyObject *
py_LM_WriteMemory(PyObject *self,
		  PyObject *args)
{
	lm_address_t dst;
	PyObject *pysrc;
	lm_bytearr_t src;
	lm_size_t size;

	if (!PyArg_ParseTuple(args, "kY", &dst, &pysrc))
		return NULL;

	src = (lm_bytearr_t)PyByteArray_AsString(pysrc);
	size = (lm_size_t)PyByteArray_Size(pysrc);

	if (LM_WriteMemory(dst, src, size) != size)
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_WriteMemoryEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t dst;
	PyObject *pysrc;
	lm_bytearr_t src;
	lm_size_t size;

	if (!PyArg_ParseTuple(args, "OkY", &pyproc, &dst, &pysrc))
		return NULL;

	src = (lm_bytearr_t)PyByteArray_AsString(pysrc);
	size = (lm_size_t)PyByteArray_Size(pysrc);

	if (LM_WriteMemoryEx(&pyproc->proc, dst, src, size) != size)
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_SetMemory(PyObject *self,
		PyObject *args)
{
	lm_address_t dst;
	lm_byte_t byte;
	lm_size_t size;

	if (!PyArg_ParseTuple(args, "kck", &dst, &byte, &size))
		return NULL;

	if (LM_SetMemory(dst, byte, size) != size)
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_SetMemoryEx(PyObject *self,
		  PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t dst;
	lm_byte_t byte;
	lm_size_t size;

	if (!PyArg_ParseTuple(args, "kck", &pyproc, &dst, &byte, &size))
		return NULL;

	if (LM_SetMemoryEx(&pyproc->proc, dst, byte, size) != size)
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_ProtMemory(PyObject *self,
		 PyObject *args)
{
	lm_address_t addr;
	lm_size_t size;
	py_lm_prot_obj *pyprot;
	lm_prot_t oldprot;
	py_lm_prot_obj *pyoldprot;

	if (!PyArg_ParseTuple(args, "kkO", &addr, &size, &pyprot))
		return NULL;

	if (!LM_ProtMemory(addr, size, pyprot->prot, &oldprot))
		return Py_BuildValue("");

	pyoldprot = (py_lm_prot_obj *)PyObject_CallFunction((PyObject *)&py_lm_prot_t, "i", oldprot);

	return (PyObject *)pyoldprot;
}

/****************************************/

static PyObject *
py_LM_ProtMemoryEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t addr;
	lm_size_t size;
	py_lm_prot_obj *pyprot;
	lm_prot_t oldprot;
	py_lm_prot_obj *pyoldprot;

	if (!PyArg_ParseTuple(args, "OkkO", &pyproc, &addr, &size, &pyprot))
		return NULL;

	if (!LM_ProtMemoryEx(&pyproc->proc, addr, size, pyprot->prot, &oldprot))
		return Py_BuildValue("");

	pyoldprot = (py_lm_prot_obj *)PyObject_CallFunction((PyObject *)&py_lm_prot_t, "i", oldprot);

	return (PyObject *)pyoldprot;
}

/****************************************/

static PyObject *
py_LM_AllocMemory(PyObject *self,
		  PyObject *args)
{
	lm_size_t size;
	py_lm_prot_obj *pyprot;
	lm_address_t alloc;

	if (!PyArg_ParseTuple(args, "kO", &size, &pyprot))
		return NULL;


	alloc = LM_AllocMemory(size, pyprot->prot);
	if (alloc == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return PyLong_FromSize_t(alloc);
}

/****************************************/

static PyObject *
py_LM_AllocMemoryEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_size_t size;
	py_lm_prot_obj *pyprot;
	lm_address_t alloc;

	if (!PyArg_ParseTuple(args, "OkO", &pyproc, &size, &pyprot))
		return NULL;


	alloc = LM_AllocMemoryEx(&pyproc->proc, size, pyprot->prot);
	if (alloc == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return PyLong_FromSize_t(alloc);
}

/****************************************/

static PyObject *
py_LM_FreeMemory(PyObject *self,
		 PyObject *args)
{
	lm_address_t alloc;
	lm_size_t size;

	if (!PyArg_ParseTuple(args, "kk", &alloc, &size))
		return NULL;


	if (!LM_FreeMemory(alloc, size))
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_FreeMemoryEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t alloc;
	lm_size_t size;

	if (!PyArg_ParseTuple(args, "Okk", &pyproc, &alloc, &size))
		return NULL;


	if (!LM_FreeMemoryEx(&pyproc->proc, alloc, size))
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_DataScan(PyObject *self,
	       PyObject *args)
{
	PyObject *pydata;
	lm_address_t addr;
	lm_size_t scansize;
	lm_bytearr_t data;
	lm_size_t size;
	lm_address_t scan_match;

	if (!PyArg_ParseTuple(args, "Ykk", &pydata, &addr, &scansize))
		return NULL;

	data = (lm_bytearr_t)PyByteArray_AsString(pydata);
	size = (lm_size_t)PyByteArray_Size(pydata);

	scan_match = LM_DataScan(data, size, addr, scansize);
	if (scan_match == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return PyLong_FromSize_t(scan_match);
}

/****************************************/

static PyObject *
py_LM_DataScanEx(PyObject *self,
		 PyObject *args)
{
	py_lm_process_obj *pyproc;
	PyObject *pydata;
	lm_address_t addr;
	lm_size_t scansize;
	lm_bytearr_t data;
	lm_size_t size;
	lm_address_t scan_match;

	if (!PyArg_ParseTuple(args, "OYkk", &pyproc, &pydata, &addr, &scansize))
		return NULL;

	data = (lm_bytearr_t)PyByteArray_AsString(pydata);
	size = (lm_size_t)PyByteArray_Size(pydata);

	scan_match = LM_DataScanEx(&pyproc->proc, data, size, addr, scansize);
	if (scan_match == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return PyLong_FromSize_t(scan_match);
}

/****************************************/

static PyObject *
py_LM_PatternScan(PyObject *self,
		  PyObject *args)
{
	PyObject *pypattern;
	lm_char_t *mask;
	lm_address_t addr;
	lm_size_t scansize;
	lm_bytearr_t pattern;
	lm_address_t scan_match;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "Yukk", &pypattern, &mask, &addr, &scansize))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "Yskk", &pypattern, &mask, &addr, &scansize))
		return NULL;
#	endif

	pattern = (lm_bytearr_t)PyByteArray_AsString(pypattern);

	scan_match = LM_PatternScan(pattern, mask, addr, scansize);
	if (scan_match == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return PyLong_FromSize_t(scan_match);
}

/****************************************/

static PyObject *
py_LM_PatternScanEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	PyObject *pypattern;
	lm_char_t *mask;
	lm_address_t addr;
	lm_size_t scansize;
	lm_bytearr_t pattern;
	lm_address_t scan_match;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "OYukk", &pyproc, &pypattern, &mask, &addr, &scansize))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "OYskk", &pyproc, &pypattern, &mask, &addr, &scansize))
		return NULL;
#	endif

	pattern = (lm_bytearr_t)PyByteArray_AsString(pypattern);

	scan_match = LM_PatternScanEx(&pyproc->proc, pattern, mask, addr, scansize);
	if (scan_match == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return PyLong_FromSize_t(scan_match);
}

/****************************************/

static PyObject *
py_LM_SigScan(PyObject *self,
	      PyObject *args)
{
	lm_char_t *sig;
	lm_address_t addr;
	lm_size_t scansize;
	lm_address_t scan_match;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "ukk", &sig, &addr, &scansize))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "skk", &sig, &addr, &scansize))
		return NULL;
#	endif

	scan_match = LM_SigScan(sig, addr, scansize);
	if (scan_match == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return PyLong_FromSize_t(scan_match);
}

/****************************************/

static PyObject *
py_LM_SigScanEx(PyObject *self,
		PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_char_t *sig;
	lm_address_t addr;
	lm_size_t scansize;
	lm_address_t scan_match;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "Oukk", &pyproc, &sig, &addr, &scansize))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "Oskk", &pyproc, &sig, &addr, &scansize))
		return NULL;
#	endif

	scan_match = LM_SigScanEx(&pyproc->proc, sig, addr, scansize);
	if (scan_match == LM_ADDRESS_BAD)
		return Py_BuildValue("");

	return PyLong_FromSize_t(scan_match);
}

/****************************************/

static PyObject *
py_LM_HookCode(PyObject *self,
	       PyObject *args)
{
	lm_address_t from;
	lm_address_t to;
	lm_address_t trampoline;
	lm_size_t    size;

	if (!PyArg_ParseTuple(args, "kk", &from, &to))
		return NULL;

	size = LM_HookCode(from, to, &trampoline);
	if (!size)
		return Py_BuildValue("");

	return Py_BuildValue("(kk)", trampoline, size);
}

/****************************************/

static PyObject *
py_LM_HookCodeEx(PyObject *self,
		 PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t from;
	lm_address_t to;
	lm_address_t trampoline;
	lm_size_t    size;

	if (!PyArg_ParseTuple(args, "Okk", &pyproc, &from, &to))
		return NULL;

	size = LM_HookCodeEx(&pyproc->proc, from, to, &trampoline);
	if (!size)
		return Py_BuildValue("");

	return Py_BuildValue("(kk)", trampoline, size);
}

/****************************************/

static PyObject *
py_LM_UnhookCode(PyObject *self,
		 PyObject *args)
{
	lm_address_t from;
	PyObject *pytrampoline;
	lm_address_t trampoline;
	lm_size_t    size;

	if (!PyArg_ParseTuple(args, "k(kk)", &from, &pytrampoline))
		return NULL;

	trampoline = (lm_address_t)PyLong_AsSize_t(PyTuple_GetItem(pytrampoline, 0));
	size = (lm_size_t)PyLong_AsSize_t(PyTuple_GetItem(pytrampoline, 1));

	if (!LM_UnhookCode(from, trampoline, size))
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_UnhookCodeEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t from;
	PyObject *pytrampoline;
	lm_address_t trampoline;
	lm_size_t    size;

	if (!PyArg_ParseTuple(args, "Ok(kk)", &pyproc, &from, &pytrampoline))
		return NULL;

	trampoline = (lm_address_t)PyLong_AsSize_t(PyTuple_GetItem(pytrampoline, 0));
	size = (lm_size_t)PyLong_AsSize_t(PyTuple_GetItem(pytrampoline, 1));

	if (!LM_UnhookCodeEx(&pyproc->proc, from, trampoline, size))
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

/****************************************/

static PyObject *
py_LM_Assemble(PyObject *self,
	       PyObject *args)
{
	lm_cstring_t code;
	lm_inst_t inst;
	py_lm_inst_obj *pyinst;

	if (!PyArg_ParseTuple(args, "s", &code))
		return NULL;

	if (!LM_Assemble(code, &inst))
		return Py_BuildValue("");

	pyinst = (py_lm_inst_obj *)PyObject_CallObject((PyObject *)&py_lm_inst_t, NULL);
	pyinst->inst = inst;

	return (PyObject *)pyinst;
}

/****************************************/

static PyObject *
py_LM_AssembleEx(PyObject *self,
		 PyObject *args)
{
	lm_cstring_t code;
	lm_size_t bits;
	lm_address_t runtime_addr;
	lm_bytearr_t codebuf;
	lm_size_t codelen;
	PyObject *pycodebuf;

	if (!PyArg_ParseTuple(args, "skk", &code, &bits, &runtime_addr))
		return NULL;

	codelen = LM_AssembleEx(code, bits, runtime_addr, &codebuf);
	if (!codelen)
		return Py_BuildValue("");

	pycodebuf = PyByteArray_FromStringAndSize((const char *)codebuf, codelen);

	LM_FreeCodeBuffer(codebuf);

	return pycodebuf;
}

/****************************************/

static PyObject *
py_LM_Disassemble(PyObject *self,
		  PyObject *args)
{
	lm_address_t code;
	lm_inst_t inst;
	py_lm_inst_obj *pyinst;

	if (!PyArg_ParseTuple(args, "k", &code))
		return NULL;

	if (!LM_Disassemble(code, &inst))
		return Py_BuildValue("");

	pyinst = (py_lm_inst_obj *)PyObject_CallObject((PyObject *)&py_lm_inst_t, NULL);
	pyinst->inst = inst;

	return (PyObject *)pyinst;
}

/****************************************/

static PyObject *
py_LM_DisassembleEx(PyObject *self,
		    PyObject *args)
{
	lm_address_t code;
	lm_size_t bits;
	lm_size_t size;
	lm_size_t count;
	lm_address_t runtime_addr;
	lm_inst_t *insts;
	lm_size_t inst_count;
	PyObject *pyinsts;
	lm_size_t i;
	py_lm_inst_obj *pyinst;

	if (!PyArg_ParseTuple(args, "kkkkk", &code, &bits, &size, &count, &runtime_addr))
		return NULL;

	inst_count = LM_DisassembleEx(code, bits, size, count, runtime_addr, &insts);
	if (!inst_count)
		return Py_BuildValue("");

	pyinsts = PyList_New((Py_ssize_t)inst_count);
	for (i = 0; i < inst_count; ++i) {
		pyinst = (py_lm_inst_obj *)PyObject_CallObject((PyObject *)&py_lm_inst_t, NULL);
		pyinst->inst = insts[i];
		PyList_SetItem(pyinsts, i, (PyObject *)pyinst);
	}

	LM_FreeInstructions(insts);

	return pyinsts;
}

/****************************************/

static PyObject *
py_LM_CodeLength(PyObject *self,
		 PyObject *args)
{
	lm_address_t code;
	lm_size_t minlength;
	lm_size_t aligned_length;

	if (!PyArg_ParseTuple(args, "kk", &code, &minlength))
		return NULL;

	aligned_length = LM_CodeLength(code, minlength);
	if (!aligned_length)
		return Py_BuildValue("");

	return (PyObject *)PyLong_FromSize_t(aligned_length);
}

/****************************************/

static PyObject *
py_LM_CodeLengthEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_address_t code;
	lm_size_t minlength;
	lm_size_t aligned_length;

	if (!PyArg_ParseTuple(args, "Okk", &pyproc, &code, &minlength))
		return NULL;

	aligned_length = LM_CodeLengthEx(&pyproc->proc, code, minlength);
	if (!aligned_length)
		return Py_BuildValue("");

	return (PyObject *)PyLong_FromSize_t(aligned_length);
}

/****************************************/

static PyMethodDef libmem_methods[] = {
	{ "LM_EnumProcesses", py_LM_EnumProcesses, METH_NOARGS, "Lists all current living processes" },
	{ "LM_GetProcess", py_LM_GetProcess, METH_NOARGS, "Gets information about the calling process" },
	{ "LM_GetProcessEx", py_LM_GetProcessEx, METH_VARARGS, "Gets information about a process from a process ID" },
	{ "LM_FindProcess", py_LM_FindProcess, METH_VARARGS, "Searches for an existing process" },
	{ "LM_IsProcessAlive", py_LM_IsProcessAlive, METH_VARARGS, "Checks if a process is alive" },
	{ "LM_GetSystemBits", py_LM_GetSystemBits, METH_VARARGS, "Checks if a process is alive" },
	/****************************************/
	{ "LM_EnumThreads", py_LM_EnumThreads, METH_NOARGS, "Lists all threads from the calling process" },
	{ "LM_EnumThreadsEx", py_LM_EnumThreadsEx, METH_VARARGS, "Lists all threads from the calling process" },
	{ "LM_GetThread", py_LM_GetThread, METH_NOARGS, "Get information about the calling thread" },
	{ "LM_GetThreadEx", py_LM_GetThreadEx, METH_VARARGS, "Get information about a remote thread" },
	{ "LM_GetThreadProcess", py_LM_GetThreadProcess, METH_VARARGS, "Gets information about a process from a thread" },
	/****************************************/
	{ "LM_EnumModules", py_LM_EnumModules, METH_NOARGS, "Lists all modules from the calling process" },
	{ "LM_EnumModulesEx", py_LM_EnumModulesEx, METH_VARARGS, "Lists all modules from a remote process" },
	{ "LM_FindModule", py_LM_FindModule, METH_VARARGS, "Searches for a module in the current process" },
	{ "LM_FindModuleEx", py_LM_FindModuleEx, METH_VARARGS, "Searches for a module in a remote process" },
	{ "LM_LoadModule", py_LM_LoadModule, METH_VARARGS, "Loads a module into the current process" },
	{ "LM_LoadModuleEx", py_LM_LoadModuleEx, METH_VARARGS, "Loads a module into a remote process" },
	{ "LM_UnloadModule", py_LM_UnloadModule, METH_VARARGS, "Unloads a module from the current process" },
	{ "LM_UnloadModuleEx", py_LM_UnloadModuleEx, METH_VARARGS, "Unloads a module from a remote process" },
	/****************************************/
	{ "LM_EnumSymbols", py_LM_EnumSymbols, METH_VARARGS, "Lists all symbols from a module" },
	{ "LM_FindSymbolAddress", py_LM_FindSymbolAddress, METH_VARARGS, "Searches for a symbols in a module" },
	/****************************************/
	{ "LM_EnumPages", py_LM_EnumPages, METH_NOARGS, "Lists all pages from the calling process" },
	{ "LM_EnumPagesEx", py_LM_EnumPagesEx, METH_VARARGS, "Lists all pages from a remote process" },
	{ "LM_GetPage", py_LM_GetPage, METH_VARARGS, "Get information about the page of an address in the current process" },
	{ "LM_GetPageEx", py_LM_GetPageEx, METH_VARARGS, "Get information about the page of an address in a remote process" },
	/****************************************/
	{ "LM_ReadMemory", py_LM_ReadMemory, METH_VARARGS, "Read memory from the calling process" },
	{ "LM_ReadMemoryEx", py_LM_ReadMemoryEx, METH_VARARGS, "Read memory from a remote process" },
	{ "LM_WriteMemory", py_LM_WriteMemory, METH_VARARGS, "Write memory to the calling process" },
	{ "LM_WriteMemoryEx", py_LM_WriteMemoryEx, METH_VARARGS, "Write memory to a remote process" },
	{ "LM_SetMemory", py_LM_SetMemory, METH_VARARGS, "Set memory to a byte in the current process" },
	{ "LM_SetMemoryEx", py_LM_SetMemoryEx, METH_VARARGS, "Set memory to a byte in a remote process" },
	{ "LM_ProtMemory", py_LM_ProtMemory, METH_VARARGS, "Change memory protection flags of a region in the current process" },
	{ "LM_ProtMemoryEx", py_LM_ProtMemoryEx, METH_VARARGS, "Change memory protection flags of a region in a remote process" },
	{ "LM_AllocMemory", py_LM_AllocMemory, METH_VARARGS, "Allocate memory in the current process" },
	{ "LM_AllocMemoryEx", py_LM_AllocMemoryEx, METH_VARARGS, "Allocate memory in a remote process" },
	{ "LM_FreeMemory", py_LM_FreeMemory, METH_VARARGS, "Free memory in the current process" },
	{ "LM_FreeMemoryEx", py_LM_FreeMemoryEx, METH_VARARGS, "Free memory in a remote process" },
	/****************************************/
	{ "LM_DataScan", py_LM_DataScan, METH_VARARGS, "Search for a byte array in the current process" },
	{ "LM_DataScanEx", py_LM_DataScanEx, METH_VARARGS, "Search for a byte array in a remote process" },
	{ "LM_PatternScan", py_LM_PatternScan, METH_VARARGS, "Search for a byte pattern with a mask filter in the current process" },
	{ "LM_PatternScanEx", py_LM_PatternScanEx, METH_VARARGS, "Search for a byte pattern with a mask filter in a remote process" },
	{ "LM_SigScan", py_LM_SigScan, METH_VARARGS, "Search for a byte signature that can contain filters in the current process" },
	{ "LM_SigScanEx", py_LM_SigScanEx, METH_VARARGS, "Search for a byte signature that can contain filters in a remote process" },
	/****************************************/
	{ "LM_HookCode", py_LM_HookCode, METH_VARARGS, "Hook/detour code in the current process, returning a gateway/trampoline" },
	{ "LM_HookCodeEx", py_LM_HookCodeEx, METH_VARARGS, "Hook/detour code in a remote process, returning a gateway/trampoline" },
	{ "LM_UnhookCode", py_LM_UnhookCode, METH_VARARGS, "Unhook/restore code in the current process" },
	{ "LM_UnhookCodeEx", py_LM_UnhookCodeEx, METH_VARARGS, "Unhook/restore code in a remote process" },
	/****************************************/
	{ "LM_Assemble", py_LM_Assemble, METH_VARARGS, "Assemble instruction from text" },
	{ "LM_AssembleEx", py_LM_AssembleEx, METH_VARARGS, "Assemble instructions from text" },
	{ "LM_Disassemble", py_LM_Disassemble, METH_VARARGS, "Disassemble instruction from an address in the current process" },
	{ "LM_DisassembleEx", py_LM_DisassembleEx, METH_VARARGS, "Disassemble instructions from an address in the current process" },
	{ "LM_CodeLength", py_LM_CodeLength, METH_VARARGS, "Get the minimum instruction aligned length for a code region in the current process" },
	{ "LM_CodeLengthEx", py_LM_CodeLengthEx, METH_VARARGS, "Get the minimum instruction aligned length for a code region in a remote process" },
	{ NULL, NULL, 0, NULL }
};

static PyModuleDef libmem_mod = {
	PyModuleDef_HEAD_INIT,
	"libmem",
	NULL,
	-1,
	libmem_methods
};

PyMODINIT_FUNC
PyInit_libmem(void)
{
	PyObject *pymod;
	PyObject *global; /* used in the DECL_GLOBAL macro */

	if (PyType_Ready(&py_lm_process_t) < 0)
		goto ERR_PYMOD;

	if (PyType_Ready(&py_lm_thread_t) < 0)
		goto ERR_PYMOD;

	if (PyType_Ready(&py_lm_module_t) < 0)
		goto ERR_PYMOD;

	if (PyType_Ready(&py_lm_symbol_t) < 0)
		goto ERR_PYMOD;

	if (PyType_Ready(&py_lm_prot_t) < 0)
		goto ERR_PYMOD;

	if (PyType_Ready(&py_lm_page_t) < 0)
		goto ERR_PYMOD;

	if (PyType_Ready(&py_lm_inst_t) < 0)
		goto ERR_PYMOD;

	if (PyType_Ready(&py_lm_vmt_t) < 0)
		goto ERR_PYMOD;

	pymod = PyModule_Create(&libmem_mod);
	if (!pymod)
		goto ERR_PYMOD;
	
	/* types */
	Py_INCREF(&py_lm_process_t);
	if (PyModule_AddObject(pymod, "lm_process_t",
			       (PyObject *)&py_lm_process_t) < 0)
		goto ERR_PROCESS;

	Py_INCREF(&py_lm_thread_t);
	if (PyModule_AddObject(pymod, "lm_thread_t",
			       (PyObject *)&py_lm_thread_t) < 0)
		goto ERR_THREAD;

	Py_INCREF(&py_lm_module_t);
	if (PyModule_AddObject(pymod, "lm_module_t",
			       (PyObject *)&py_lm_module_t) < 0)
		goto ERR_MODULE;

	Py_INCREF(&py_lm_symbol_t);
	if (PyModule_AddObject(pymod, "lm_symbol_t",
			       (PyObject *)&py_lm_symbol_t) < 0)
		goto ERR_SYMBOL;

	Py_INCREF(&py_lm_prot_t);
	if (PyModule_AddObject(pymod, "lm_prot_t",
			       (PyObject *)&py_lm_prot_t) < 0)
		goto ERR_PROT;

	Py_INCREF(&py_lm_page_t);
	if (PyModule_AddObject(pymod, "lm_page_t",
			       (PyObject *)&py_lm_page_t) < 0)
		goto ERR_PAGE;

	Py_INCREF(&py_lm_inst_t);
	if (PyModule_AddObject(pymod, "lm_inst_t",
			       (PyObject *)&py_lm_inst_t) < 0)
		goto ERR_INST;

	Py_INCREF(&py_lm_vmt_t);
	if (PyModule_AddObject(pymod, "lm_vmt_t",
			       (PyObject *)&py_lm_vmt_t) < 0)
		goto ERR_VMT;

	/* global variables */
	DECL_GLOBAL_PROT(LM_PROT_X);
	DECL_GLOBAL_PROT(LM_PROT_R);
	DECL_GLOBAL_PROT(LM_PROT_W);
	DECL_GLOBAL_PROT(LM_PROT_XR);
	DECL_GLOBAL_PROT(LM_PROT_XW);
	DECL_GLOBAL_PROT(LM_PROT_RW);
	DECL_GLOBAL_PROT(LM_PROT_XRW);
	DECL_GLOBAL_LONG(LM_BITS);

	goto EXIT; /* no errors */

ERR_VMT:
	Py_DECREF(&py_lm_vmt_t);
	Py_DECREF(pymod);
ERR_INST:
	Py_DECREF(&py_lm_inst_t);
	Py_DECREF(pymod);
ERR_PROT:
	Py_DECREF(&py_lm_prot_t);
	Py_DECREF(pymod);
ERR_PAGE:
	Py_DECREF(&py_lm_page_t);
	Py_DECREF(pymod);
ERR_SYMBOL:
	Py_DECREF(&py_lm_symbol_t);
	Py_DECREF(pymod);
ERR_MODULE:
	Py_DECREF(&py_lm_module_t);
	Py_DECREF(pymod);
ERR_THREAD:
	Py_DECREF(&py_lm_thread_t);
	Py_DECREF(pymod);
ERR_PROCESS:
	Py_DECREF(&py_lm_process_t);
	Py_DECREF(pymod);
ERR_PYMOD:
	pymod = (PyObject *)NULL;
EXIT:
	return pymod;
}

