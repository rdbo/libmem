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

#ifndef LIBMEM_TYPES_H
#define LIBMEM_TYPES_H

#include <libmem/libmem.h>
#include <Python.h>
#include <structmember.h>

#define T_SIZE T_ULONG

/* lm_process_t */
typedef struct {
	PyObject_HEAD
	lm_process_t proc;
} py_lm_process_obj;

static PyMemberDef py_lm_process_members[] = {
	{ "pid", T_INT, offsetof(py_lm_process_obj, proc.pid), READONLY, "Process ID" },
	{ "ppid", T_INT, offsetof(py_lm_process_obj, proc.ppid), READONLY, "Parent Process ID" },
	{ "bits", T_SIZE, offsetof(py_lm_process_obj, proc.bits), READONLY, "Process Bits" },
	{ NULL }
};

PyObject *
py_lm_process_get_path(PyObject *self, void *closure)
{
	return PyUnicode_FromString(((py_lm_process_obj *)self)->proc.path);
}

PyObject *
py_lm_process_get_name(PyObject *self, void *closure)
{
	return PyUnicode_FromString(((py_lm_process_obj *)self)->proc.name);
}

PyObject *
py_lm_process_str(PyObject *self)
{
	py_lm_process_obj *pyproc = (py_lm_process_obj *)self;
	return PyUnicode_FromFormat("<lm_process_t { pid: %d, ppid: %d, bits: %zu, path: %s, name: %s }>", pyproc->proc.pid, pyproc->proc.ppid, pyproc->proc.bits, pyproc->proc.path, pyproc->proc.name);
}

static PyGetSetDef py_lm_process_accessors[] = {
	{ "path", py_lm_process_get_path, NULL, NULL, NULL },
	{ "name", py_lm_process_get_name, NULL, NULL, NULL },
	{ NULL, NULL, NULL, NULL, NULL }
};

static PyTypeObject py_lm_process_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_process_t",
	.tp_doc = "Stores information about a process",
	.tp_basicsize = sizeof(py_lm_process_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_process_members,
	.tp_getset = py_lm_process_accessors,
	.tp_str = py_lm_process_str,
	.tp_repr = py_lm_process_str
};

/****************************************/

/* lm_thread_t */
typedef struct {
	PyObject_HEAD
	lm_thread_t thread;
} py_lm_thread_obj;

static PyMemberDef py_lm_thread_members[] = {
	{ "tid", T_INT, offsetof(py_lm_thread_obj, thread.tid), READONLY, "Thread ID" },
	{ NULL }
};

PyObject *
py_lm_thread_str(PyObject *self)
{
	py_lm_thread_obj *pythread = (py_lm_thread_obj *)self;
	return PyUnicode_FromFormat("<lm_thread_t { tid: %d }>", pythread->thread.tid);
}

static PyTypeObject py_lm_thread_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_thread_t",
	.tp_doc = "Stores information about a thread",
	.tp_basicsize = sizeof(py_lm_thread_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_thread_members,
	.tp_str = py_lm_thread_str,
	.tp_repr = py_lm_thread_str
};

/****************************************/

/* lm_module_t */
typedef struct {
	PyObject_HEAD
	lm_module_t mod;
} py_lm_module_obj;

static PyMemberDef py_lm_module_members[] = {
	{ "base", T_SIZE, offsetof(py_lm_module_obj, mod.base), READONLY, "Module Base Address" },
	{ "end", T_SIZE, offsetof(py_lm_module_obj, mod.end), READONLY, "Module End Address" },
	{ "size", T_SIZE, offsetof(py_lm_module_obj, mod.size), READONLY, "Module Size" },
	{ NULL }
};

PyObject *
py_lm_module_get_path(PyObject *self, void *closure)
{
	return PyUnicode_FromString(((py_lm_module_obj *)self)->mod.path);
}

PyObject *
py_lm_module_get_name(PyObject *self, void *closure)
{
	return PyUnicode_FromString(((py_lm_module_obj *)self)->mod.name);
}

PyObject *
py_lm_module_str(PyObject *self)
{
	py_lm_module_obj *pymodule = (py_lm_module_obj *)self;
	return PyUnicode_FromFormat("<lm_module_t { base: %p, end: %p, size: %p, path: %s, name: %s }>", (void *)pymodule->mod.base, (void *)pymodule->mod.end, (void *)pymodule->mod.size, pymodule->mod.path, pymodule->mod.name);
}

static PyGetSetDef py_lm_module_accessors[] = {
	{ "path", py_lm_module_get_path, NULL, NULL, NULL },
	{ "name", py_lm_module_get_name, NULL, NULL, NULL },
	{ NULL, NULL, NULL, NULL, NULL }
};

static PyTypeObject py_lm_module_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_module_t",
	.tp_doc = "Stores information about a module",
	.tp_basicsize = sizeof(py_lm_module_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_module_members,
	.tp_getset = py_lm_module_accessors,
	.tp_str = py_lm_module_str,
	.tp_repr = py_lm_module_str
};

#endif

/****************************************/

/* lm_symbol_t */
typedef struct {
	PyObject_HEAD
	lm_symbol_t symbol;
	PyObject *name;
} py_lm_symbol_obj;

static PyMemberDef py_lm_symbol_members[] = {
	{ "name", T_OBJECT, offsetof(py_lm_symbol_obj, name), READONLY, "Symbol Name" },
	{ "address", T_SIZE, offsetof(py_lm_symbol_obj, symbol.address), READONLY, "Symbol Address" },
	{ NULL }
};

PyObject *
py_lm_symbol_str(PyObject *self)
{
	py_lm_symbol_obj *pysym = (py_lm_symbol_obj *)self;
	return PyUnicode_FromFormat("<lm_symbol_t { name: %s, address: %p }>", PyUnicode_AsUTF8(pysym->name), (void *)pysym->symbol.address);
}

static PyTypeObject py_lm_symbol_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_symbol_t",
	.tp_doc = "Stores information about a symbol",
	.tp_basicsize = sizeof(py_lm_symbol_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_symbol_members,
	.tp_str = py_lm_symbol_str,
	.tp_repr = py_lm_symbol_str
};

