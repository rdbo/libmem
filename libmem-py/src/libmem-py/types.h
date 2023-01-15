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

/* lm_process_t */
typedef struct {
	PyObject_HEAD
	lm_process_t proc;
} py_lm_process_obj;

static PyMemberDef py_lm_process_members[] = {
	{ "pid", T_INT, offsetof(py_lm_process_obj, proc.pid), READONLY, "Process ID" },
	{ "ppid", T_INT, offsetof(py_lm_process_obj, proc.ppid), READONLY, "Parent Process ID" },
	{ "bits", T_ULONG, offsetof(py_lm_process_obj, proc.bits), READONLY, "Process Bits" },
	{ "path", T_STRING, offsetof(py_lm_process_obj, proc.path), READONLY, "Process Executable Path" },
	{ "name", T_STRING, offsetof(py_lm_process_obj, proc.name), READONLY, "Process Name" },
	{ NULL }
};

static PyTypeObject py_lm_process_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_process_t",
	.tp_doc = "Stores information about a process",
	.tp_basicsize = sizeof(py_lm_process_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_process_members
};

/****************************************/



#endif

