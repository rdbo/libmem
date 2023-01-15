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

static PyMethodDef libmem_methods[] = {
	{ "LM_FindProcess", py_LM_FindProcess, METH_VARARGS, "Searches for an existing process" },
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

	if (PyType_Ready(&py_lm_process_t) < 0)
		goto ERR_PYMOD;

	pymod = PyModule_Create(&libmem_mod);
	if (!pymod)
		goto ERR_PYMOD;
	
	/* types */
	Py_INCREF(&py_lm_process_t);
	if (PyModule_AddObject(pymod, "lm_process_t",
			       (PyObject *)&py_lm_process_t) < 0)
		goto ERR_PROCESS;

	goto EXIT; /* no errors */

ERR_PROCESS:
	Py_DECREF(&py_lm_process_t);
	Py_DECREF(pymod);
ERR_PYMOD:
	pymod = (PyObject *)NULL;
EXIT:
	return pymod;
}

