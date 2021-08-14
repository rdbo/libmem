#include <libmem.h>
#include <Python.h>
#include <structmember.h>

/* Python Types */
typedef struct {
	PyObject_HEAD
	lm_pid_t pid;
} py_lm_pid_obj;

static PyMemberDef py_lm_pid_members[] = {
	{ "pid", T_INT, offsetof(py_lm_pid_obj, pid), 0, "" }
};

static PyObject *
py_lm_pid_int(py_lm_pid_obj *self)
{
	return PyLong_FromPid(self->pid);
}

static PyNumberMethods lm_pid_number_methods = {
	.nb_int = (unaryfunc)py_lm_pid_int
};

static PyTypeObject py_lm_pid_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_pid_t",
	.tp_doc = "",
	.tp_basicsize = sizeof(py_lm_pid_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_pid_members,
	.tp_as_number = &lm_pid_number_methods
};

/****************************************/

typedef struct {
	PyObject_HEAD
	lm_process_t proc;
} py_lm_process_obj;

static PyMemberDef py_lm_process_members[] = {
	{ "pid", T_INT, offsetof(py_lm_process_obj, proc.pid), 0, "" }
#	if LM_OS == LM_OS_WIN
	{ "handle", T_INT, offsetof(py_lm_process_obj, proc.handle), 0, "" }
#	endif
};

static PyTypeObject py_lm_process_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_process_t",
	.tp_doc = "",
	.tp_basicsize = sizeof(py_lm_process_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_process_members
};

/* Python Functions */
static PyObject *
py_LM_GetProcessId(PyObject *self,
		   PyObject *args)
{
	py_lm_pid_obj *pypid;
	
	pypid = (py_lm_pid_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_pid_t);
	pypid->pid = LM_GetProcessId();

	return (PyObject *)pypid;
}

static PyObject *
py_LM_GetProcessIdEx(PyObject *self,
		     PyObject *args)
{
	py_lm_pid_obj *pypid;
	lm_tchar_t    *procstr;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "u", &procstr))
			return NULL;
#	else
	if (!PyArg_ParseTuple(args, "s", &procstr))
		return NULL;
#	endif

	pypid = (py_lm_pid_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_pid_t);
	pypid->pid = LM_GetProcessIdEx(procstr);

	return (PyObject *)pypid;
}

static PyObject *
py_LM_OpenProcess(PyObject *self,
		  PyObject *args)
{
	py_lm_process_obj *pyproc;

	pyproc = (py_lm_process_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_process_t);

	LM_OpenProcess(&pyproc->proc);
	
	return (PyObject *)pyproc;
}

static PyObject *
py_LM_OpenProcessEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	py_lm_pid_obj     *pypid;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_pid_t, &pypid))
		return NULL;

	pyproc = (py_lm_process_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_process_t);

	LM_OpenProcessEx(pypid->pid, &pyproc->proc);
	
	return (PyObject *)pyproc;
}

static PyObject *
py_LM_CloseProcess(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	
	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;

	LM_CloseProcess(&pyproc->proc);

	return PyLong_FromLong(0);
}

static PyObject *
py_LM_GetProcessPath(PyObject *self,
		     PyObject *args)
{
	PyUnicodeObject *pystr = (PyUnicodeObject *)NULL;
	lm_tchar_t      *pathbuf;
	lm_size_t        length;

	pathbuf = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!pathbuf)
		return NULL;
	
	length = LM_GetProcessPath(pathbuf, LM_PATH_MAX);
	if (!length)
		goto _FREE_RET;
	
#	if LM_CHARSET == LM_CHARSET_UC
	pystr = (PyUnicodeObject *)PyUnicode_FromUnicode(pathbuf, length);
#	else
	pystr = (PyUnicodeObject *)PyUnicode_FromString(pathbuf);
#	endif

_FREE_RET:
	LM_FREE(pathbuf);
	return (PyObject *)pystr;
}

static PyObject *
py_LM_GetProcessPathEx(PyObject *self,
		       PyObject *args)
{
	PyUnicodeObject   *pystr = (PyUnicodeObject *)NULL;
	py_lm_process_obj *pyproc;
	lm_tchar_t        *pathbuf;
	lm_size_t          length;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;

	pathbuf = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!pathbuf)
		return NULL;
	
	length = LM_GetProcessPathEx(pyproc->proc, pathbuf, LM_PATH_MAX);
	if (!length)
		goto _FREE_RET;
	
#	if LM_CHARSET == LM_CHARSET_UC
	pystr = (PyUnicodeObject *)PyUnicode_FromUnicode(pathbuf, length);
#	else
	pystr = (PyUnicodeObject *)PyUnicode_FromString(pathbuf);
#	endif

_FREE_RET:
	LM_FREE(pathbuf);
	return (PyObject *)pystr;
}

/* Python Module */
static PyMethodDef libmem_methods[] = {
	{ "LM_GetProcessId", py_LM_GetProcessId, METH_NOARGS, "" },
	{ "LM_GetProcessIdEx", py_LM_GetProcessIdEx, METH_VARARGS, "" },
	{ "LM_OpenProcess", py_LM_OpenProcess, METH_NOARGS, "" },
	{ "LM_OpenProcessEx", py_LM_OpenProcessEx, METH_VARARGS, "" },
	{ "LM_CloseProcess", py_LM_CloseProcess, METH_VARARGS, "" },
	{ "LM_GetProcessPath", py_LM_GetProcessPath, METH_NOARGS, "" },
	{ "LM_GetProcessPathEx", py_LM_GetProcessPathEx, METH_VARARGS, "" },
	{ NULL, NULL, 0, NULL } /* Sentinel */
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

	if (PyType_Ready(&py_lm_pid_t) < 0)
		goto _ERR_MOD;
	
	if (PyType_Ready(&py_lm_process_t) < 0)
		goto _ERR_MOD;

	pymod = PyModule_Create(&libmem_mod);
	if (!pymod)
		goto _ERR_MOD;
	
	Py_INCREF(&py_lm_pid_t);
	if (PyModule_AddObject(pymod, "lm_pid_t",
			       (PyObject *)&py_lm_pid_t) < 0)
		goto _ERR_PID;
	
	Py_INCREF(&py_lm_process_t);
	if (PyModule_AddObject(pymod, "lm_process_t",
			       (PyObject *)&py_lm_process_t) < 0)
		goto _ERR_PROCESS;

	goto _RET; /* No Type Errors */
_ERR_PROCESS:
	Py_DECREF(&py_lm_process_t);
	Py_DECREF(pymod);
_ERR_PID:
	Py_DECREF(&py_lm_pid_t);
	Py_DECREF(pymod);
_ERR_MOD:
	pymod = (PyObject *)NULL;
_RET:
	return pymod;
}
