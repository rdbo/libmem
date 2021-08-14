#include <libmem.h>
#include <Python.h>
#include <structmember.h>

#define DECL_GLOBAL(mod, name, val) { \
	PyObject *global; \
	global = PyLong_FromLong(val); \
	PyObject_SetAttrString(mod, name, global); \
	Py_DECREF(global); \
}

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
	lm_tid_t tid;
} py_lm_tid_obj;

static PyMemberDef py_lm_tid_members[] = {
	{ "tid", T_INT, offsetof(py_lm_tid_obj, tid), 0, "" }
};

static PyObject *
py_lm_tid_int(py_lm_tid_obj *self)
{
	return PyLong_FromLong(self->tid);
}

static PyNumberMethods lm_tid_number_methods = {
	.nb_int = (unaryfunc)py_lm_tid_int
};

static PyTypeObject py_lm_tid_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_tid_t",
	.tp_doc = "",
	.tp_basicsize = sizeof(py_lm_tid_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_tid_members,
	.tp_as_number = &lm_tid_number_methods
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

/****************************************/

typedef struct {
	PyObject_HEAD
	lm_module_t mod;
} py_lm_module_obj;

static PyMemberDef py_lm_module_members[] = {
	{ "base", T_ULONG, offsetof(py_lm_module_obj, mod.base), 0, "" },
	{ "end", T_ULONG, offsetof(py_lm_module_obj, mod.end), 0, "" },
	{ "size", T_ULONG, offsetof(py_lm_module_obj, mod.size), 0, "" }
};

static PyTypeObject py_lm_module_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_module_t",
	.tp_doc = "",
	.tp_basicsize = sizeof(py_lm_module_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_module_members
};

/* Python Functions */
typedef struct {
	PyObject *callback;
	PyObject *arg;
} py_lm_enum_processes_t;

static lm_bool_t
py_LM_EnumProcessesCallback(lm_pid_t   pid,
			    lm_void_t *arg)
{
	py_lm_enum_processes_t *parg = (py_lm_enum_processes_t *)arg;
	py_lm_pid_obj *pypid;
	PyLongObject *pyret;

	pypid = (py_lm_pid_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_pid_t);
	pypid->pid = pid;
	
	pyret = (PyLongObject *)(
		PyObject_CallFunctionObjArgs(parg->callback,
					     pypid,
					     parg->arg,
					     NULL)
	);

	return PyLong_AsLong((PyObject *)pyret) ? LM_TRUE : LM_FALSE;
}

static PyObject *
py_LM_EnumProcesses(PyObject *self,
		    PyObject *args)
{
	py_lm_enum_processes_t arg;

	if (!PyArg_ParseTuple(args, "O|O", &arg.callback, &arg.arg))
		return NULL;
	
	return PyLong_FromLong(
		LM_EnumProcesses(
			py_LM_EnumProcessesCallback,
			(lm_void_t *)&arg
		)
	);
}

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
py_LM_GetParentId(PyObject *self,
		  PyObject *args)
{
	py_lm_pid_obj *pyppid;

	pyppid = (py_lm_pid_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_pid_t);
	pyppid->pid = LM_GetParentId();

	return (PyObject *)pyppid;
}

static PyObject *
py_LM_GetParentIdEx(PyObject *self,
		    PyObject *args)
{
	py_lm_pid_obj *pyppid;
	py_lm_pid_obj *pypid;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_pid_t, &pypid))
		return NULL;
	
	pyppid = (py_lm_pid_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_pid_t);
	pyppid->pid = LM_GetParentIdEx(pypid->pid);

	return (PyObject *)pyppid;
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

static PyObject *
py_LM_GetProcessName(PyObject *self,
		     PyObject *args)
{
	PyUnicodeObject *pystr = (PyUnicodeObject *)NULL;
	lm_tchar_t      *namebuf;
	lm_size_t        length;

	namebuf = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!namebuf)
		return NULL;
	
	length = LM_GetProcessName(namebuf, LM_PATH_MAX);
	if (!length)
		goto _FREE_RET;
	
#	if LM_CHARSET == LM_CHARSET_UC
	pystr = (PyUnicodeObject *)PyUnicode_FromUnicode(namebuf, length);
#	else
	pystr = (PyUnicodeObject *)PyUnicode_FromString(namebuf);
#	endif

_FREE_RET:
	LM_FREE(namebuf);
	return (PyObject *)pystr;
}

static PyObject *
py_LM_GetProcessNameEx(PyObject *self,
		       PyObject *args)
{
	PyUnicodeObject   *pystr = (PyUnicodeObject *)NULL;
	py_lm_process_obj *pyproc;
	lm_tchar_t        *namebuf;
	lm_size_t          length;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;

	namebuf = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!namebuf)
		return NULL;
	
	length = LM_GetProcessNameEx(pyproc->proc, namebuf, LM_PATH_MAX);
	if (!length)
		goto _FREE_RET;
	
#	if LM_CHARSET == LM_CHARSET_UC
	pystr = (PyUnicodeObject *)PyUnicode_FromUnicode(namebuf, length);
#	else
	pystr = (PyUnicodeObject *)PyUnicode_FromString(namebuf);
#	endif

_FREE_RET:
	LM_FREE(namebuf);
	return (PyObject *)pystr;
}

static PyObject *
py_LM_GetSystemBits(PyObject *self,
		    PyObject *args)
{
	return PyLong_FromLong(LM_GetSystemBits());
}

static PyObject *
py_LM_GetProcessBits(PyObject *self,
		     PyObject *args)
{
	return PyLong_FromLong(LM_GetProcessBits());
}

static PyObject *
py_LM_GetProcessBitsEx(PyObject *self,
		       PyObject *args)
{
	py_lm_process_obj *pyproc;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;
	
	return PyLong_FromLong(LM_GetProcessBitsEx(pyproc->proc));
}

/****************************************/

typedef struct {
	PyObject *callback;
	PyObject *arg;
} py_lm_enum_threads_t;

static lm_bool_t
py_LM_EnumThreadsCallback(lm_tid_t   tid,
			  lm_void_t *arg)
{
	PyLongObject         *pyret;
	py_lm_tid_obj        *pytid;
	py_lm_enum_threads_t *parg = (py_lm_enum_threads_t *)arg;

	pytid = (py_lm_tid_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_tid_t);
	pytid->tid = tid;

	pyret = (PyLongObject *)(
		PyObject_CallFunctionObjArgs(parg->callback,
					     pytid,
					     parg->arg,
					     NULL)
	);

	return PyLong_AsLong((PyObject *)pyret) ? LM_TRUE : LM_FALSE;
}

static PyObject *
py_LM_EnumThreads(PyObject *self,
		  PyObject *args)
{
	py_lm_enum_threads_t arg;

	if (!PyArg_ParseTuple(args, "O|O", &arg.callback, &arg.arg))
		return NULL;
	
	return PyLong_FromLong(
		LM_EnumThreads(py_LM_EnumThreadsCallback,
			       (lm_void_t *)&arg)
	);
}

static PyObject *
py_LM_EnumThreadsEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj   *pyproc;
	py_lm_enum_threads_t arg;

	if (!PyArg_ParseTuple(args, "O!|O|O", &py_lm_process_t, &pyproc,
			      &arg.callback, &arg.arg))
		return NULL;
	
	return PyLong_FromLong(
		LM_EnumThreadsEx(pyproc->proc,
				 py_LM_EnumThreadsCallback,
				 (lm_void_t *)&arg)
	);
}

static PyObject *
py_LM_GetThreadId(PyObject *self,
		  PyObject *args)
{
	py_lm_tid_obj *pytid;

	pytid = (py_lm_tid_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_tid_t);
	pytid->tid = LM_GetThreadId();

	return (PyObject *)pytid;
}

static PyObject *
py_LM_GetThreadIdEx(PyObject *self,
		    PyObject *args)
{
	py_lm_tid_obj     *pytid;
	py_lm_process_obj *pyproc;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;

	pytid = (py_lm_tid_obj *)PyObject_CallNoArgs((PyObject *)&py_lm_tid_t);
	pytid->tid = LM_GetThreadIdEx(pyproc->proc);

	return (PyObject *)pytid;
}

/****************************************/

typedef struct {
	PyObject *callback;
	PyObject *arg;
} py_lm_enum_modules_t;

static lm_bool_t
py_LM_EnumModulesCallback(lm_module_t  mod,
			  lm_tstring_t path,
			  lm_void_t   *arg)
{
	PyLongObject         *pyret;
	PyUnicodeObject      *pypath;
	py_lm_module_obj     *pymod;
	py_lm_enum_modules_t *parg = (py_lm_enum_modules_t *)arg;

	pymod = (py_lm_module_obj *)(
		PyObject_CallNoArgs((PyObject *)&py_lm_module_t)
	);
	pymod->mod = mod;

#	if LM_CHARSET == LM_CHARSET_UC
	pypath = (PyUnicodeObject *)PyUnicode_FromUnicode(path,
							  LM_STRLEN(path));
#	else
	pypath = (PyUnicodeObject *)PyUnicode_FromString(path);
#	endif

	pyret = (PyLongObject *)(
		PyObject_CallFunctionObjArgs(parg->callback,
					     pymod,
					     pypath,
					     parg->arg,
					     NULL)
	);

	return PyLong_AsLong((PyObject *)pyret) ? LM_TRUE : LM_FALSE;

	return LM_TRUE;
}

static PyObject *
py_LM_EnumModules(PyObject *self,
		  PyObject *args)
{
	py_lm_enum_modules_t arg;

	if (!PyArg_ParseTuple(args, "O|O", &arg.callback, &arg.arg))
		return NULL;
	
	return PyLong_FromLong(
		LM_EnumModules(py_LM_EnumModulesCallback,
			       (lm_void_t *)&arg)
	);
}

static PyObject *
py_LM_EnumModulesEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj   *pyproc;
	py_lm_enum_modules_t arg;

	if (!PyArg_ParseTuple(args, "O!|O|O", &py_lm_process_t, &pyproc,
			      &arg.callback, &arg.arg))
		return NULL;
	
	return PyLong_FromLong(
		LM_EnumModulesEx(pyproc->proc,
				 py_LM_EnumModulesCallback,
				 (lm_void_t *)&arg)
	);
}

/* Python Module */
static PyMethodDef libmem_methods[] = {
	{ "LM_EnumProcesses", py_LM_EnumProcesses, METH_VARARGS, "" },
	{ "LM_GetProcessId", py_LM_GetProcessId, METH_NOARGS, "" },
	{ "LM_GetProcessIdEx", py_LM_GetProcessIdEx, METH_VARARGS, "" },
	{ "LM_GetParentId", py_LM_GetParentId, METH_NOARGS, "" },
	{ "LM_GetParentIdEx", py_LM_GetParentIdEx, METH_VARARGS, "" },
	{ "LM_OpenProcess", py_LM_OpenProcess, METH_NOARGS, "" },
	{ "LM_OpenProcessEx", py_LM_OpenProcessEx, METH_VARARGS, "" },
	{ "LM_CloseProcess", py_LM_CloseProcess, METH_VARARGS, "" },
	{ "LM_GetProcessPath", py_LM_GetProcessPath, METH_NOARGS, "" },
	{ "LM_GetProcessPathEx", py_LM_GetProcessPathEx, METH_VARARGS, "" },
	{ "LM_GetProcessName", py_LM_GetProcessName, METH_NOARGS, "" },
	{ "LM_GetProcessNameEx", py_LM_GetProcessNameEx, METH_VARARGS, "" },
	{ "LM_GetSystemBits", py_LM_GetSystemBits, METH_NOARGS, "" },
	{ "LM_GetProcessBits", py_LM_GetProcessBits, METH_NOARGS, "" },
	{ "LM_GetProcessBitsEx", py_LM_GetProcessBitsEx, METH_VARARGS, "" },
	/****************************************/
	{ "LM_EnumThreads", py_LM_EnumThreads, METH_VARARGS, "" },
	{ "LM_EnumThreadsEx", py_LM_EnumThreadsEx, METH_VARARGS, "" },
	{ "LM_GetThreadId", py_LM_GetThreadId, METH_NOARGS, "" },
	{ "LM_GetThreadIdEx", py_LM_GetThreadIdEx, METH_VARARGS, "" },
	/****************************************/
	{ "LM_EnumModules", py_LM_EnumModules, METH_VARARGS, "" },
	{ "LM_EnumModulesEx", py_LM_EnumModulesEx, METH_VARARGS, "" },
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
	
	if (PyType_Ready(&py_lm_tid_t) < 0)
		goto _ERR_MOD;
	
	if (PyType_Ready(&py_lm_process_t) < 0)
		goto _ERR_MOD;
	
	if (PyType_Ready(&py_lm_module_t) < 0)
		goto _ERR_MOD;

	pymod = PyModule_Create(&libmem_mod);
	if (!pymod)
		goto _ERR_MOD;
	
	/* Global Variables */
	DECL_GLOBAL(pymod, "LM_OS_WIN", LM_OS_WIN);
	DECL_GLOBAL(pymod, "LM_OS_LINUX", LM_OS_LINUX);
	DECL_GLOBAL(pymod, "LM_OS_BSD", LM_OS_BSD);
	DECL_GLOBAL(pymod, "LM_OS", LM_OS);

	DECL_GLOBAL(pymod, "LM_ARCH_X86", LM_ARCH_X86);
	DECL_GLOBAL(pymod, "LM_ARCH_ARM", LM_ARCH_ARM);
	DECL_GLOBAL(pymod, "LM_ARCH", LM_ARCH);

	DECL_GLOBAL(pymod, "LM_BITS", LM_BITS);

	DECL_GLOBAL(pymod, "LM_COMPILER_MSVC", LM_COMPILER_MSVC);
	DECL_GLOBAL(pymod, "LM_COMPILER_CC", LM_COMPILER_CC);

	DECL_GLOBAL(pymod, "LM_CHARSET_UC", LM_CHARSET_UC);
	DECL_GLOBAL(pymod, "LM_CHARSET_MB", LM_CHARSET_MB);
	DECL_GLOBAL(pymod, "LM_CHARSET", LM_CHARSET);

	DECL_GLOBAL(pymod, "LM_LANG_C", LM_LANG_C);
	DECL_GLOBAL(pymod, "LM_LANG_CPP", LM_LANG_CPP);
	DECL_GLOBAL(pymod, "LM_LANG", LM_LANG);

	DECL_GLOBAL(pymod, "LM_PROT_R", LM_PROT_R);
	DECL_GLOBAL(pymod, "LM_PROT_W", LM_PROT_W);
	DECL_GLOBAL(pymod, "LM_PROT_X", LM_PROT_X);
	DECL_GLOBAL(pymod, "LM_PROT_RW", LM_PROT_RW);
	DECL_GLOBAL(pymod, "LM_PROT_XR", LM_PROT_XR);
	DECL_GLOBAL(pymod, "LM_PROT_XRW", LM_PROT_XRW);

	DECL_GLOBAL(pymod, "LM_NULL", LM_NULL);
	DECL_GLOBAL(pymod, "LM_NULLPTR", LM_NULLPTR);
	DECL_GLOBAL(pymod, "LM_FALSE", LM_FALSE);
	DECL_GLOBAL(pymod, "LM_TRUE", LM_TRUE);
	DECL_GLOBAL(pymod, "LM_BAD", LM_BAD);
	DECL_GLOBAL(pymod, "LM_OK", LM_OK);
	DECL_GLOBAL(pymod, "LM_MAX", LM_MAX);
	DECL_GLOBAL(pymod, "LM_PATH_MAX", LM_PATH_MAX);
	DECL_GLOBAL(pymod, "LM_MOD_BY_STR", LM_MOD_BY_STR);
	DECL_GLOBAL(pymod, "LM_MOD_BY_ADDR", LM_MOD_BY_ADDR);
	
	/* Types */
	Py_INCREF(&py_lm_pid_t);
	if (PyModule_AddObject(pymod, "lm_pid_t",
			       (PyObject *)&py_lm_pid_t) < 0)
		goto _ERR_PID;
	
	Py_INCREF(&py_lm_tid_t);
	if (PyModule_AddObject(pymod, "lm_tid_t",
			       (PyObject *)&py_lm_tid_t) < 0)
		goto _ERR_TID;
	
	Py_INCREF(&py_lm_process_t);
	if (PyModule_AddObject(pymod, "lm_process_t",
			       (PyObject *)&py_lm_process_t) < 0)
		goto _ERR_PROCESS;
	
	Py_INCREF(&py_lm_module_t);
	if (PyModule_AddObject(pymod, "lm_module_t",
			       (PyObject *)&py_lm_module_t) < 0)
		goto _ERR_MODULE;

	goto _RET; /* No Type Errors */
_ERR_MODULE:
	Py_DECREF(&py_lm_module_t);
	Py_DECREF(pymod);
_ERR_PROCESS:
	Py_DECREF(&py_lm_process_t);
	Py_DECREF(pymod);
_ERR_TID:
	Py_DECREF(&py_lm_tid_t);
	Py_DECREF(pymod);
_ERR_PID:
	Py_DECREF(&py_lm_pid_t);
	Py_DECREF(pymod);
_ERR_MOD:
	pymod = (PyObject *)NULL;
_RET:
	return pymod;
}
