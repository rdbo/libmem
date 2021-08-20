/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

#include <libmem.h>
#include <Python.h>
#include <structmember.h>

#define DECL_GLOBAL(mod, name, val) { \
	PyObject *global; \
	global = PyLong_FromLong((long)val); \
	PyObject_SetAttrString(mod, name, global); \
	Py_DECREF(global); \
}

#define PyErr_libmem() PyErr_Format(PyExc_RuntimeError, "libmem internal error")
#define PyErr_libmem_arg() PyErr_Format(PyExc_TypeError, "invalid argument(s)")
#define PyErr_libmem_nomem() PyErr_NoMemory()

/* Python Types */

typedef struct {
	PyObject_HEAD
	lm_process_t proc;
} py_lm_process_obj;

static PyMemberDef py_lm_process_members[] = {
	{ "pid", T_INT, offsetof(py_lm_process_obj, proc.pid), 0, "" },
#	if LM_OS == LM_OS_WIN
	{ "handle", T_INT, offsetof(py_lm_process_obj, proc.handle), 0, "" },
#	endif
	{ NULL }
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
	{ "size", T_ULONG, offsetof(py_lm_module_obj, mod.size), 0, "" },
	{ NULL }
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

/****************************************/

typedef struct {
	PyObject_HEAD
	lm_page_t page;
} py_lm_page_obj;

static PyMemberDef py_lm_page_members[] = {
	{ "base", T_ULONG, offsetof(py_lm_page_obj, page.base), 0, "" },
	{ "end", T_ULONG, offsetof(py_lm_page_obj, page.end), 0, "" },
	{ "size", T_ULONG, offsetof(py_lm_page_obj, page.size), 0, "" },
	{ "prot", T_INT, offsetof(py_lm_page_obj, page.prot), 0, "" },
	{ "flags", T_INT, offsetof(py_lm_page_obj, page.flags), 0, "" },
	{ NULL }
};

static PyTypeObject py_lm_page_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_page_t",
	.tp_doc = "",
	.tp_basicsize = sizeof(py_lm_page_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_page_members
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
	PyLongObject           *pypid;
	PyLongObject           *pyret;
	lm_bool_t               ret;

	pypid = (PyLongObject *)PyLong_FromPid(pid);
	
	pyret = (PyLongObject *)(
		PyObject_CallFunctionObjArgs(parg->callback,
					     pypid,
					     parg->arg,
					     NULL)
	);

	ret = PyLong_AsLong((PyObject *)pyret) ? LM_TRUE : LM_FALSE;

	Py_DECREF(pypid);
	Py_DECREF(pyret);

	return ret;
}

static PyObject *
py_LM_EnumProcesses(PyObject *self,
		    PyObject *args)
{
	py_lm_enum_processes_t arg;

	if (!PyArg_ParseTuple(args, "O|O", &arg.callback, &arg.arg))
		return NULL;
	
	if (!LM_EnumProcesses(py_LM_EnumProcessesCallback,
			      (lm_void_t *)&arg))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_GetProcessId(PyObject *self,
		   PyObject *args)
{
	lm_pid_t pid;

	pid = LM_GetProcessId();
	if (pid == (lm_pid_t)LM_BAD) {
		PyErr_libmem();
		return NULL;
	}

	return (PyObject *)PyLong_FromPid(pid);
}

static PyObject *
py_LM_GetProcessIdEx(PyObject *self,
		     PyObject *args)
{
	lm_tchar_t    *procstr;
	lm_pid_t       pid;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "u", &procstr))
			return NULL;
#	else
	if (!PyArg_ParseTuple(args, "s", &procstr))
		return NULL;
#	endif

	pid = LM_GetProcessIdEx(procstr);
	if (pid == (lm_pid_t)LM_BAD)
		return PyErr_libmem();

	return (PyObject *)PyLong_FromPid(pid);
}

static PyObject *
py_LM_GetParentId(PyObject *self,
		  PyObject *args)
{
	return PyLong_FromPid(LM_GetParentId());
}

static PyObject *
py_LM_GetParentIdEx(PyObject *self,
		    PyObject *args)
{
	long pypid;

	if (!PyArg_ParseTuple(args, "l", &pypid))
		return NULL;

	return PyLong_FromPid(LM_GetParentIdEx((lm_pid_t)pypid));
}

static PyObject *
py_LM_CheckProcess(PyObject *self,
		   PyObject *args)
{
	long pid;

	if (!PyArg_ParseTuple(args, "l", &pid))
		return NULL;
	
	return PyBool_FromLong(LM_CheckProcess((lm_pid_t)pid));
}

static PyObject *
py_LM_OpenProcess(PyObject *self,
		  PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_process_t       proc;

	if (!LM_OpenProcess(&proc))
		PyErr_libmem();

	pyproc = (py_lm_process_obj *)PyObject_CallObject((PyObject *)&py_lm_process_t, NULL);
	pyproc->proc = proc;
	
	return (PyObject *)pyproc;
}

static PyObject *
py_LM_OpenProcessEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	long               pypid;
	lm_process_t       proc;

	if (!PyArg_ParseTuple(args, "l", &pypid))
		return NULL;

	if (!LM_OpenProcessEx((lm_pid_t)pypid, &proc))
		return PyErr_libmem();

	pyproc = (py_lm_process_obj *)PyObject_CallObject((PyObject *)&py_lm_process_t, NULL);
	pyproc->proc = proc;
	
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

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_GetProcessPath(PyObject *self,
		     PyObject *args)
{
	PyObject        *pystr;
	lm_tchar_t      *pathbuf;
	lm_size_t        length;

	pathbuf = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!pathbuf)
		return PyErr_libmem_nomem();
	
	length = LM_GetProcessPath(pathbuf, LM_PATH_MAX);
	if (!length) {
		pystr = PyErr_libmem();
		goto _FREE_RET;
	}
	
#	if LM_CHARSET == LM_CHARSET_UC
	pystr = PyUnicode_FromUnicode(pathbuf, length);
#	else
	pystr = PyUnicode_FromString(pathbuf);
#	endif

_FREE_RET:
	LM_FREE(pathbuf);
	return pystr;
}

static PyObject *
py_LM_GetProcessPathEx(PyObject *self,
		       PyObject *args)
{
	PyObject          *pystr;
	py_lm_process_obj *pyproc;
	lm_tchar_t        *pathbuf;
	lm_size_t          length;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;

	pathbuf = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!pathbuf)
		return PyErr_libmem_nomem();
	
	length = LM_GetProcessPathEx(pyproc->proc, pathbuf, LM_PATH_MAX);
	if (!length) {
		pystr = PyErr_libmem();
		goto _FREE_RET;
	}
	
#	if LM_CHARSET == LM_CHARSET_UC
	pystr = PyUnicode_FromUnicode(pathbuf, length);
#	else
	pystr = PyUnicode_FromString(pathbuf);
#	endif

_FREE_RET:
	LM_FREE(pathbuf);
	return pystr;
}

static PyObject *
py_LM_GetProcessName(PyObject *self,
		     PyObject *args)
{
	PyObject        *pystr;
	lm_tchar_t      *namebuf;
	lm_size_t        length;

	namebuf = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!namebuf)
		return PyErr_libmem_nomem();
	
	length = LM_GetProcessName(namebuf, LM_PATH_MAX);
	if (!length) {
		pystr = PyErr_libmem();
		goto _FREE_RET;
	}
	
#	if LM_CHARSET == LM_CHARSET_UC
	pystr = PyUnicode_FromUnicode(namebuf, length);
#	else
	pystr = PyUnicode_FromString(namebuf);
#	endif

_FREE_RET:
	LM_FREE(namebuf);
	return pystr;
}

static PyObject *
py_LM_GetProcessNameEx(PyObject *self,
		       PyObject *args)
{
	PyObject          *pystr;
	py_lm_process_obj *pyproc;
	lm_tchar_t        *namebuf;
	lm_size_t          length;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;

	namebuf = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!namebuf)
		return PyErr_libmem_nomem();
	
	length = LM_GetProcessNameEx(pyproc->proc, namebuf, LM_PATH_MAX);
	if (!length) {
		pystr = PyErr_libmem();
		goto _FREE_RET;
	}
	
#	if LM_CHARSET == LM_CHARSET_UC
	pystr = PyUnicode_FromUnicode(namebuf, length);
#	else
	pystr = PyUnicode_FromString(namebuf);
#	endif

_FREE_RET:
	LM_FREE(namebuf);
	return pystr;
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
	lm_size_t          bits;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;
	
	bits = LM_GetProcessBitsEx(pyproc->proc);
	if (!bits)
		return PyErr_libmem();

	return PyLong_FromLong(bits);
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
	PyObject             *pyret;
	PyObject             *pytid;
	py_lm_enum_threads_t *parg = (py_lm_enum_threads_t *)arg;
	lm_bool_t             ret;

	pytid = PyLong_FromLong((long)tid);

	pyret = PyObject_CallFunctionObjArgs(parg->callback,
					     pytid,
					     parg->arg,
					     NULL);
	
	ret = PyLong_AsLong(pyret) ? LM_TRUE : LM_FALSE;

	Py_DECREF(pytid);
	Py_DECREF(pyret);

	return ret;
}

static PyObject *
py_LM_EnumThreads(PyObject *self,
		  PyObject *args)
{
	py_lm_enum_threads_t arg;

	if (!PyArg_ParseTuple(args, "O|O", &arg.callback, &arg.arg))
		return NULL;
	
	if (!LM_EnumThreads(py_LM_EnumThreadsCallback,
			    (lm_void_t *)&arg))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_EnumThreadsEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj   *pyproc;
	py_lm_enum_threads_t arg;

	if (!PyArg_ParseTuple(args, "O!O|O", &py_lm_process_t, &pyproc,
			      &arg.callback, &arg.arg))
		return NULL;
	
	if (!LM_EnumThreadsEx(pyproc->proc,
			      py_LM_EnumThreadsCallback,
			      (lm_void_t *)&arg))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_GetThreadId(PyObject *self,
		  PyObject *args)
{
	lm_tid_t tid;

	tid = LM_GetThreadId();
	if (tid == (lm_tid_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromLong((long)tid);
}

static PyObject *
py_LM_GetThreadIdEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_tid_t           tid;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_process_t, &pyproc))
		return NULL;

	tid = LM_GetThreadIdEx(pyproc->proc);
	if (tid == (lm_tid_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromLong((long)tid);
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
	PyObject             *pyret;
	PyObject             *pypath;
	py_lm_module_obj     *pymod;
	py_lm_enum_modules_t *parg = (py_lm_enum_modules_t *)arg;
	lm_bool_t             ret;

	pymod = (py_lm_module_obj *)(
		PyObject_CallObject((PyObject *)&py_lm_module_t, NULL)
	);
	pymod->mod = mod;

#	if LM_CHARSET == LM_CHARSET_UC
	pypath = PyUnicode_FromUnicode(path, LM_STRLEN(path));
#	else
	pypath = PyUnicode_FromString(path);
#	endif

	pyret = PyObject_CallFunctionObjArgs(parg->callback,
					     pymod,
					     pypath,
					     parg->arg,
					     NULL);
	
	ret = PyLong_AsLong(pyret) ? LM_TRUE : LM_FALSE;

	Py_DECREF(pymod);
	Py_DECREF(pyret);

	return ret;
}

static PyObject *
py_LM_EnumModules(PyObject *self,
		  PyObject *args)
{
	py_lm_enum_modules_t arg;

	if (!PyArg_ParseTuple(args, "O|O", &arg.callback, &arg.arg))
		return NULL;
	
	if (!LM_EnumModules(py_LM_EnumModulesCallback, (lm_void_t *)&arg))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_EnumModulesEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj   *pyproc;
	py_lm_enum_modules_t arg;

	if (!PyArg_ParseTuple(args, "O!O|O", &py_lm_process_t, &pyproc,
			      &arg.callback, &arg.arg))
		return NULL;
	
	if (!LM_EnumModulesEx(pyproc->proc,
			      py_LM_EnumModulesCallback,
			      (lm_void_t *)&arg))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_GetModule(PyObject *self,
		PyObject *args)
{
	py_lm_module_obj *pymod;
	lm_module_t       mod;
	PyObject         *pymodarg;
	lm_void_t        *modarg;
	long              flags;

	if (!PyArg_ParseTuple(args, "lO", &flags, &pymodarg))
		return NULL;

	if (flags == (long)LM_MOD_BY_STR) {
#		if LM_CHARSET == LM_CHARSET_UC
		modarg = (lm_void_t *)(PyUnicode_AsUnicode(pymodarg));
#		else
		modarg = (lm_void_t *)(PyUnicode_AsUTF8(pymodarg));
#		endif
	} else if (flags == (long)LM_MOD_BY_ADDR) {
		modarg = (lm_void_t *)PyLong_AsLong(pymodarg);
	} else {
		return PyErr_libmem_arg();
	}

	if (!LM_GetModule((lm_int_t)flags, modarg, &mod))
		return PyErr_libmem();
	
	pymod = (py_lm_module_obj *)(
		PyObject_CallObject((PyObject *)&py_lm_module_t, NULL)
	);

	pymod->mod = mod;

	return (PyObject *)pymod;
}

static PyObject *
py_LM_GetModuleEx(PyObject *self,
		  PyObject *args)
{
	py_lm_module_obj  *pymod;
	lm_module_t        mod;
	py_lm_process_obj *pyproc;
	PyObject          *pymodarg;
	lm_void_t         *modarg;
	long               flags;

	if (!PyArg_ParseTuple(args, "O!lO", &py_lm_process_t, &pyproc,
			      &flags, &pymodarg))
		return NULL;

	if (flags == (long)LM_MOD_BY_STR) {
#		if LM_CHARSET == LM_CHARSET_UC
		modarg = (lm_void_t *)(PyUnicode_AsUnicode(pymodarg));
#		else
		modarg = (lm_void_t *)(PyUnicode_AsUTF8(pymodarg));
#		endif
	} else if (flags == (long)LM_MOD_BY_ADDR) {
		modarg = (lm_void_t *)PyLong_AsLong(pymodarg);
	} else {
		return PyErr_libmem_arg();
	}

	if (!LM_GetModuleEx(pyproc->proc, (lm_int_t)flags, modarg, &mod))
		return PyErr_libmem();
	
	pymod = (py_lm_module_obj *)(
		PyObject_CallObject((PyObject *)&py_lm_module_t, NULL)
	);

	pymod->mod = mod;

	return (PyObject *)pymod;
}

static PyObject *
py_LM_GetModulePath(PyObject *self,
		    PyObject *args)
{
	PyObject         *pymodpath;
	py_lm_module_obj *pymod;
	lm_tchar_t       *modpath;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_module_t, &pymod))
		return NULL;
	
	modpath = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!modpath)
		return PyErr_libmem_nomem();
	
	if (!LM_GetModulePath(pymod->mod, modpath, LM_PATH_MAX)) {
		pymodpath = PyErr_libmem();
		goto _FREE_RET;
	}

#	if LM_CHARSET == LM_CHARSET_UC
	pymodpath = PyUnicode_FromUnicode(modpath);
#	else
	pymodpath = PyUnicode_FromString(modpath);
#	endif

_FREE_RET:
	LM_FREE(modpath);

	return pymodpath;
}

static PyObject *
py_LM_GetModulePathEx(PyObject *self,
		      PyObject *args)
{
	PyObject          *pymodpath;
	py_lm_process_obj *pyproc;
	py_lm_module_obj  *pymod;
	lm_tchar_t        *modpath;

	if (!PyArg_ParseTuple(args, "O!O!", &py_lm_process_t, &pyproc,
			      &py_lm_module_t, &pymod))
		return NULL;
	
	modpath = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!modpath)
		return PyErr_libmem_nomem();
	
	if (!LM_GetModulePathEx(pyproc->proc, pymod->mod,
				modpath, LM_PATH_MAX)) {
		pymodpath = PyErr_libmem();
		goto _FREE_RET;
	}

#	if LM_CHARSET == LM_CHARSET_UC
	pymodpath = PyUnicode_FromUnicode(modpath);
#	else
	pymodpath = PyUnicode_FromString(modpath);
#	endif

_FREE_RET:
	LM_FREE(modpath);

	return pymodpath;
}

static PyObject *
py_LM_GetModuleName(PyObject *self,
		    PyObject *args)
{
	PyObject         *pymodname;
	py_lm_module_obj *pymod;
	lm_tchar_t       *modname;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_module_t, &pymod))
		return NULL;
	
	modname = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!modname)
		return PyErr_libmem_nomem();
	
	if (!LM_GetModuleName(pymod->mod, modname, LM_PATH_MAX)) {
		pymodname = PyErr_libmem();
		goto _FREE_RET;
	}

#	if LM_CHARSET == LM_CHARSET_UC
	pymodname = PyUnicode_FromUnicode(modname);
#	else
	pymodname = PyUnicode_FromString(modname);
#	endif

_FREE_RET:
	LM_FREE(modname);

	return pymodname;
}

static PyObject *
py_LM_GetModuleNameEx(PyObject *self,
		      PyObject *args)
{
	PyObject          *pymodname;
	py_lm_process_obj *pyproc;
	py_lm_module_obj  *pymod;
	lm_tchar_t        *modname;

	if (!PyArg_ParseTuple(args, "O!O!", &py_lm_process_t, &pyproc,
			      &py_lm_module_t, &pymod))
		return NULL;
	
	modname = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!modname)
		return PyErr_libmem_nomem();
	
	if (!LM_GetModuleNameEx(pyproc->proc, pymod->mod,
				modname, LM_PATH_MAX)) {
		pymodname = PyErr_libmem();
		goto _FREE_RET;
	}

#	if LM_CHARSET == LM_CHARSET_UC
	pymodname = PyUnicode_FromUnicode(modname);
#	else
	pymodname = PyUnicode_FromString(modname);
#	endif

_FREE_RET:
	LM_FREE(modname);

	return pymodname;
}

static PyObject *
py_LM_LoadModule(PyObject *self,
		 PyObject *args)
{
	lm_tchar_t       *modpath;
	py_lm_module_obj *pymod;
	lm_module_t       modbuf;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "u", &modpath))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "s", &modpath))
		return NULL;
#	endif

	if (!LM_LoadModule(modpath, &modbuf)) 
		return PyErr_libmem();

	pymod = (py_lm_module_obj *)(
		PyObject_CallObject((PyObject *)&py_lm_module_t, NULL)
	);
	pymod->mod = modbuf;

	return (PyObject *)pymod;
}

static PyObject *
py_LM_LoadModuleEx(PyObject *self,
		   PyObject *args)
{
	lm_tchar_t        *modpath;
	py_lm_process_obj *pyproc;
	py_lm_module_obj  *pymod;
	lm_module_t        modbuf;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "u", &modpath))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "O!s", &py_lm_process_t, &pyproc,
			      &modpath))
		return NULL;
#	endif

	if (!LM_LoadModuleEx(pyproc->proc, modpath, &modbuf)) 
		return PyErr_libmem();

	pymod = (py_lm_module_obj *)(
		PyObject_CallObject((PyObject *)&py_lm_module_t, NULL)
	);
	pymod->mod = modbuf;

	return (PyObject *)pymod;
}

static PyObject *
py_LM_UnloadModule(PyObject *self,
		   PyObject *args)
{
	py_lm_module_obj *pymod;

	if (!PyArg_ParseTuple(args, "O!", &py_lm_module_t, &pymod))
		return NULL;
	
	if (!LM_UnloadModule(pymod->mod))
		return PyErr_libmem();
	
	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_UnloadModuleEx(PyObject *self,
		     PyObject *args)
{
	py_lm_process_obj *pyproc;
	py_lm_module_obj  *pymod;

	if (!PyArg_ParseTuple(args, "O!O!", &py_lm_process_t, &pyproc,
			      &py_lm_module_t, &pymod))
		return NULL;
	
	if (!LM_UnloadModuleEx(pyproc->proc, pymod->mod))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

/****************************************/

typedef struct {
	PyObject *callback;
	PyObject *arg;
} py_lm_enum_symbols_t;

static lm_bool_t py_LM_EnumSymbolsCallback(lm_cstring_t symbol,
					   lm_address_t addr,
					   lm_void_t   *arg)
{
	py_lm_enum_symbols_t *parg = (py_lm_enum_symbols_t *)arg;
	PyObject             *pysymbol;
	PyObject             *pyaddr;
	PyObject             *pyret;
	lm_bool_t             ret;

	pysymbol = PyUnicode_FromString(symbol);

	if (!pysymbol) {
		/* UTF-8 Decoding Failed */
		PyErr_Clear();
		return LM_TRUE;
	}

	pyaddr = PyLong_FromVoidPtr(addr);

	pyret = PyObject_CallFunctionObjArgs(parg->callback,
					     pysymbol,
					     pyaddr,
					     parg->arg,
					     NULL);

	ret = PyLong_AsLong(pyret) ? LM_TRUE : LM_FALSE;

	Py_DECREF(pysymbol);
	Py_DECREF(pyaddr);
	Py_DECREF(pyret);

	return ret;
}


static PyObject *
py_LM_EnumSymbols(PyObject *self,
		  PyObject *args)
{
	py_lm_enum_symbols_t arg;
	py_lm_module_obj    *pymod;

	if (!PyArg_ParseTuple(args, "O!O|O", &py_lm_module_t, &pymod,
			      &arg.callback,
			      &arg.arg))
		return NULL;
	
	if (!LM_EnumSymbols(pymod->mod,
			    py_LM_EnumSymbolsCallback,
			    (lm_void_t *)&arg))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_EnumSymbolsEx(PyObject *self,
		    PyObject *args)
{
	py_lm_enum_symbols_t arg;
	py_lm_process_obj   *pyproc;
	py_lm_module_obj    *pymod;

	if (!PyArg_ParseTuple(args, "O!O!O|O", &py_lm_process_t, &pyproc,
			      &py_lm_module_t, &pymod,
			      &arg.callback,
			      &arg.arg))
		return NULL;
	
	if (!LM_EnumSymbolsEx(pyproc->proc, pymod->mod,
			      py_LM_EnumSymbolsCallback,
			      (lm_void_t *)&arg))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_GetSymbol(PyObject *self,
		PyObject *args)
{
	py_lm_module_obj *pymod;
	lm_cstring_t      symstr;
	lm_address_t      symaddr;

	if (!PyArg_ParseTuple(args, "O!s", &py_lm_module_t, &pymod,
			      &symstr))
		return NULL;
	
	symaddr = LM_GetSymbol(pymod->mod, symstr);
	if (symaddr == (lm_address_t)LM_BAD)
		return PyErr_libmem();
	
	return PyLong_FromVoidPtr(symaddr);
}

static PyObject *
py_LM_GetSymbolEx(PyObject *self,
		  PyObject *args)
{
	py_lm_process_obj *pyproc;
	py_lm_module_obj  *pymod;
	lm_cstring_t       symstr;
	lm_address_t       symaddr;

	if (!PyArg_ParseTuple(args, "O!O!s", &py_lm_process_t, &pyproc,
			      &py_lm_module_t, &pymod,
			      &symstr))
		return NULL;
	
	symaddr = LM_GetSymbolEx(pyproc->proc, pymod->mod, symstr);
	
	return PyLong_FromVoidPtr(symaddr);
}

/****************************************/

typedef struct {
	PyObject *callback;
	PyObject *arg;
} py_lm_enum_pages_t;

static lm_bool_t
py_LM_EnumPagesCallback(lm_page_t  page,
			lm_void_t *arg)
{
	py_lm_enum_pages_t *parg = (py_lm_enum_pages_t *)arg;
	py_lm_page_obj     *pypage;
	PyObject           *pyret;
	lm_bool_t           ret;

	pypage = (py_lm_page_obj *)(
		PyObject_CallObject((PyObject *)&py_lm_page_t, NULL)
	);
	pypage->page = page;

	pyret = PyObject_CallFunctionObjArgs(parg->callback,
					     pypage,
					     parg->arg);
	
	ret = PyLong_AsLong(pyret) ? LM_TRUE : LM_FALSE;

	Py_DECREF(pypage);
	Py_DECREF(pyret);

	return ret;
}

static PyObject *
py_LM_EnumPages(PyObject *self,
		PyObject *args)
{
	py_lm_enum_pages_t arg;

	if (!PyArg_ParseTuple(args, "O|O", &arg.callback,
			      &arg.arg))
		return NULL;
	
	if (!LM_EnumPages(py_LM_EnumPagesCallback,
			  (lm_void_t *)&arg))
		return PyErr_libmem();
	
	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_EnumPagesEx(PyObject *self,
		  PyObject *args)
{
	py_lm_enum_pages_t arg;
	py_lm_process_obj *pyproc;

	if (!PyArg_ParseTuple(args, "O!O|O", &py_lm_process_t, &pyproc,
			      &arg.callback,
			      &arg.arg))
		return NULL;
	
	if (!LM_EnumPagesEx(pyproc->proc,
			    py_LM_EnumPagesCallback,
			    (lm_void_t *)&arg))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_GetPage(PyObject *self,
	      PyObject *args)
{
	py_lm_page_obj *pypage;
	lm_page_t       page;
	unsigned long   addr;

	if (!PyArg_ParseTuple(args, "k", &addr))
		return NULL;
	
	if (!LM_GetPage((lm_address_t)(lm_uintptr_t)addr, &page))
		return PyErr_libmem();
	
	pypage = (py_lm_page_obj *)(
		PyObject_CallObject((PyObject *)&py_lm_page_t, NULL)
	);
	pypage->page = page;

	return (PyObject *)pypage;
}

static PyObject *
py_LM_GetPageEx(PyObject *self,
		PyObject *args)
{
	py_lm_process_obj *pyproc;
	py_lm_page_obj    *pypage;
	lm_page_t          page;
	unsigned long      addr;

	if (!PyArg_ParseTuple(args, "O!k", &py_lm_process_t, &pyproc,
			      &addr))
		return NULL;
	
	if (!LM_GetPageEx(pyproc->proc,
			  (lm_address_t)(lm_uintptr_t)addr,
			  &page))
		return PyErr_libmem();
	
	pypage = (py_lm_page_obj *)(
		PyObject_CallObject((PyObject *)&py_lm_page_t, NULL)
	);
	pypage->page = page;

	return (PyObject *)pypage;
}

/****************************************/

static PyObject *
py_LM_ReadMemory(PyObject *self,
		 PyObject *args)
{
	unsigned long src;
	unsigned long size;
	char         *dst;
	PyObject     *ret;

	if (!PyArg_ParseTuple(args, "kk", &src, &size))
		return NULL;
	
	dst = LM_MALLOC(size);
	if (!dst)
		return PyErr_libmem_nomem();

	if (LM_ReadMemory((lm_address_t)src,
			  (lm_byte_t *)dst,
			  (lm_size_t)size) != (lm_size_t)size) {
		ret = PyErr_libmem();
		goto _FREE_RET;
	}

	ret = PyByteArray_FromStringAndSize(dst, size);

_FREE_RET:
	LM_FREE(dst);

	return ret;
}

static PyObject *
py_LM_ReadMemoryEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	unsigned long      src;
	unsigned long      size;
	char              *dst;
	PyObject          *ret;

	if (!PyArg_ParseTuple(args, "O!kk", &py_lm_process_t, &pyproc,
			      &src, &size))
		return NULL;
	
	dst = LM_MALLOC(size);
	if (!dst)
		return PyErr_libmem_nomem();

	if (LM_ReadMemoryEx(pyproc->proc,
			    (lm_address_t)src,
			    (lm_byte_t *)dst,
			    (lm_size_t)size) != (lm_size_t)size) {
		ret = PyErr_libmem();
		goto _FREE_RET;
	}

	ret = PyByteArray_FromStringAndSize(dst, size);

_FREE_RET:
	LM_FREE(dst);

	return ret;
}

static PyObject *
py_LM_WriteMemory(PyObject *self,
		  PyObject *args)
{
	unsigned long dst;
	Py_buffer     buf;

	if (!PyArg_ParseTuple(args, "ks*", &dst, &buf))
		return NULL;
	
	if (LM_WriteMemory((lm_address_t)dst,
			   (lm_bstring_t)buf.buf,
			   (lm_size_t)buf.len) != (lm_size_t)buf.len)
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_WriteMemoryEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	unsigned long      dst;
	Py_buffer          buf;

	if (!PyArg_ParseTuple(args, "O!ks*", &py_lm_process_t, &pyproc,
			      &dst, &buf))
		return NULL;
	
	if (LM_WriteMemoryEx(pyproc->proc,
			     (lm_address_t)dst,
			     (lm_bstring_t)buf.buf,
			     (lm_size_t)buf.len) != (lm_size_t)buf.len)
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_SetMemory(PyObject *self,
		PyObject *args)
{
	unsigned long dst;
	char          byte;
	unsigned long size;

	if (!PyArg_ParseTuple(args, "kck", &dst, &byte, &size))
		return NULL;
	
	if (LM_SetMemory((lm_byte_t *)dst,
			 (lm_byte_t)byte,
			 (lm_size_t)size) != (lm_size_t)size)
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_SetMemoryEx(PyObject *self,
		  PyObject *args)
{
	py_lm_process_obj *pyproc;
	unsigned long      dst;
	char               byte;
	unsigned long      size;

	if (!PyArg_ParseTuple(args, "O!kck", &py_lm_process_t, &pyproc,
			      &dst, &byte, &size))
		return NULL;
	
	if (LM_SetMemoryEx(pyproc->proc,
			   (lm_byte_t *)dst,
			   (lm_byte_t)byte,
			   (lm_size_t)size) != (lm_size_t)size)
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_ProtMemory(PyObject *self,
		 PyObject *args)
{
	unsigned long addr;
	unsigned long size;
	long          prot;
	lm_prot_t     old_prot = 0;

	if (!PyArg_ParseTuple(args, "kkl", &addr, &size, &prot))
		return NULL;
	
	if (!LM_ProtMemory((lm_address_t)addr,
			   (lm_size_t)size,
			   (lm_prot_t)prot,
			   &old_prot))
		return PyErr_libmem();
	
	return PyLong_FromLong(old_prot);
}

static PyObject *
py_LM_ProtMemoryEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	unsigned long      addr;
	unsigned long      size;
	long               prot;
	lm_prot_t          old_prot = 0;

	if (!PyArg_ParseTuple(args, "O!kkl", &py_lm_process_t, &pyproc,
			      &addr, &size, &prot))
		return NULL;
	
	if (!LM_ProtMemoryEx(pyproc->proc,
			     (lm_address_t)addr,
			     (lm_size_t)size,
			     (lm_prot_t)prot,
			     &old_prot))
		return PyErr_libmem();
	
	return PyLong_FromLong(old_prot);
}

static PyObject *
py_LM_AllocMemory(PyObject *self,
		  PyObject *args)
{
	unsigned long size;
	long          prot;
	lm_address_t  alloc;

	if (!PyArg_ParseTuple(args, "kl", &size, &prot))
		return NULL;
	
	alloc = LM_AllocMemory((lm_size_t)size, (lm_prot_t)prot);
	if (alloc == (lm_address_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromVoidPtr(alloc);
}

static PyObject *
py_LM_AllocMemoryEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	unsigned long      size;
	long               prot;
	lm_address_t       alloc;

	if (!PyArg_ParseTuple(args, "O!kl", &py_lm_process_t, &pyproc,
			      &size, &prot))
		return NULL;

	alloc = LM_AllocMemoryEx(pyproc->proc,
				 (lm_size_t)size,
				 (lm_prot_t)prot);
	
	if (alloc == (lm_address_t)LM_BAD)
		return PyErr_libmem();
	
	return PyLong_FromVoidPtr(alloc);
}

static PyObject *
py_LM_FreeMemory(PyObject *self,
		 PyObject *args)
{
	unsigned long alloc;
	unsigned long size;

	if (!PyArg_ParseTuple(args, "kk", &alloc, &size))
		return NULL;
	
	if (!LM_FreeMemory((lm_address_t)alloc, (lm_size_t)size))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_FreeMemoryEx(PyObject *self,
		   PyObject *args)
{
	py_lm_process_obj *pyproc;
	unsigned long      alloc;
	unsigned long      size;

	if (!PyArg_ParseTuple(args, "O!kk", &py_lm_process_t, &pyproc,
			      &alloc, &size))
		return NULL;
	
	if (!LM_FreeMemoryEx(pyproc->proc,
			     (lm_address_t)alloc,
			     (lm_size_t)size))
		return PyErr_libmem();

	return PyBool_FromLong(LM_TRUE);
}

static PyObject *
py_LM_DataScan(PyObject *self,
	       PyObject *args)
{
	Py_buffer     buf;
	unsigned long start;
	unsigned long stop;
	lm_address_t  scan;

	if (!PyArg_ParseTuple(args, "s*kk", &buf, &start, &stop))
		return NULL;
	
	scan = LM_DataScan((lm_bstring_t)buf.buf,
			   (lm_size_t)buf.len,
			   (lm_address_t)start,
			   (lm_address_t)stop);

	if (scan == (lm_address_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromVoidPtr(scan);
}

static PyObject *
py_LM_DataScanEx(PyObject *self,
		 PyObject *args)
{
	py_lm_process_obj *pyproc;
	Py_buffer          buf;
	unsigned long      start;
	unsigned long      stop;
	lm_address_t       scan;

	if (!PyArg_ParseTuple(args, "O!s*kk", &py_lm_process_t, &pyproc,
			      &buf, &start, &stop))
		return NULL;
	
	scan = LM_DataScanEx(pyproc->proc,
			     (lm_bstring_t)buf.buf,
			     (lm_size_t)buf.len,
			     (lm_address_t)start,
			     (lm_address_t)stop);

	if (scan == (lm_address_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromVoidPtr(scan);
}

static PyObject *
py_LM_PatternScan(PyObject *self,
		  PyObject *args)
{
	Py_buffer     pattern;
	lm_tstring_t  mask;
	unsigned long start;
	unsigned long stop;
	lm_address_t  scan;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "s*ukk", &pattern, &mask, &start, &stop))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "s*skk", &pattern, &mask, &start, &stop))
		return NULL;
#	endif

	scan = LM_PatternScan((lm_bstring_t)pattern.buf,
			       mask,
			       (lm_address_t)start,
			       (lm_address_t)stop);

	if (scan == (lm_address_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromVoidPtr(scan);
}

static PyObject *
py_LM_PatternScanEx(PyObject *self,
		    PyObject *args)
{
	py_lm_process_obj *pyproc;
	Py_buffer          pattern;
	lm_tstring_t       mask;
	unsigned long      start;
	unsigned long      stop;
	lm_address_t       scan;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "O!s*ukk", &py_lm_process_t, &pyproc,
			      &pattern, &mask, &start, &stop))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "O!s*skk", &py_lm_process_t, &pyproc,
			      &pattern, &mask, &start, &stop))
		return NULL;
#	endif

	scan = LM_PatternScanEx(pyproc->proc,
				 (lm_bstring_t)pattern.buf,
				 mask,
				 (lm_address_t)start,
				 (lm_address_t)stop);

	if (scan == (lm_address_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromVoidPtr(scan);
}

static PyObject *
py_LM_SigScan(PyObject *self,
	      PyObject *args)
{
	lm_tstring_t  sig;
	unsigned long start;
	unsigned long stop;
	lm_address_t  scan;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "ukk", &sig, &start, &stop))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "skk", &sig, &start, &stop))
		return NULL;
#	endif

	scan = LM_SigScan(sig, (lm_address_t)start, (lm_address_t)stop);
	if (scan == (lm_address_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromVoidPtr(scan);
}

static PyObject *
py_LM_SigScanEx(PyObject *self,
		PyObject *args)
{
	py_lm_process_obj *pyproc;
	lm_tstring_t       sig;
	unsigned long      start;
	unsigned long      stop;
	lm_address_t       scan;

#	if LM_CHARSET == LM_CHARSET_UC
	if (!PyArg_ParseTuple(args, "O!ukk", &py_lm_process_t, &pyproc,
			      &sig, &start, &stop))
		return NULL;
#	else
	if (!PyArg_ParseTuple(args, "O!skk", &py_lm_process_t, &pyproc,
			      &sig, &start, &stop))
		return NULL;
#	endif

	scan = LM_SigScanEx(pyproc->proc,
			     sig,
			     (lm_address_t)start,
			     (lm_address_t)stop);
	
	if (scan == (lm_address_t)LM_BAD)
		return PyErr_libmem();

	return PyLong_FromVoidPtr(scan);
}

/* Python Module */
static PyMethodDef libmem_methods[] = {
	{ "LM_EnumProcesses", py_LM_EnumProcesses, METH_VARARGS, "" },
	{ "LM_GetProcessId", py_LM_GetProcessId, METH_NOARGS, "" },
	{ "LM_GetProcessIdEx", py_LM_GetProcessIdEx, METH_VARARGS, "" },
	{ "LM_GetParentId", py_LM_GetParentId, METH_NOARGS, "" },
	{ "LM_GetParentIdEx", py_LM_GetParentIdEx, METH_VARARGS, "" },
	{ "LM_CheckProcess", py_LM_CheckProcess, METH_VARARGS, "" },
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
	{ "LM_GetModule", py_LM_GetModule, METH_VARARGS, "" },
	{ "LM_GetModuleEx", py_LM_GetModuleEx, METH_VARARGS, "" },
	{ "LM_GetModulePath", py_LM_GetModulePath, METH_VARARGS, "" },
	{ "LM_GetModulePathEx", py_LM_GetModulePathEx, METH_VARARGS, "" },
	{ "LM_GetModuleName", py_LM_GetModuleName, METH_VARARGS, "" },
	{ "LM_GetModuleNameEx", py_LM_GetModuleNameEx, METH_VARARGS, "" },
	{ "LM_LoadModule", py_LM_LoadModule, METH_VARARGS, "" },
	{ "LM_LoadModuleEx", py_LM_LoadModuleEx, METH_VARARGS, "" },
	{ "LM_UnloadModule", py_LM_UnloadModule, METH_VARARGS, "" },
	{ "LM_UnloadModuleEx", py_LM_UnloadModuleEx, METH_VARARGS, "" },
	/****************************************/
	{ "LM_EnumSymbols", py_LM_EnumSymbols, METH_VARARGS, "" },
	{ "LM_EnumSymbolsEx", py_LM_EnumSymbolsEx, METH_VARARGS, "" },
	{ "LM_GetSymbol", py_LM_GetSymbol, METH_VARARGS, "" },
	{ "LM_GetSymbolEx", py_LM_GetSymbolEx, METH_VARARGS, "" },
	/****************************************/
	{ "LM_EnumPages", py_LM_EnumPages, METH_VARARGS, "" },
	{ "LM_EnumPagesEx", py_LM_EnumPagesEx, METH_VARARGS, "" },
	{ "LM_GetPage", py_LM_GetPage, METH_VARARGS, "" },
	{ "LM_GetPageEx", py_LM_GetPageEx, METH_VARARGS, "" },
	/****************************************/
	{ "LM_ReadMemory", py_LM_ReadMemory, METH_VARARGS, "" },
	{ "LM_ReadMemoryEx", py_LM_ReadMemoryEx, METH_VARARGS, "" },
	{ "LM_WriteMemory", py_LM_WriteMemory, METH_VARARGS, "" },
	{ "LM_WriteMemoryEx", py_LM_WriteMemoryEx, METH_VARARGS, "" },
	{ "LM_SetMemory", py_LM_SetMemory, METH_VARARGS, "" },
	{ "LM_SetMemoryEx", py_LM_SetMemoryEx, METH_VARARGS, "" },
	{ "LM_ProtMemory", py_LM_ProtMemory, METH_VARARGS, "" },
	{ "LM_ProtMemoryEx", py_LM_ProtMemoryEx, METH_VARARGS, "" },
	{ "LM_AllocMemory", py_LM_AllocMemory, METH_VARARGS, "" },
	{ "LM_AllocMemoryEx", py_LM_AllocMemoryEx, METH_VARARGS, "" },
	{ "LM_FreeMemory", py_LM_FreeMemory, METH_VARARGS, "" },
	{ "LM_FreeMemoryEx", py_LM_FreeMemoryEx, METH_VARARGS, "" },
	{ "LM_DataScan", py_LM_DataScan, METH_VARARGS, "" },
	{ "LM_DataScanEx", py_LM_DataScanEx, METH_VARARGS, "" },
	{ "LM_PatternScan", py_LM_PatternScan, METH_VARARGS, "" },
	{ "LM_PatternScanEx", py_LM_PatternScanEx, METH_VARARGS, "" },
	{ "LM_SigScan", py_LM_SigScan, METH_VARARGS, "" },
	{ "LM_SigScanEx", py_LM_SigScanEx, METH_VARARGS, "" },
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

	if (PyType_Ready(&py_lm_process_t) < 0)
		goto _ERR_PYMOD;
	
	if (PyType_Ready(&py_lm_module_t) < 0)
		goto _ERR_PYMOD;
	
	if (PyType_Ready(&py_lm_page_t) < 0)
		goto _ERR_PYMOD;

	pymod = PyModule_Create(&libmem_mod);
	if (!pymod)
		goto _ERR_PYMOD;
	
	/* Types */
	Py_INCREF(&py_lm_process_t);
	if (PyModule_AddObject(pymod, "lm_process_t",
			       (PyObject *)&py_lm_process_t) < 0)
		goto _ERR_PROCESS;
	
	Py_INCREF(&py_lm_module_t);
	if (PyModule_AddObject(pymod, "lm_module_t",
			       (PyObject *)&py_lm_module_t) < 0)
		goto _ERR_MODULE;
	
	Py_INCREF(&py_lm_page_t);
	if (PyModule_AddObject(pymod, "lm_page_t",
			       (PyObject *)&py_lm_page_t) < 0)
		goto _ERR_PAGE;
	
	/* Global Variables */
	DECL_GLOBAL(pymod, "LM_OS_WIN", LM_OS_WIN);
	DECL_GLOBAL(pymod, "LM_OS_LINUX", LM_OS_LINUX);
	DECL_GLOBAL(pymod, "LM_OS_BSD", LM_OS_BSD);
	DECL_GLOBAL(pymod, "LM_OS_ANDROID", LM_OS_ANDROID);
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

	goto _RET; /* No Type Errors */
_ERR_PAGE:
	Py_DECREF(&py_lm_page_t);
	Py_DECREF(pymod);
_ERR_MODULE:
	Py_DECREF(&py_lm_module_t);
	Py_DECREF(pymod);
_ERR_PROCESS:
	Py_DECREF(&py_lm_process_t);
	Py_DECREF(pymod);
_ERR_PYMOD:
	pymod = (PyObject *)NULL;
_RET:
	return pymod;
}
