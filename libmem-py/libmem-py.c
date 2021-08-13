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

static PyTypeObject py_lm_pid_t = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libmem.lm_pid_t",
	.tp_doc = "",
	.tp_basicsize = sizeof(py_lm_pid_obj),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_members = py_lm_pid_members
};

/* Python Functions */
static PyObject *
py_LM_GetProcessId(PyObject *self,
		  PyObject *args)
{
	py_lm_pid_obj *pid;
	
	pid = (py_lm_pid_obj *)(PyObject_CallNoArgs((PyObject *)&py_lm_pid_t));
	pid->pid = LM_GetProcessId();
	return (PyObject *)pid;
}

/* Python Module */
static PyMethodDef libmem_methods[] = {
	{ "LM_GetProcessId", py_LM_GetProcessId, METH_NOARGS, "" },
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
		return NULL;

	pymod = PyModule_Create(&libmem_mod);
	if (!pymod)
		return NULL;
	
	Py_INCREF(&py_lm_pid_t);
	if (PyModule_AddObject(pymod, "lm_pid_t",
			       (PyObject *)&py_lm_pid_t) < 0) {
		Py_DECREF(&py_lm_pid_t);
		Py_DECREF(pymod);
		return NULL;
	}

	return pymod;
}
