#include <libmem.h>
#include <Python.h>

static PyObject *
libmem_LM_GetProcessId(PyObject *self,
		       PyObject *args)
{
	return PyLong_FromLong(LM_GetProcessId());
}

static PyMethodDef libmem_methods[] = {
	{ "LM_GetProcessId", libmem_LM_GetProcessId, METH_NOARGS, "" },
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
	return PyModule_Create(&libmem_mod);
}
