#include <Python.h>
#include <ev.h>
#include <netinet/in.h>
#include <stdio.h>
#include "structmember.h"
#include <udns.h>

#include "mod_udns.h"

static PyObject *module;

// fwd decl
static PyTypeObject QueryType;
static PyTypeObject RRWrapType;


// *************************************
// Python backwards compat begins
// *************************************

#ifndef PyVarObject_HEAD_INIT
#define PyVarObject_HEAD_INIT(p, s) PyObject_HEAD_INIT(p) s,
#endif

#ifndef Py_TYPE
#define Py_TYPE(obj) obj->ob_type
#endif

#ifndef PyModule_AddIntMacro
#define PyModule_AddIntMacro(m, macro) PyModule_AddIntConstant(m, #macro, macro)
#endif

// *************************************
// Python backwards compat ends
// *************************************


// *************************************
// common begins
// *************************************

#ifndef NDEBUG
#define DPRINT(s)              printf("debug: " s)
#define DPRINT1(s, arg0)       printf("debug: " s, arg0)
#define DPRINT2(s, arg0, arg1) printf("debug: " s, arg0, arg1)
#define DPRINT(s)
#define DPRINT1(s, arg0)
#define DPRINT2(s, arg0, arg1)
#else
#define DPRINT(s)
#define DPRINT1(s, arg0)
#define DPRINT2(s, arg0, arg1)
#endif

// *************************************
// common ends
// *************************************


// *************************************
// Resolver begins
// *************************************

PyDoc_STRVAR(Resolver_doc,
"udns resolver. This is your start and endpoint of DNS resolving.\n"
"\n"
"Resolver(create_new=False, do_open=True) constructor takes 2 bool arguments.\n"
"   # create_new: False to use singleton default resolver, True to create new.\n"
"       You hardly ever need to create new resolver.\n"
"   # do_open: False to just init, True to init and open UDP socket.\n"
"       If you don't open socket now, you must call .open() later.\n"
"\n"
"Raises MemoryError if udns dns_new() fails,\n"
"   Exception if udns context init fails.\n"
"   IOError if udns socket open fails.\n"
);

static int
Resolver_init(Resolver *self, PyObject *args) {
    int r = 0, create_new = 0, do_open = 1;

    if (!PyArg_ParseTuple(args, "|ii", &create_new, &do_open)) {
        PyErr_SetString(PyExc_TypeError, "Resolver(create_new=False, do_open=True) wrong arguments. See help(Resolver) for details.");
        return -1;
    }

    //FIXME
    if (0 == do_open) {
        PyErr_SetString(PyExc_NotImplementedError, "Resolver() do_open=False not yet implemented. Pass True for now. Sorry.");
        return -1;
    }

    self->ctx = NULL;

    if (1 == create_new) {
        self->ctx = dns_new(NULL);
        if (NULL == self->ctx) {
            PyErr_SetString(PyExc_MemoryError, "Resolver() failed to create new udns context.");
            return -1;
        }
    }

    r = dns_init(self->ctx, 0);
    if (r < 0) {
        PyErr_SetString(PyExc_Exception, "Resolver() failed to init udns context.");
        return -1;
    }

    if (1 == do_open) {
        self->fd = dns_open(self->ctx);
        if (self->fd < 0) {
            PyErr_SetString(PyExc_IOError, "Resolver() failed to open udns socket.");
            return -1;
        }
    }

    return 0;
}

static void
Resolver_dealloc(Resolver *self) {
    if (NULL != self->ctx) {
        dns_free(self->ctx);
        self->ctx = NULL;
    }
    self->ob_type->tp_free((PyObject*)self);
}

// Resolver.cancel(query) -> None
PyDoc_STRVAR(Resolver_cancel_doc, "\
TODO\n\
");

/*@null@*/
static PyObject*
Resolver_cancel(Resolver *self, PyObject *args) {
    Query *query = NULL;

    if (!PyArg_ParseTuple(args, "O", &query) || NULL == query) {
        PyErr_SetString(PyExc_TypeError, "Resolver.cancel(query) wrong arguments. Pass Query returned by submit_* methods.");
        return NULL;
    }

    if (NULL != query->q) {
        dns_cancel(self->ctx, query->q);
        // q is invalid pointer afterwards, so we forget it
        query->q = NULL;
    }

    Py_RETURN_NONE;
}

// Resolver.close() -> None
PyDoc_STRVAR(Resolver_close_doc, "\
TODO\n\
");

/*@null@*/
static PyObject*
Resolver_close(Resolver *self, PyObject *args) {
    if (args && !PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_TypeError, "Resolver.close() takes no arguments.");
        return NULL;
    }

    dns_close(self->ctx);

    Py_RETURN_NONE;
}

// Resolver.ioevent(now=0) -> None
PyDoc_STRVAR(Resolver_ioevent_doc, "\
ioevent(now=0)\n\
\n\
`now` is current timestamp. If it is 0 udns will find current time on it's own.\n\
");

/*@null@*/
static PyObject*
Resolver_ioevent (Resolver *self, PyObject *args) {
    time_t now = 0;

    if (!PyArg_ParseTuple(args, "|l", &now)) {
        PyErr_SetString(PyExc_TypeError, "Resolver.ioevent(now=0) wrong arguments.");
        return NULL;
    }

    dns_ioevent(self->ctx, now);

    Py_RETURN_NONE;
}

// Resolver.timeouts(maxwait, now=0) -> wait
PyDoc_STRVAR(Resolver_timeouts_doc, "\
TODO\n\
");

/*@null@*/
static PyObject*
Resolver_timeouts (Resolver *self, PyObject *args) {
    time_t now = 0;
    int wait = 0, maxwait = 0;

    if (!PyArg_ParseTuple(args, "i|l", &maxwait, &now)) {
        PyErr_SetString(PyExc_TypeError, "Resolver.timeouts(maxwait, now=0) takes 2 int arguments: maxwait and current timestamp.");
        return NULL;
    }

    wait = dns_timeouts(self->ctx, maxwait, now);

    return Py_BuildValue("i", wait);
}

static void
on_dns_resolve_a4 (struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data) {
    int i;
    PyObject *list, *item, *r;
    Query *query = data;
    char buf[17];
    const char *ntop_r;

    query->is_completed = true;
    if (NULL == result) {
        r = PyObject_CallFunction(query->callback, "OO", Py_None, query->data);
        if (NULL == r) {
        }
    } else {
        list = PyTuple_New(result->dnsa4_nrr);
        for (i = 0; i < result->dnsa4_nrr; i++) {
            memset(buf, 0, sizeof(buf));
            ntop_r = dns_ntop(AF_INET, &(result->dnsa4_addr[i]), buf, 16);
            if (NULL == ntop_r) {
                // TODO: handle error
            }
            item = Py_BuildValue("s", buf);
            PyTuple_SET_ITEM(list, i, item);
        }
        free(result); // man 3 udns: it's the application who is responsible for freeing result memory
        r = PyObject_CallFunction(query->callback, "NO", list, query->data);
    }
    Py_XDECREF(r);
    query->q = NULL;
    Py_DECREF(query);
}

// Resolver.submit_a4() -> None
PyDoc_STRVAR(Resolver_submit_a4_doc, "\
TODO\n\
");

/*@null@*/
static PyObject*
Resolver_submit_a4 (Resolver *self, PyObject *args) {
    const char *domain;
    PyObject *cb, *cb_data = Py_None;
    Query *query;
    int flags = 0;

    if (!PyArg_ParseTuple(args, "sO|Oi", &domain, &cb, &cb_data, &flags)) {
        PyErr_SetString(PyExc_TypeError, "Resolver.submit_a4(domain, callback, data=None, flags=0) wrong arguments.");
        return NULL;
    }
    if (!cb || !PyCallable_Check(cb)) {
        PyErr_SetString(PyExc_TypeError, "'callback' is not callable.");
        return NULL;
    }

    query = (Query*)PyObject_CallObject((PyObject*)&QueryType, NULL);
    if (NULL == query) {
        PyErr_SetString(PyExc_MemoryError, "Can't create Query object.");
        return NULL;
    }
    Py_INCREF(self);
    query->resolver = (PyObject*)self;
    Py_INCREF(cb);
    query->callback = cb;
    Py_INCREF(cb_data);
    query->data = cb_data;
    Py_INCREF(query);
    query->q = dns_submit_a4(self->ctx, domain, flags, on_dns_resolve_a4, (void*)query);

    return (PyObject*)query;
}

static PyMethodDef Resolver_methods[] = {
    {"cancel", (PyCFunction)Resolver_cancel, METH_VARARGS, Resolver_cancel_doc},
    {"close", (PyCFunction)Resolver_close, METH_NOARGS, Resolver_close_doc},
    {"ioevent", (PyCFunction)Resolver_ioevent, METH_VARARGS, Resolver_ioevent_doc},
    {"submit_a4", (PyCFunction)Resolver_submit_a4, METH_VARARGS, Resolver_submit_a4_doc},
    {"timeouts", (PyCFunction)Resolver_timeouts, METH_VARARGS, Resolver_timeouts_doc},
    {NULL} /* Sentinel */
};

static PyObject*
Resolver_get_active(Resolver *self, void *closure) {
    int active = dns_active(self->ctx);

    return Py_BuildValue("i", active);
}

static PyObject*
Resolver_get_sock(Resolver *self, void *closure) {
    int sock = dns_sock(self->ctx);

    return Py_BuildValue("i", sock);
}

static PyObject*
Resolver_get_status(Resolver *self, void *closure) {
    int status = dns_status(self->ctx);

    return Py_BuildValue("i", status);
}

static PyGetSetDef Resolver_getseters[] = {
    {"active", (getter)Resolver_get_active, NULL,
        "TODO",
        NULL},
    {"sock", (getter)Resolver_get_sock, NULL,
        "TODO",
        NULL},
    {"status", (getter)Resolver_get_status, NULL,
        "TODO",
        NULL},
    {NULL} /* Sentinel */
};

/* ResolverType */
static PyTypeObject ResolverType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_udns.Resolver",                         /*tp_name*/
    sizeof(Resolver),                         /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Resolver_dealloc,             /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Resolver_doc,                             /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Resolver_methods,                         /*tp_methods*/
    0,                                        /*tp_members*/
    Resolver_getseters,                       /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    offsetof(Resolver, __dict__),             /*tp_dictoffset*/
    (initproc)Resolver_init,                  /*tp_init*/
};

// *************************************
// Resolver ends
// *************************************


// *************************************
// Query begins
// *************************************

PyDoc_STRVAR(Query_doc, "\
DNS Query\n\
");

/*@null@*/ static PyObject *
Query_new (PyTypeObject *type, PyObject *args, /*@unused@*/ PyObject *kwargs) {
    Query *self;

    if (!PyArg_ParseTuple(args, "")) {
        return NULL;
    }

    self = (Query*)type->tp_alloc(type, 0);
    if (!self) { return NULL; }

    self->resolver = NULL;
    self->q = NULL;
    self->callback = NULL;
    self->data = NULL;
    self->is_completed = false;

    return (PyObject*)self;
}

static void
Query_dealloc(Query *self)
{
    Py_DECREF(self->resolver);
    Py_DECREF(self->callback);
    Py_DECREF(self->data);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

// Query.cancel(query) -> None
PyDoc_STRVAR(Query_cancel_doc, "\
TODO\n\
");

/*@null@*/
static PyObject*
Query_cancel(Query *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_TypeError, "Query.cancel() wrong arguments.");
        return NULL;
    }

    assert(NULL != self->resolver);

    if (NULL != self->q) {
        dns_cancel(((Resolver*)self->resolver)->ctx, self->q);
        // q is invalid pointer afterwards, so we forget it
        self->q = NULL;
    }

    Py_RETURN_NONE;
}

static PyMethodDef Query_methods[] = {
    {"cancel", (PyCFunction)Query_cancel, METH_VARARGS, Query_cancel_doc},
    {NULL} // Sentinel
};

static PyMemberDef Query_members[] = {
    {"resolver", T_OBJECT_EX, offsetof(Query, resolver), READONLY,
     "TODO"},
    {"callback", T_OBJECT_EX, offsetof(Query, callback), READONLY,
     "TODO"},
    {"data",     T_OBJECT, offsetof(Query, data), READONLY,
     "TODO"},
    {NULL} // Sentinel
};

// Query.is_completed -> bool
PyDoc_STRVAR(Query_is_completed_doc,
"Whether current Query is completed or not.");

/*@null@*/ static PyObject *
Query_is_completed_get (Query *self, /*@unused@*/ void *closure)
{
    if (self->is_completed) { Py_RETURN_TRUE; }
    else { Py_RETURN_FALSE; }
}

static PyGetSetDef Query_getsets[] = {
    {"is_completed", (getter)Query_is_completed_get, NULL, Query_is_completed_doc, NULL},
    {NULL} // Sentinel
};

/* QueryType */
static PyTypeObject QueryType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_udns.Query",                            /*tp_name*/
    sizeof(Query),                            /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Query_dealloc,                /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Query_doc,                                /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Query_methods,                            /*tp_methods*/
    Query_members,                            /*tp_members*/
    Query_getsets,                            /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    offsetof(Query, __dict__),                /*tp_dictoffset*/
    0,                                        /*tp_init*/
    0,                                        /*tp_alloc*/
    Query_new,                                /*tp_new*/
};

// *************************************
// Query ends
// *************************************


// *************************************
// RRWrap begins
// *************************************

PyDoc_STRVAR(RRWrap_doc,
"DNS Result Record");

static PyObject*
RRWrap_get_query (RRWrap *self, void *closure) {
    assert(NULL != self->rr);

    return Py_BuildValue("s", self->rr->dnsn_qname);
}

static PyObject*
RRWrap_get_cname (RRWrap *self, void *closure) {
    assert(NULL != self->rr);

    return Py_BuildValue("s", self->rr->dnsn_cname);
}

static PyObject*
RRWrap_get_ttl (RRWrap *self, void *closure) {
    assert(NULL != self->rr);

    return Py_BuildValue("i", self->rr->dnsn_ttl);
}

static PyObject*
RRWrap_get_count (RRWrap *self, void *closure) {
    assert(NULL != self->rr);

    return Py_BuildValue("i", self->rr->dnsn_nrr);
}

static PyGetSetDef RRWrap_getseters[] = {
    {"query", (getter)RRWrap_get_query, NULL,
        "TODO",
        NULL},
    {"cname", (getter)RRWrap_get_cname, NULL,
        "TODO",
        NULL},
    {"ttl", (getter)RRWrap_get_ttl, NULL,
        "TODO",
        NULL},
    {"count", (getter)RRWrap_get_count, NULL,
        "TODO",
        NULL},
    {NULL} /* Sentinel */
};

/*@null@*/
static PyObject*
RRWrap_str(RRWrap *self) {
    assert(NULL != self->rr);

    return Py_BuildValue("s", "");
}

/* RRWrapType */
static PyTypeObject RRWrapType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_udns.RR",                               /*tp_name*/
    sizeof(RRWrap),                           /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    0,                                        /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    (reprfunc)RRWrap_str,                     /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    RRWrap_doc,                               /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    0,                                        /*tp_methods*/
    0,                                        /*tp_members*/
    RRWrap_getseters,                         /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    offsetof(RRWrap, __dict__),               /*tp_dictoffset*/
};

// *************************************
// RRWrap ends
// *************************************


// *************************************
// module begins
// *************************************

PyDoc_STRVAR(module_abi_version_doc, "\
TODO\n\
");

/*@null@*/
static PyObject*
module_abi_version(PyObject *self, PyObject *args) {
    const char *version = NULL;

    if (args && !PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_TypeError, "udns.abi_version() takes no arguments.");
        return NULL;
    }

    version = dns_version();

    return Py_BuildValue("s", version);
}

static PyMethodDef module_methods[] = {
    {"get_version", (PyCFunction)module_abi_version, METH_NOARGS, module_abi_version_doc},
    {NULL, NULL, 0, NULL} /* Sentinel */
};

PyMODINIT_FUNC
init_udns(void) {
    // init types
    ResolverType.tp_new = PyType_GenericNew;
    RRWrapType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ResolverType) ||
        PyType_Ready(&QueryType) ||
        PyType_Ready(&RRWrapType)
       )
        return;

    // init module
    module = Py_InitModule("_udns", module_methods);
    if (NULL == module)
        return;

    PyModule_AddIntConstant(module, "E_TEMPFAIL", DNS_E_TEMPFAIL);
    PyModule_AddIntConstant(module, "E_PROTOCOL", DNS_E_PROTOCOL);
    PyModule_AddIntConstant(module, "E_NXDOMAIN", DNS_E_NXDOMAIN);
    PyModule_AddIntConstant(module, "E_NODATA",   DNS_E_NODATA);
    PyModule_AddIntConstant(module, "E_NOMEM",    DNS_E_NOMEM);
    PyModule_AddIntConstant(module, "E_BADQUERY", DNS_E_BADQUERY);

    Py_INCREF(&ResolverType);
    PyModule_AddObject(module, "Resolver", (PyObject*)&ResolverType);
    Py_INCREF(&QueryType);
    PyModule_AddObject(module, "Query", (PyObject*)&QueryType);
    Py_INCREF(&RRWrapType);
    PyModule_AddObject(module, "RR", (PyObject*)&RRWrapType);
}

// *************************************
// module ends
// *************************************
