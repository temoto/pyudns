#ifndef mod_udns_h
#define mod_udns_h

#ifdef __cplusplus
extern "C" {
#endif

#include <Python.h>
#include <stdbool.h>

#include <udns.h>


typedef struct {
    PyObject_HEAD
    PyObject *__dict__;
    struct dns_ctx *ctx;
    int fd;
} Resolver;

typedef struct {
    PyObject_HEAD
    PyObject *__dict__;
    PyObject *resolver;
    struct dns_query *q;
    PyObject *callback;
    PyObject *data; // and its data pointer
    bool is_completed;
} Query;

typedef struct {
    PyObject_HEAD
    PyObject *__dict__;
    PyObject *resolver;
    struct dns_ctx *ctx;
    struct dns_rr_null *rr;
} RRWrap;


#ifdef __cplusplus
}
#endif
#endif // mod_udns_h
