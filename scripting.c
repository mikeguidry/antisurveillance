/*

This should contain glue functions for being able to use scripting.  I'll use code I have from other projects but Python, LUA, maybe JavaScript,
and a way to use binary packets to obtain requests/control should be easy enough to support.

I will allow access to all portions of the C code.  Any further develops, controlling, etc can be handled in python.  It should be fairly
simple to integrate P2P code.  It will allow building packets, management, and even incoming packet delivery to python.  The entire system
could be developed in python although it would be fairly slow...  I decided to cut C code down and complete like this for the final
public version.  It will allow using some new attacks, and should be good enough for anyone wishing to fuck up mass surveillance
in their area... or everywhere?

lessons will be learned 1 way or another.

*/
#define PYTHON_MODULES

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "network.h"
#include "antisurveillance.h"
#include "scripting.h"
#ifdef PYTHON_MODULES
#include <Python.h>
#endif




typedef struct _script_callbacks {
    struct _script_callbacks *next;

    // whenever an attack structure is completed.. lets notify the script
    // it may modify it, or just keep track
    void *attack_completed;
    // whenever a new attack is added lets notify the script
    void *attack_added;

    // the perform function (a single main loop iteration)
    void *perform;

    // whenever a traceroute is completed.. the script can pull information and help with strategy, or IP list.. etc
    void *traceroute_completed;
    // new traceroute campaign is added
    void *traceroute_added;

    // all network queue was completed (script can restart, add new, etc)
    void *network_queue_completed;

    // pcap was loaded
    void *pcap_loaded;
    // pcap was saved
    void *pcap_saved;

    // blackhole entry was added
    void *blackhole_added;
    // blackhole entry completed (so it can adjust it to continue, or modify)
    // it could verify it is working, otherwise it can change a few parameters, or modify the attack slightly
    void *blackhole_completed;

} ScriptCallbacks;


// custom variables for a python module
typedef struct _python_module_custom {
    // so we can verify its the correct structure..
    int size;
#ifdef PYTHON_MODULES
    // if python... this allows to easily kill the script
    PyThreadState *python_thread;
    PyObject *pModule;
#endif
} PythonModuleCustom;



// allocates custom data for a module..
// this is so python.h doesnt have to be loaded in every source file
void *ModuleCustomPtr(AS_scripts *eptr, int custom_size) {
    if (eptr->script_context == NULL) {
        if ((eptr->script_context = (char *)calloc(1,custom_size + 1)) == NULL) {
            return NULL;
        }
    }
    
    return (void *)eptr->script_context;
}

// -----------------------------------------------------------------------
//  Used code from: https://docs.python.org/2/extending/newtypes.html
//  Was going to use lots of code from this but decided it was too much to change..
//  used as a reference instead
//  https://github.com/grisha/mod_python/blob/master/src/requestobject.c
#ifndef Py_STRUCTMEMBER_H
#define Py_STRUCTMEMBER_H
#ifdef __cplusplus
extern "C" {
#endif


/* Interface to map C struct members to Python object attributes */

#include <stddef.h> /* For offsetof */

/* The offsetof() macro calculates the offset of a structure member
   in its structure.  Unfortunately this cannot be written down
   portably, hence it is provided by a Standard C header file.
   For pre-Standard C compilers, here is a version that usually works
   (but watch out!): */

#ifndef offsetof
#define offsetof(type, member) ( (int) & ((type*)0) -> member )
#endif

/* An array of memberlist structures defines the name, type and offset
   of selected members of a C structure.  These can be read by
   PyMember_Get() and set by PyMember_Set() (except if their READONLY flag
   is set).  The array must be terminated with an entry whose name
   pointer is NULL. */

struct memberlist {
    /* Obsolete version, for binary backwards compatibility */
    char *name;
    int type;
    int offset;
    int flags;
};

typedef struct PyMemberDef {
    /* Current version, use this */
    char *name;
    int type;
    Py_ssize_t offset;
    int flags;
    char *doc;
} PyMemberDef;

/* Types */
#define T_SHORT         0
#define T_INT           1
#define T_LONG          2
#define T_FLOAT         3
#define T_DOUBLE        4
#define T_STRING        5
#define T_OBJECT        6
/* XXX the ordering here is weird for binary compatibility */
#define T_CHAR          7       /* 1-character string */
#define T_BYTE          8       /* 8-bit signed int */
/* unsigned variants: */
#define T_UBYTE         9
#define T_USHORT        10
#define T_UINT          11
#define T_ULONG         12

/* Added by Jack: strings contained in the structure */
#define T_STRING_INPLACE        13

/* Added by Lillo: bools contained in the structure (assumed char) */
#define T_BOOL          14

#define T_OBJECT_EX     16      /* Like T_OBJECT, but raises AttributeError
                   when the value is NULL, instead of
                   converting to None. */
#ifdef HAVE_LONG_LONG
#define T_LONGLONG      17
#define T_ULONGLONG      18
#endif /* HAVE_LONG_LONG */

#define T_PYSSIZET       19 /* Py_ssize_t */


/* Flags */
#define READONLY        1
#define RO              READONLY                /* Shorthand */
#define READ_RESTRICTED 2
#define PY_WRITE_RESTRICTED 4
#define RESTRICTED      (READ_RESTRICTED | PY_WRITE_RESTRICTED)


/* Obsolete API, for binary backwards compatibility */
PyAPI_FUNC(PyObject *) PyMember_Get(const char *, struct memberlist *, const char *);
PyAPI_FUNC(int) PyMember_Set(char *, struct memberlist *, const char *, PyObject *);

/* Current API, use this */
PyAPI_FUNC(PyObject *) PyMember_GetOne(const char *, struct PyMemberDef *);
PyAPI_FUNC(int) PyMember_SetOne(char *, struct PyMemberDef *, PyObject *);


#ifdef __cplusplus
}
#endif
#endif /* !Py_STRUCTMEMBER_H */
typedef struct {
    PyObject_HEAD
    PyObject *first;
    PyObject *last;
    int number;
    AS_context *ctx;
} PyAS_Config;

static int PyASC_traverse(PyAS_Config *self, visitproc visit, void *arg) {
    int vret;

    if (self->first) {
        vret = visit(self->first, arg);
        if (vret != 0)
            return vret;
    }
    if (self->last) {
        vret = visit(self->last, arg);
        if (vret != 0)
            return vret;
    }

    return 0;
}

static int PyASC_clear(PyAS_Config *self) {
    PyObject *tmp;

    tmp = self->first;
    self->first = NULL;
    Py_XDECREF(tmp);

    tmp = self->last;
    self->last = NULL;
    Py_XDECREF(tmp);

    return 0;
}

static void
PyASC_dealloc(PyAS_Config *self)
{
    PyObject_GC_UnTrack(self);
    PyASC_clear(self);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *PyASC_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    PyAS_Config *self;

    self = (PyAS_Config *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->first = PyString_FromString("");
        if (self->first == NULL) {
            Py_DECREF(self);
            return NULL;
        }

        self->last = PyString_FromString("");
        if (self->last == NULL) {
            Py_DECREF(self);
            return NULL;
        }

        self->number = 0;
    }

    return (PyObject *)self;
}

static int PyASC_init(PyAS_Config *self, PyObject *args, PyObject *kwds) {
    PyObject *first=NULL, *last=NULL, *tmp;

    static char *kwlist[] = {"first", "last", "number", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|SSi", kwlist,
                                      &first, &last,
                                      &self->number))
        return -1;

    if (first) {
        tmp = self->first;
        Py_INCREF(first);
        self->first = first;
        Py_XDECREF(tmp);
    }

    if (last) {
        tmp = self->last;
        Py_INCREF(last);
        self->last = last;
        Py_XDECREF(tmp);
    }

    return 0;
}


static PyMemberDef PyASC_members[] = {
    {"first", T_OBJECT_EX, offsetof(PyAS_Config, first), 0,
     "first name"},
    {"last", T_OBJECT_EX, offsetof(PyAS_Config, last), 0,
     "last name"},
    {"number", T_INT, offsetof(PyAS_Config, number), 0,
     "noddy number"},
    {NULL}  /* Sentinel */
};


static PyObject *PyASC_DIE(PyAS_Config* self){
    exit(-1);
}

static PyObject *PyASC_name(PyAS_Config* self){
    static PyObject *format = NULL;
    PyObject *args, *result;

    if (format == NULL) {
        format = PyString_FromString("%s %s");
        if (format == NULL)
            return NULL;
    }

    if (self->first == NULL) {
        PyErr_SetString(PyExc_AttributeError, "first");
        return NULL;
    }

    if (self->last == NULL) {
        PyErr_SetString(PyExc_AttributeError, "last");
        return NULL;
    }

    args = Py_BuildValue("OO", self->first, self->last);
    if (args == NULL)
        return NULL;

    result = PyString_Format(format, args);
    Py_DECREF(args);

    return result;
}


static PyObject *PyASC_Disable(PyAS_Config* self){
    if (self->ctx) self->ctx->paused = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *PyASC_Enable(PyAS_Config* self){
    if (self->ctx) self->ctx->paused = 0;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *PyASC_Clear(PyAS_Config* self){

    Py_INCREF(Py_None);
    return Py_None; 
}

static PyObject *PyASC_PCAPload(PyAS_Config* self){

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *PyASC_PCAPsave(PyAS_Config* self){

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *PyASC_NetworkClear(PyAS_Config* self){

    Py_INCREF(Py_None);
    return Py_None;    
}

static PyObject *PyASC_NetworkOff(PyAS_Config* self){

    if (self->ctx) self->ctx->network_disabled = 1;

    Py_INCREF(Py_None);
    return Py_None; 
}

static PyObject *PyASC_NetworkOn(PyAS_Config* self){
    if (self->ctx) self->ctx->network_disabled = 0;

    Py_INCREF(Py_None);
    return Py_None; 
}

static PyObject *PyASC_CTXSet(PyAS_Config* self, PyObject *Pctx){
    void *ctx = PyLong_AsVoidPtr(Pctx);

    printf("CTX %p\n", ctx);
    self->ctx = ctx;

    Py_INCREF(Py_None);
    return Py_None;
}


static PyMethodDef PyASC_methods[] = {
    {"name", (PyCFunction)PyASC_name,   METH_NOARGS,    "Return the name, combining the first and last name" },
    {"exit", (PyCFunction)PyASC_DIE,    METH_NOARGS,    "Exits the software" },
    {"disable", (PyCFunction)PyASC_Disable,    METH_NOARGS,    "pauses the software" },
    {"enable", (PyCFunction)PyASC_Enable,    METH_NOARGS,    "continues the software" },
    {"clear", (PyCFunction)PyASC_Clear,    METH_NOARGS,    "clears all outgoing queue, and attack structures" },
    {"pcapload", (PyCFunction)PyASC_PCAPload,    METH_NOARGS,    "" },
    {"pcapsave", (PyCFunction)PyASC_PCAPsave,    METH_NOARGS,    "" },
    {"networkclear", (PyCFunction)PyASC_NetworkClear,    METH_NOARGS,    "clear outgoing network packets" },
    {"networkoff", (PyCFunction)PyASC_NetworkOff,    METH_NOARGS,    "disable writing to network" },
    {"networkon", (PyCFunction)PyASC_NetworkOn,    METH_NOARGS,    "enable writing to network" },
    {"setctx", (PyCFunction)PyASC_CTXSet,    METH_O,    "set context pointer.. automate later" },
    {NULL}  /* Sentinel */
};
/*
for i in Disable Enable Clear PCAPload PCAPsave NetworkClear NetworkOff NetworkOn;do
echo "
static PyObject *PyASC_$i(PyAS_Config* self){
}"
done
*/

/*

start_ts (get)
raw_socket (possibly use? proxy write? maybe read?)
read_socket.. depends on circumstances w kernel.. maybe can use one socket.. but maybe not.. lots of traffic on write
attack list (iterate)

list of server bodies, client bodies (and paired to geoip regions, etc)

gzip (array?) total gzip count, gzip cache, gzip cache size, gzip initialized, gzip cache count

network queue (iterate, count packets, clear)
network queue last (can use it)
pthread: network thread (verify its existing, kill, restart)
network threaded (does it think its thread is open?)

aggressive (need to recode, but chnage aggressive-ness.. how much CPU etc)
with python somme small code can check CPU and auto modify this to get it at a particular % (verifying with
systems tasks every X seconds) - this will allow a router which is being used heavily
at one time of the day to auto optimize and work perfectly without issues or dropped packets

scripts (list, check callbaks, remove calllbacks (raw), add callbacks, spy callbacks,
spy callbacks means we get information about all callbacks which will go to a script)...
can be used to modfy things in other scripts, or redirect.. proxy or filter another script

AS attacks: (create, delete, pause, unpause, lock mutex, unlock mutex, clear list, save cofiguration to disk,
get configuration inline)
id
type (ATTACK_MULTI, ATTACK_SESSION)
src, dst
source port, dest port

send_state, recv_state (not used yet) .. maybe remove? can determine how many packets are left in queue (conncept of when
the attack will end, or reach its next interval for replaying)

packet build instructions (list, modify, add, create new)

client_basae_seq, server_base_seq (no reason for this.. who knnows?)

packets, currnt packet (can check how many is left by counting)

paused (pause/unpause)
join (is it waiting to pthread join)
pause mutex (lock, unlock)

commpleted (is it completed? lets completee it.)

customm function (set, ,get, call, copy to a new attack kstructure from an existing)

extra_attack_parameters (stored gzip parameters here).. maybe allow a global onone, ,or custom

which context does this attack belong to? (if we wish to pause/unpause etire configurations of attacks)
ie: different nodes can enable/disable at various times using p2p to coordinate...

skip_adjustments - custom such as DNS, or something which requires 0 packet adjustments...



mutex(s): gzip_cache_mutex (check if can capture),
network queue mutex


*/


PyASC_getfirst(PyAS_Config *self, void *closure)
{
    Py_INCREF(self->first);
    return self->first;
}

static int PyASC_setfirst(PyAS_Config *self, PyObject *value, void *closure) {
  if (value == NULL) {
    PyErr_SetString(PyExc_TypeError, "Cannot delete the first attribute");
    return -1;
  }

  if (! PyString_Check(value)) {
    PyErr_SetString(PyExc_TypeError,
               
        "The first attribute value must be a string");
    return -1;
  }

  Py_DECREF(self->first);
  Py_INCREF(value);
  self->first = value;

  return 0;
}



static PyObject *
PyASC_getlast(PyAS_Config *self, void *closure)
{
    Py_INCREF(self->last);
    return self->last;
}

static int
PyASC_setlast(PyAS_Config *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the last attribute");
        return -1;
    }

    if (! PyString_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
                        "The last attribute value must be a string");
        return -1;
    }

    Py_DECREF(self->last);
    Py_INCREF(value);
    self->last = value;

    return 0;
}


static PyGetSetDef PyASC_getseters[] = {
    {"first",
     (getter)PyASC_getfirst, (setter)PyASC_setfirst,
     "first name",
     NULL},
    {"last",
     (getter)PyASC_getlast, (setter)PyASC_setlast,
     "last name",
     NULL},
    {NULL}  /* Sentinel */
};





static PyTypeObject PyASCType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "antisurveillance.Config",             /* tp_name */
    sizeof(PyAS_Config),             /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)PyASC_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,    /* tp_flags */
    "Config objects",           /* tp_doc */
    (traverseproc)PyASC_traverse,   /* tp_traverse */
    (inquiry)PyASC_clear,           /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    PyASC_methods,             /* tp_methods */
    PyASC_members,             /* tp_members */
    PyASC_getseters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PyASC_init,      /* tp_init */
    0,                         /* tp_alloc */
    PyASC_new,                 /* tp_new */
};

static PyMethodDef module_methods[] = {
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC initpyasc(void) {
    PyObject* m;

    if (PyType_Ready(&PyASCType) < 0)
        return;

    m = Py_InitModule3("antisurveillance", module_methods,
                       "Example module that creates an extension type.");

    if (m == NULL)
        return;

    Py_INCREF(&PyASCType);
    PyModule_AddObject(m, "Config", (PyObject *)&PyASCType);
}


// -----------------------------------------------------------------------


int ExternalExecutePython(AS_scripts *eptr, char *script, char *func_name, PyObject *pVars);



int python_module_deinit(AS_scripts *mptr) {
    #ifdef PYTHON_MODULES
        PythonModuleCustom *evars = (PythonModuleCustom *)ModuleCustomPtr(mptr, sizeof(PythonModuleCustom));
        
        if (evars == NULL) return -1;
        
        if (evars->python_thread)
            Py_EndInterpreter(evars->python_thread);
    #endif        
        return 0;
    }



int python_init(AS_scripts *eptr, char *filename) {
    PythonModuleCustom *evars = NULL;
    int ret = 0;

    evars = (PythonModuleCustom *)ModuleCustomPtr(eptr, sizeof(PythonModuleCustom));
    if (evars != NULL) {

        printf("initialize %p %p\n", eptr, evars);
        // we must initialize a new python interpreter...
        // i wasnt goign to do this but to be able to kill the thread at any time..
        // requires it to happens
        evars->python_thread = Py_NewInterpreter();

        // python is fairly simple..
        //ret = ExternalExecutePython(eptr, filename, "init", NULL);
        //ret = PythonModuleExecute(eptr, NULL, "init", NULL);

        // need to do this at the end..           
        //Py_EndInterpreter(python_handle)
    }

    printf("ret\n");
    return ret;
}



// execute a python function from a file..
// it will load into memory the first execution, and then use the original handle
// for subsequent.. so the first should execute an 'init' function, and following
// a loop (sockets, read, etc)
// global variables are itchy.. 
// check ircs.py for example of how i had it work.. I did 
// global = class_init() and made initfunc bind using a 'start' function (which used the globla handler)
// and the plumbing function then can access it correctly
// i wasnt able to get the init function to declare the globla variable using the class, and have it 
// work with the sequential calls.. so this works and ill stick with it..
// i suggest using the function externally to test..
// argument can be NULL.. or it can give the argument :)
// *** todo: maybe separate python execution environments for each script..
int PythonModuleExecute(AS_scripts *eptr, char *script_file, char *func_name, PyObject *pArgs) {
#ifdef PYTHON_MODULES
    PyObject *pName=NULL, *pModule=NULL, *pFunc=NULL;
    PyObject *pValue=NULL;
    int ret = 0;
    char fmt[] = "sys.path.append(\"%s\")";
    char *dirs[] = { "/tmp", "/var/tmp", ".", NULL };
    char buf[1024];
    int i = 0;
    PyObject *pCtx = NULL;
    PythonModuleCustom *evars = (PythonModuleCustom *)ModuleCustomPtr(eptr, sizeof(PythonModuleCustom));
    
    if (evars == NULL) return -1;
    
    printf("initialize %p %p\n", eptr, evars);

    //PyEval_AcquireThread(evars->python_thread);
    
    if (!evars->pModule) {
        // initialize python paths etc that we require for operating
        PyRun_SimpleString("import sys");
        for (i = 0; dirs[i] != NULL; i++) {
            sprintf(buf, fmt, dirs[i]);
            PyRun_SimpleString(buf);
        }

        initpyasc();

        printf("before import\n");
        //PyRun_SimpleString("from pprint import pprint");
        // specify as a python object the name of the file we wish to load
        pName = PyString_FromString(script_file);
        // perform the loading
        pModule = PyImport_Import(pName);
        Py_DECREF(pName);
        // keep for later (for the plumbing/loop)
        evars->pModule = pModule;
        if (pModule == NULL) {
            PyErr_Print();
            exit(-1);
        }
        printf("after import pmodule %p\n", pModule);

        // ***
        // we need to prepare the script with the context pointer..
        //    PyObject_SetAttr

        pCtx = PyLong_FromVoidPtr((void *)eptr->ctx);
        i = PyObject_SetAttrString(pModule, "ctx", pCtx);
        printf("i: %d\n", i);
    
    }
    
    pModule = evars->pModule;
    if (pModule == NULL) goto end;
    
    // we want to execute a particular function under this module we imported
    pFunc = PyObject_GetAttrString(pModule, func_name);
    printf("pfunc %p\n", pFunc);




    // now we must verify that the function is accurate
    if (!(pFunc && PyCallable_Check(pFunc))) {
        goto end;
    }
    
    pValue = PyObject_CallObject(pFunc, pArgs);
    if (pValue != NULL && !PyErr_Occurred()) {
        // we must extract the integer and return it.. 
        // for init it will contain the module identifier for
        // passing messages between the module & others
        ret = PyLong_AsLong(pValue);
        // usually you have to use Py_DECREF() here.. 
        // so if the application requires a more intersting object type from python, then adjust that here   
    }
        
end:;
    if (pFunc != NULL)
        Py_XDECREF(pFunc);
    if (pValue != NULL)
        Py_XDECREF(pValue);

    //PyEval_ReleaseThread(evars->python_thread);

    return ret;
#else
    return -1;
#endif
}

    
int python_sendmessage(AS_scripts *mptr,  char *message, int size) {
    int ret = -1;
#ifdef PYTHON_MODULES
    PyObject *pArgs = NULL;
    PyObject *pMessage = NULL;
    PyObject *pValue = NULL;
        
        // first we must create the arguments
        // setup and convert arguments for python script
        pArgs = PyTuple_New(2);
        if (pArgs != NULL) {
            // convert the message to a python object
            pMessage = PyString_FromString(message);
            if (pMessage != NULL) {
                // if that went successful.. set it in the tuple
                PyTuple_SetItem(pArgs, 0, pMessage);
                // now convert the size of the message to a python object
                pValue = PyInt_FromLong(size);
                if (pValue != NULL) {
                    // if that worked out ok then set it in the tuple as well
                    PyTuple_SetItem(pArgs, 2, pValue);
                    
                    // now push that argument to the actual python 'incoming' function in that script
                    ret = PythonModuleExecute(mptr, NULL, "incoming", pArgs);
                    
                    // free size
                    Py_DECREF(pValue);
                }
                // free message
                Py_DECREF(pMessage);
            }
            // free tuple
            Py_DECREF(pArgs);
        }
#endif
    return ret;
}
    
    // the way connections are handled using ConnectionBad, etc.. gives us ability to easily
// make a STACK based Connection structure to pass information to the appropriate module we are attempting object
// for moving information from botlink to irc, etc
int MessageModule(int module_id, AS_scripts *module_list, char *message, int size) {
    AS_scripts *mptr = module_list;

    int ret = -1;
    
    // set an empty connection structure.. its just to not crash when the modules attempt to adjust it
//        memset(&temp_conn, 0, sizeof(Connection));
    // later it may be useful to get the address of the IRC client giving the command, etc
    // that could be returned back in an array, and converted and passed into the client structure here
    
    // first we check if the module exists within the normal set of modules (compiled in)
    while (mptr != NULL) {
        if (mptr->id == module_id) {
            break;
        }
        
        mptr = mptr->next;
    }
        
    // now use the modules correct function to send the message
    if (mptr) {
        //if (mptr->type == MODULE_TYPE_SO)
            //  ret = mptr->functions->incoming(mptr, &temp_conn, message, size);
    //     if (mptr->type == MODULE_TYPE_PYTHON)
            ret = python_sendmessage(mptr, message, size);
    }   
        
    return ret;
}

enum {
    SCRIPT_PYTHON,
    SCRIPT_LUA
};








int Scripting_Perform(AS_context *ctx) {
    int ret = -1;

    end:;
    return ret;
}






int Scripting_Init(AS_context *ctx) {
    int ret = -1;
    int i = 0;
    
    Py_Initialize();

    ret = 1;

    end:;
    return ret;           
}


AS_scripts *Scripting_New(AS_context *ctx) {
    AS_scripts *sctx = NULL;

    printf("Scripting new ctx %p\n", ctx);

    if ((sctx = (AS_scripts *)calloc(1, sizeof(AS_scripts))) == NULL) return NULL;

    sctx->ctx = ctx;
    python_init(sctx, NULL);

    return sctx;
}