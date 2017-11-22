/*

This should contain glue functions for being able to use scripting.  I'll use code I have from other projects but Python, LUA, maybe JavaScript,
and a way to use binary packets to obtain requests/control should be easy enough to support.

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



// scripts that are loaded that should be checked periodically for control variables, etc
typedef struct _as_scripts {
    struct _as_scripts *next;

    int id;

    // type of script? python, etc...
    int type;
 
    AS_context *ctx;

    // scripts custom context (like PythonModuleCustom)
    void *script_context;
} AS_scripts;


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

        // we must initialize a new python interpreter...
        // i wasnt goign to do this but to be able to kill the thread at any time..
        // requires it to happens
        evars->python_thread = Py_NewInterpreter();

        // python is fairly simple..
        //ret = ExternalExecutePython(eptr, filename, "init", NULL);
        ret = PythonModuleExecute(eptr, NULL, "init", NULL);

        // need to do this at the end..           
        //Py_EndInterpreter(python_handle)
    }

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
    PythonModuleCustom *evars = (PythonModuleCustom *)ModuleCustomPtr(eptr, sizeof(PythonModuleCustom));
    
    if (evars == NULL) return -1;
    
    PyEval_AcquireThread(evars->python_thread);
    
    if (!evars->pModule) {
        // initialize python paths etc that we require for operating
        PyRun_SimpleString("import sys");
        for (i = 0; dirs[i] != NULL; i++) {
            sprintf(buf, fmt, dirs[i]);
            PyRun_SimpleString(buf);
        }

        // specify as a python object the name of the file we wish to load
        pName = PyString_FromString(script_file);
        // perform the loading
        pModule = PyImport_Import(pName);
        Py_DECREF(pName);
        // keep for later (for the plumbing/loop)
        evars->pModule = pModule;
    }
    
    pModule = evars->pModule;
    if (pModule == NULL) goto end;
    
    // we want to execute a particular function under this module we imported
    pFunc = PyObject_GetAttrString(pModule, func_name);
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

    PyEval_ReleaseThread(evars->python_thread);

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
    
    end:;
    return ret;           
}

