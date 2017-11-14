/*

This should contain glue functions for being able to use scripting.  I'll use code I have from other projects but Python, LUA, maybe JavaScript,
and a way to use binary packets to obtain requests/control should be easy enough to support.

*/

/* 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <Python.h>


int ExternalExecutePython(Modules *eptr, char *script, char *func_name, PyObject *pVars);

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


int python_module_deinit(Modules *mptr) {
    #ifdef PYTHON_MODULES
        PythonModuleCustom *evars = (PythonModuleCustom *)ModuleCustomPtr(mptr, sizeof(PythonModuleCustom));
        
        if (evars == NULL) return -1;
        
        if (evars->python_thread)
            Py_EndInterpreter(evars->python_thread);
    #endif        
        return 0;
    }


PythonModuleCustom *evars = NULL;

if (eptr->type == MODULE_TYPE_PYTHON) {
    // first we must deinit it..
    if (ModuleDeinit(eptr) == 0)
      return ret;
}

evars = (PythonModuleCustom *)ModuleCustomPtr(eptr, sizeof(PythonModuleCustom));
if (evars != NULL) {

    // we must initialize a new python interpreter...
    // i wasnt goign to do this but to be able to kill the thread at any time..
    // requires it to happens
    evars->python_thread = Py_NewInterpreter();

    // python is fairly simple..
    ret = ExternalExecutePython(eptr, filename, "init", NULL);

    // need to do this at the end..           
    //Py_EndInterpreter(python_handle)
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
int PythonModuleExecute(Modules *eptr, char *script_file, char *func_name, PyObject *pArgs) {
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

    
    int python_sendmessage(Modules *mptr, Connection *cptr, char *message, int size) {
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
    int MessageModule(int module_id, Modules *module_list, char *message, int size) {
        Modules *mptr = module_list;
        Connection temp_conn;
        int ret = -1;
        
        // set an empty connection structure.. its just to not crash when the modules attempt to adjust it
        memset(&temp_conn, 0, sizeof(Connection));
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
            if (mptr->type == MODULE_TYPE_SO)
                ret = mptr->functions->incoming(mptr, &temp_conn, message, size);
            else if (mptr->type == MODULE_TYPE_PYTHON)
                ret = python_sendmessage(mptr, &temp_conn, message, size);
        }   
            
        return ret;
    }

    */