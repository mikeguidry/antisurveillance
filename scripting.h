

// scripts that are loaded that should be checked periodically for control variables, etc
typedef struct _as_scripts {
    struct _as_scripts *next;

    int id;

    // type of script? python, etc...
    int type;
 
    AS_context *ctx;    
    PyThreadState *python_thread;
    PyObject *pModule;

    PyThreadState *mainThreadState;
    PyThreadState *myThreadState;
    PyThreadState *tempState;

    PyInterpreterState *mainInterpreterState;

    // did this script have a script_perform() function whenever it was loaded into memory?
    int perform;

    pthread_mutex_t lock_mutex;
} AS_scripts;

int Scripting_Perform(AS_context *ctx);
int Scripting_Init(AS_context *ctx);
AS_scripts *Scripting_New(AS_context *ctx);
AS_scripts *Scripting_FindFunction(AS_context *, char *);
int Scripting_ThreadPost(AS_context *ctx, AS_scripts *sptr);
int Scripting_ThreadPre(AS_context *ctx, AS_scripts *sptr);


#define FROM_CLIENT 1
#define FROM_SERVER 0

