/*

This should contain glue functions for being able to use scripting.  I'll use code I have from other projects but Python, LUA, maybe JavaScript,
and a way to use binary packets to obtain requests/control should be easy enough to support.

i should say i hate python.  I am just making it easier for people to utilize this tool.. without requiring tons of custom code..
if pythoon didnt require indentions i'd prob try it more often


// -----------------------------------------------------------------------
//  Used code from: https://docs.python.org/2/extending/newtypes.html


*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stddef.h> /* For offsetof */
#include "network.h"
#include "antisurveillance.h"
#include "scripting.h"
#include "pcap.h"
#include "packetbuilding.h"
#include "instructions.h"
#include "utils.h"
#include "research.h"
#include "attacks.h"
#include <Python.h>

#ifndef offsetof
#define offsetof(type, member) ( (int) & ((type*)0) -> member )
#endif


const char generator_function[] = "content_generator";
const char scripting_main_loop_function[] = "script_perform";




// python configuration structure which has anything the script requires over time
typedef struct {
    PyObject_HEAD
    AS_context *ctx;

    ConnectionProperties connection_parameters;
    PacketBuildInstructions *instructions;

    FilterInformation flt;

    // *** incomplete
    // defaults are used if the script doesn't provide... so its shared across several functions
    // maybe retrieve this from C subsystem
    int replay_count;
    int replay_interval;
} PyAS_Config;



// deallocate the structure which was created for the C extension for python
static void PyASC_dealloc(PyAS_Config *self) {
    PyObject_GC_UnTrack(self);
    
    Py_TYPE(self)->tp_free((PyObject*)self);
}


// allocate the structure which is used to bridge between python, and our C extension
static PyObject *PyASC_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    PyAS_Config *self;

    self = (PyAS_Config *)type->tp_alloc(type, 0);

    return (PyObject *)self;
}

// this is literally the function that gets called while initializing the object which allows controlling the anti surveillance software
static int PyASC_init(PyAS_Config *self, PyObject *args, PyObject *kwds) {
    void *ctx = NULL;

    static char *kwlist[] = { "ctx", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|K", kwlist, &ctx))
        return -1;

    if (ctx) self->ctx = ctx;

    // some global defaults... *** todo: retrieve fromm C side, or double check its used everywhere
    self->replay_count = 99999999;
    self->replay_interval = 1;

    return 0;
}


// immediate exit of the application by doing exit() in python
static PyObject *PyASC_DIE(PyAS_Config* self){
    exit(-1);
}

// disable the system temporarily
static PyObject *PyASC_Disable(PyAS_Config* self){

    if (self->ctx) self->ctx->paused = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

// enable the system
static PyObject *PyASC_Enable(PyAS_Config* self){
    if (self->ctx) self->ctx->paused = 0;

    Py_INCREF(Py_None);
    return Py_None;
}


// clear all attack structures, and outgoing queues
static PyObject *PyASC_Clear(PyAS_Config* self){

    if (self->ctx) AS_Clear_All((AS_context *)self->ctx);

    Py_INCREF(Py_None);
    return Py_None; 
}


// *** todo: modify this to accept the filter here if its been created..
// also accept count, and interval.. and setup a global default (maybe in self) to let python modify
static PyObject *PyASC_PCAPload(PyAS_Config* self,  PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = { "filename", "use_python_filter", "destination_port", 0 };
    char *filename = NULL;
    int use_python_filter = 0;
    int destination_port = 80;
    int ret = 0;
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|ii", kwd_list, &filename, &use_python_filter, &destination_port)) {
        PyErr_Print();
        return NULL;
    }

    if (filename && self->ctx) {
        // *** todo: allow modified parameters, and setting globals to be used for everything
        ret = PCAPtoAttack(self->ctx, (char *)filename, destination_port, self->replay_count, self->replay_interval, use_python_filter ? &self->flt : NULL);
    }

    return PyInt_FromLong(ret);
}


// save all packet captures to a filename fromm network outgoing queue
static PyObject *PyASC_PCAPsave(PyAS_Config* self, PyObject *Pfilename){
    const char* s = PyString_AsString(Pfilename);

    if (s && self->ctx) {
        pthread_mutex_lock(&self->ctx->network_queue_mutex);
        PcapSave(self->ctx, (char *)s, self->ctx->outgoing_queue, NULL, 0);
        pthread_mutex_unlock(&self->ctx->network_queue_mutex);
    }

    Py_INCREF(Py_None);
    return Py_None;
}

// count outgoing network queue
static PyObject *PyASC_QueueIncomingCount(PyAS_Config* self){
    long ret = 0;

    if (self->ctx) {
        pthread_mutex_lock(&self->ctx->network_queue_mutex);
        ret = L_count((LINK *)self->ctx->incoming_queue);
        pthread_mutex_unlock(&self->ctx->network_queue_mutex);
    }

    return PyInt_FromLong(ret);
}

// count outgoing network queue
static PyObject *PyASC_QueueOutgoingCount(PyAS_Config* self){
    long ret = 0;

    if (self->ctx) {
        pthread_mutex_lock(&self->ctx->network_queue_mutex);
        ret = L_count((LINK *)self->ctx->outgoing_queue);
        pthread_mutex_unlock(&self->ctx->network_queue_mutex);
    }

    return PyInt_FromLong(ret);
}

// count outgoing network queue
static PyObject *PyASC_QueueOutgoingPoolCount(PyAS_Config* self){
    long ret = 0;

    if (self->ctx) {
        pthread_mutex_lock(&self->ctx->network_queue_mutex);
        ret = L_count((LINK *)self->ctx->outgoing_pool_waiting);
        pthread_mutex_unlock(&self->ctx->network_queue_mutex);
    }

    return PyInt_FromLong(ret);
}

// count outgoing network queue
static PyObject *PyASC_QueueIncomingPoolCount(PyAS_Config* self){
    long ret = 0;

    if (self->ctx) {
        pthread_mutex_lock(&self->ctx->network_queue_mutex);

        ret = L_count((LINK *)self->ctx->incoming_pool_waiting);
        
        pthread_mutex_unlock(&self->ctx->network_queue_mutex);
    }

    return PyInt_FromLong(ret);
}

// count outgoing network queue
static PyObject *PyASC_NetworkCount(PyAS_Config* self){
    long ret = 0;

    if (self->ctx) {
        pthread_mutex_lock(&self->ctx->network_queue_mutex);
        ret = L_count((LINK *)self->ctx->outgoing_queue);
        pthread_mutex_unlock(&self->ctx->network_queue_mutex);
    }

    return PyInt_FromLong(ret);
}


// count outgoing network queue
static PyObject *PyASC_AttackCount(PyAS_Config* self){
    long ret = 0;

    if (self->ctx) ret = L_count((LINK *)self->ctx->attack_list);


    return PyInt_FromLong(ret);
}

// count outgoing network queue
static PyObject *PyASC_TracerouteCount(PyAS_Config* self,  PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = { "completed", "disabled", 0 };
    long ret = 0;
    int completed = 0;
    int disabled = 0;


    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwd_list, &completed, &disabled)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx) ret = Traceroute_Count(self->ctx, completed, disabled)   ;

    return PyInt_FromLong(ret);
}

    

// clear the outgoing network queue
static PyObject *PyASC_NetworkClear(PyAS_Config* self){
    // clear all packets using the context given
    if (self->ctx) ClearPackets((AS_context *)self->ctx);

    Py_INCREF(Py_None);
    return Py_None;    
}


// disable flushing the outgoing network queue to the live wire
static PyObject *PyASC_NetworkOff(PyAS_Config* self){
    if (self->ctx) self->ctx->network_disabled = 1;

    Py_INCREF(Py_None);
    return Py_None; 
}

// enable flushing the network queue to the live wire
static PyObject *PyASC_NetworkOn(PyAS_Config* self){
    if (self->ctx) self->ctx->network_disabled = 0;

    Py_INCREF(Py_None);
    return Py_None; 
}


// set the context which is the glue to apply any changes
// *** figure out how to set this without using this solution...
static PyObject *PyASC_CTXSet(PyAS_Config* self, PyObject *Pctx){
    void *ctx = PyLong_AsVoidPtr(Pctx);

    self->ctx = ctx;

    return PyInt_FromLong(1);
    //Py_INCREF(Py_None);
    //return Py_None;
}


// clear all attack structures
static PyObject *PyASC_AttackClear(PyAS_Config* self){    
    if (self->ctx) AS_Clear_All((AS_context *)self->ctx);

    Py_INCREF(Py_None);
    return Py_None;
}

// perform one iteration of all attack structures
static PyObject *PyASC_AttackPerform(PyAS_Config* self) { 
    if (self->ctx) AS_perform(self->ctx);

    Py_INCREF(Py_None);
    return Py_None;
}


// disable blackhole attacks
static PyObject *PyASC_BlackholeDisable(PyAS_Config* self){

    if (self->ctx) self->ctx->blackhole_paused = 0;

    Py_INCREF(Py_None);
    return Py_None;
}


// enable blackhole attacks
static PyObject *PyASC_BlackholeEnable(PyAS_Config* self){

    if (self->ctx) self->ctx->blackhole_paused = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

// clear all blackhole attack parameters (targets)
static PyObject *PyASC_BlackholeClear(PyAS_Config* self){

    if (self->ctx) BH_Clear(self->ctx);

    Py_INCREF(Py_None);
    return Py_None;
}


// add a target to the blackhole attack
static PyObject *PyASC_BlackholeAdd(PyAS_Config* self, PyObject *Ptarget){
    const char* target = PyString_AsString(Ptarget);


    if (self->ctx)
        BH_add_IP(self->ctx, inet_addr(target));

    Py_INCREF(Py_None);
    return Py_None;
}

// remove a single target from the blackhole attack
static PyObject *PyASC_BlackholeDel(PyAS_Config* self, PyObject *Ptarget) {
    const char* target = PyString_AsString(Ptarget);

    if (self->ctx)
        BH_del_IP(self->ctx, inet_addr(target));

    Py_INCREF(Py_None);
    return Py_None;    
}


// prepare a filter with particular flags, and values those filter flags requires
static PyObject *PyASC_FilterPrepare(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = { "source_ip", "destination_ip", "source_port", "destination_port",
    "packet_flags", "familiar", 0};
    char *source_ip = NULL;
    char *destination_ip = NULL;
    int source_port = 0;
    int destination_port = 0;
    int packet_flags = 0;
    int familiar = 0;
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ssiiii", kwd_list,  &source_ip, &destination_ip, &source_port, &destination_port, &packet_flags, &familiar)) {
        PyErr_Print();
        return NULL;
    }

    if (source_ip) {
        // prepare either IPv4, or IPv6 client ip checking
        IP_prepare(source_ip, &self->flt.source_ip, &self->flt.source_ipv6, &self->flt.is_source_ipv6);
        self->flt.flags |= FILTER_CLIENT_IP;
    }

    if (destination_ip) {
        // prepare either IPv4, or IPv6 server ip checking
        IP_prepare(destination_ip, &self->flt.destination_ip, &self->flt.destination_ipv6, &self->flt.is_destination_ipv6);
        self->flt.flags |= FILTER_SERVER_IP;
    }

    if (source_port)
        FilterPrepare(&self->flt, FILTER_CLIENT_PORT, source_port);

    if (destination_port)
        FilterPrepare(&self->flt, FILTER_SERVER_PORT, destination_port);

    // *** need to work this out more
    if (packet_flags)
        FilterPrepare(&self->flt, FILTER_PACKET_FLAGS, packet_flags);

    if (familiar)
        FilterPrepare(&self->flt, FILTER_PACKET_FAMILIAR, 0);

    Py_INCREF(Py_None);
    return Py_None;
}



// create a new fiilter.. if one was already beign created hten it will be discarded
static PyObject *PyASC_FilterCreate(PyAS_Config* self, PyObject *args, PyObject *kwds) {

    // zero the filter
    memset((void *)&self->flt, 0, sizeof(FilterInformation));

    // must initialize the filter
    self->flt.init = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

// instructions add a tcp close from a particular side of the connection
// default is from client
static PyObject *PyASC_InstructionsTCPClose(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    int from_client = 1;
    static char *kwd_list[] = { "from_client", 0};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwd_list,  &from_client)) {
        PyErr_Print();
        return NULL;
    }

    int ret = GenerateTCPCloseConnectionInstructions(&self->connection_parameters, &self->instructions, from_client);

    return PyInt_FromLong(ret);
}

// send data from one side of the tcp conneccton to the other
static PyObject *PyASC_InstructionsTCPSend(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    int from_client = 0;
    char *data = NULL;
    int size = 0;
    int ret = 0;

    static char *kwd_list[] = { "from_client", "data", 0};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "is#", kwd_list,  &from_client, &data, &size)) {
        PyErr_Print();
        return NULL;
    }

    ret = GenerateTCPSendDataInstructions(&self->connection_parameters, &self->instructions, from_client, data, size);

    return PyInt_FromLong(ret);
}

// create packets for opening a tcp conneection
static PyObject *PyASC_InstructionsTCPOpen(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    
    int ret = GenerateTCPConnectionInstructions(&self->connection_parameters, &self->instructions);

    return PyInt_FromLong(ret);
}


// this is sortof redundant... it only takes 4 other commands (2 of the same)
static PyObject *PyASC_BuildHTTP(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {
    "client_ip", "client_port", "destination_ip", "destination_port", 
    "client_body", "client_body_size", "server_body", "server_body_size",
    "count", "interval",
    // these are not required
    "client_ttl", "server_ttl", 
    "client_window_size", "server_window_size","client_seq", "server_seq", "client_identifier",
    "server_identifier", "client_os","server_os", "gzip_enable", "gzip_percentage","gzip_size",
    "gzip_injections", 0};

    char *client_ip = NULL, *destination_ip = NULL;
    char *server_body = NULL, *client_body = NULL;
    int client_body_size = 0, server_body_size = 0;
    int client_port = 0, destination_port = 0, client_ttl = 0, server_ttl = 0, client_window_size = 0;
    int server_window_size = 0;
    unsigned long client_seq = 0, server_seq = 0, client_identifier = 0, server_identifier = 0;
    int client_os = 0, server_os = 0;
    int count = self->replay_count;
    int interval = self->replay_interval;
    AS_attacks *aptr = NULL;

    // *** finish implementing gzip here.. it has to create a new thread if the percentage matches
    // is gzip attack enabled? default yes
    int gzip_enable = 1;
    // what percentage chance does this http session get affected? (Default 30)
    int gzip_percentage = 30;
    // default to 100megs
    int gzip_size = 1024*1024*100;
    // injections = rand between 1-5
    int gzip_injections = 1+ (rand()%5);

    int ret = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "sisis#s#|iiiiiikkkkiiiiii", kwd_list,  
    &client_ip, &client_port, &destination_ip, &destination_port, &client_body, &client_body_size,
    &server_body, &server_body_size, &count, &interval, &client_ttl, &server_ttl, &client_window_size,
    &server_window_size, &client_seq, &server_seq, &client_identifier, &server_identifier, &client_os,
    &server_os, &gzip_enable, &gzip_percentage, &gzip_size, &gzip_injections)) {
        PyErr_Print();
        return NULL;
    }

    memset((void *)&self->connection_parameters, 0, sizeof(ConnectionProperties));

    // the new connection needs these variables prepared
    IP_prepare(destination_ip, &self->connection_parameters.server_ip, &self->connection_parameters.server_ipv6, &self->connection_parameters.is_ipv6);
    IP_prepare(client_ip, &self->connection_parameters.client_ip, &self->connection_parameters.client_ipv6, &self->connection_parameters.is_ipv6);
    self->connection_parameters.server_port = destination_port;
    self->connection_parameters.client_port = client_port;
    self->connection_parameters.server_identifier = server_identifier ? server_identifier : rand()%0xFFFFFFFF;
    self->connection_parameters.client_identifier = client_identifier ? client_identifier : rand()%0xFFFFFFFF;
    self->connection_parameters.server_seq = server_seq ? server_seq : rand()%0xFFFFFFFF;
    self->connection_parameters.client_seq = client_seq ? client_seq : rand()%0xFFFFFFFF;

    self->connection_parameters.client_ttl = client_ttl ? client_ttl : 64;
    self->connection_parameters.server_ttl = server_ttl ? server_ttl : 53;
    self->connection_parameters.max_packet_size_client = client_window_size ? client_window_size : (1500 - (20 * 2 + 12));
    self->connection_parameters.max_packet_size_server = server_window_size ? server_window_size : (1500 - (20 * 2 + 12));;

    gettimeofday(&self->connection_parameters.ts, NULL);

    // free all instructions used by this python module
    PacketBuildInstructionsFree(&self->instructions);

    
    // open the connection...
    if (GenerateTCPConnectionInstructions(&self->connection_parameters, &self->instructions) != 1) { ret = -2; goto err; }

    // now we must send data from client to server (http request)
    if (GenerateTCPSendDataInstructions(&self->connection_parameters, &self->instructions, FROM_CLIENT, client_body, client_body_size) != 1) { ret = -3; goto err; }

    // now we must send data from the server to the client (web page body)
    if (GenerateTCPSendDataInstructions(&self->connection_parameters, &self->instructions, FROM_SERVER, server_body, server_body_size) != 1) { ret = -4; goto err; }

    // now lets close the connection from client side first
    if (GenerateTCPCloseConnectionInstructions(&self->connection_parameters, &self->instructions, FROM_CLIENT) != 1) { ret = -5; goto err; }


    // now lets create the attak structure to begin...
    if ((aptr = (AS_attacks *)calloc(1, sizeof(AS_attacks))) == NULL) goto err;

    aptr->ctx = self->ctx;
    aptr->id = rand()%5000;
    pthread_mutex_init(&aptr->pause_mutex, NULL);  
    aptr->type = ATTACK_SESSION;

    aptr->count = count;
    aptr->repeat_interval = interval;

    // that concludes all packets
    aptr->packet_build_instructions = self->instructions;
    // lets unlink it from our structure..
    self->instructions = NULL;

    // now lets build the low level packets for writing to the network interface
    BuildPackets(aptr);


    if (aptr != NULL) {
        // link it in.
        aptr->next = self->ctx->attack_list;
        self->ctx->attack_list = aptr;

        // lets return the ID
        ret = aptr->id;

    }
err:;

    if (ret <= 0) {
        PacketBuildInstructionsFree(&self->instructions);
    }

    return PyInt_FromLong(ret);
}


static PyObject *PyASC_AttackDetails(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"attack_id", 0};
    int attack_id = 0;
    AS_attacks *aptr = NULL;
    PyObject *pRet = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &attack_id)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx) {
        aptr = AttackFind(self->ctx, attack_id, NULL, NULL, NULL, 0, 0, 0, 0);
        if (aptr != NULL) {
            pRet = PyAttackDetails(aptr);
        }

    }

    return pRet;
    
}

// start a new instruction set (removing anything previously not saved, etc)
static PyObject *PyASC_InstructionsCreate(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {
    "client_ip", "client_port", "destination_ip", "destination_port", "client_ttl", "server_ttl", 
    "client_window_size", "server_window_size","client_seq", "server_seq", "client_identifier",
    "server_identifier", "client_os","server_os", 0};

    char *client_ip = NULL, *destination_ip = NULL;
    int client_port = 0, destination_port = 0, client_ttl = 0, server_ttl = 0, client_window_size = 0;
    int server_window_size = 0;
    unsigned long client_seq = 0, server_seq = 0, client_identifier = 0, server_identifier = 0;
    int client_os = 0, server_os = 0;


    if (!PyArg_ParseTupleAndKeywords(args, kwds, "sisiiiii|kkkkii", kwd_list,  &client_ip, &client_port,
    &destination_ip, &destination_port, &client_ttl, &server_ttl, &client_window_size, &server_window_size,
    &client_seq, &server_seq, &client_identifier, &server_identifier, &client_os, &server_os)) {
        PyErr_Print();
        return NULL;
    }

    memset((void *)&self->connection_parameters, 0, sizeof(ConnectionProperties));

    // the new connection needs these variables prepared
    IP_prepare(destination_ip, &self->connection_parameters.server_ip, &self->connection_parameters.server_ipv6, &self->connection_parameters.is_ipv6);
    //printf("ipv6? %d ip %s\n", self->connection_parameters.is_ipv6, destination_ip);
    IP_prepare(client_ip, &self->connection_parameters.client_ip, &self->connection_parameters.client_ipv6, &self->connection_parameters.is_ipv6);
    //printf("ipv6? %d ip %s\n", self->connection_parameters.is_ipv6, client_ip);
    self->connection_parameters.server_port = destination_port;
    self->connection_parameters.client_port = client_port;
    self->connection_parameters.server_identifier = server_identifier;
    self->connection_parameters.client_identifier = client_identifier;
    self->connection_parameters.server_seq = server_seq;
    self->connection_parameters.client_seq = client_seq;

    self->connection_parameters.client_ttl = client_ttl;
    self->connection_parameters.server_ttl = server_ttl;
    self->connection_parameters.max_packet_size_client = client_window_size;
    self->connection_parameters.max_packet_size_server = server_window_size;

    // free all instructions used by this python module
    PacketBuildInstructionsFree(&self->instructions);


    Py_INCREF(Py_None);
    return Py_None;
}


// ------------------
// turn an instruction set in meomry that was built into an attack structure for live attacks
// it doesnt need anymore information about the instructions since they should be in memory.
static PyObject *PyASC_InstructionsBuildAttack(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"count", "interval", "skip_adjustments", 0};
    int ret = 0;
    int count = self->replay_count;
    int interval = self->replay_interval;
    int skip_adjustments=0;
    AS_attacks *aptr = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iii", kwd_list, &count, &interval, &skip_adjustments))
        return NULL;

    if (self->ctx) {
        if (self->instructions == NULL) {
            // show error.. no instructions to turn into an attack
        } else {

            aptr = InstructionsToAttack(self->ctx, self->instructions, count, interval);

            // if it worked.. lets return its ID
            if (aptr != NULL) {

                aptr->skip_adjustments = skip_adjustments;

                // link the attack to make it active
                aptr->next = self->ctx->attack_list;
                self->ctx->attack_list = aptr;

                // return the attack ID
                ret = aptr->id;
                return PyInt_FromLong(ret);
            }

        }
    }

    Py_INCREF(Py_None);
    return Py_None;
}





// enable attacks by id, ips, ports, or age
static PyObject *PyASC_AttackEnable(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"id","source_ip","destination_ip","any_ip","source_port","destination_port",
    "any_port", "age", 0};
    int id = 0;
    char *source_ip = NULL, *destination_ip = NULL, *any_ip = NULL;
    int source_port = 0, destination_port = 0, any_port = 0, age = 0;
    AS_attacks *aptr = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|isssiiii", kwd_list, &id, &source_ip, &destination_ip,
    &any_ip, &source_port, &destination_port, &any_port, &age)) {
        PyErr_Print();
        return NULL;
    }

    if ((aptr = AttackFind(self->ctx, id, source_ip, destination_ip, any_ip, source_port, destination_port, any_port, age)) != NULL) {
        aptr->paused = 0;
    }


    Py_INCREF(Py_None);
    return Py_None;
    
}



// disable attacks by id, ips, ports, or age
// complete this ***
static PyObject *PyASC_AttackDisable(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"id","source_ip","destination_ip","any_ip","source_port","destination_port",
    "any_port", "age", 0};
    int id = 0;
    char *source_ip = NULL, *destination_ip = NULL, *any_ip = NULL;
    int source_port = 0, destination_port = 0, any_port = 0, age = 0;
    AS_attacks *aptr = NULL;


    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|isssiiii", kwd_list, &id, &source_ip, &destination_ip,
    &any_ip, &source_port, &destination_port, &any_port, &age)) {
        PyErr_Print();
        return NULL;
    }

    if ((aptr = AttackFind(self->ctx, id, source_ip, destination_ip, any_ip, source_port, destination_port, any_port, age)) != NULL) {
        aptr->paused = 1;
    }

    Py_INCREF(Py_None);
    return Py_None;
    
}

// attack list and have optional filters to narrow it down
// this just returns the entire list ATM... i have to add filtering (using PyList_New() with the value, innstead of append)
// redo soon
static PyObject *PyASC_AttackList(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"source_ip","destination_ip","any_ip","source_port","destination_port",
    "any_port", "age", 0};

    char *source_ip = NULL, *destination_ip = NULL, *any_ip = NULL;
    int source_port = 0, destination_port = 0, any_port = 0, age = 0;

    int attack_count = 0;
    PyObject *PAttackList = NULL;
    AS_attacks *aptr = NULL;
    int i = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sssiiii", kwd_list, &source_ip, &destination_ip, &any_ip, &source_port, &destination_port, &any_port, &age)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx == NULL) return NULL;

    attack_count = (int)L_count((LINK *)self->ctx->attack_list);

    PAttackList = PyList_New(attack_count);
    if (PAttackList == NULL) {
        PyErr_Print();
        return NULL;
    }

    aptr = self->ctx->attack_list;

    while (aptr != NULL) {
        PyList_SET_ITEM(PAttackList, i++, PyLong_FromLong(aptr->id));

        aptr = aptr->next;
    }

    //Py_INCREF(PAttackList);
    return PAttackList; 
}


// retrieve distance between two nodes via traceroute, and other mechanisms
// fuzzy means we alllow imaginary nodes whenever data isnt complete
static PyObject *PyASC_TracerouteDistance(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"first_address", "second_address", "check_targets", "fuzzy", 0};
    int ret = 0;
    char *first_address = NULL;
    struct in6_addr first_ipv6;
    int first_is_ipv6 = 0;
    uint32_t first_ipv4 = 0;

    char *second_address = NULL;
    struct in6_addr second_ipv6;
    int second_is_ipv6 = 0;
    uint32_t second_ipv4 = 0;

    TracerouteSpider *Sfirst = NULL, *Ssecond = NULL;

    int check_targets = 0;
    int imaginary=0;
    
    // check_targets means check ->target as well as ->hop (we wanna scan by the actual client/server address instead of routes)

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss|ii", kwd_list, &first_address, &second_address, &check_targets, &imaginary)) {
        PyErr_Print();
        return NULL;
    }

    IP_prepare(first_address, &first_ipv4, &first_ipv6, &first_is_ipv6);
    IP_prepare(second_address, &second_ipv4, &second_ipv6, &second_is_ipv6); 

    // make sure both are the same type of address (cant mix 4, and 6)
    if (first_is_ipv6 != second_is_ipv6) return NULL;

    if (self->ctx) {
        Sfirst = Traceroute_Find(self->ctx, first_ipv4, &first_ipv6, check_targets);
        Ssecond = Traceroute_Find(self->ctx, second_ipv4, &second_ipv6, check_targets);

        if (Sfirst && Ssecond) {
            printf("IDs: %X %X\n", Sfirst->identifier_id, Ssecond->identifier_id);
            ret = Traceroute_Compare(self->ctx, Sfirst, Ssecond, imaginary);
            printf("Distance between %s -> %s: %d\n", first_address, second_address, ret);
        }

        
    }


    return PyInt_FromLong(ret);
}




static PyObject *PyASC_TracerouteGenerateRandomGEO(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"country",0};
    int ret = 0;
    char *country = NULL;
    

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwd_list, &country)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx) {
        ret = TracerouteAddRandomIP(self->ctx, country);
    }

    return PyInt_FromLong(ret);
}




static PyObject *PyASC_MergeAttacks(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"destination_attack_id","source_attack_id",0};
    long destination_id = 0, source_id = 0;
    AS_attacks *dst = NULL;
    AS_attacks *src = NULL;
    int ret = 0;
    

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "kk", kwd_list, &destination_id, &source_id)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx) {
        dst = AttackFind(self->ctx, destination_id, NULL, NULL, NULL, 0, 0, 0, 0);
        src = AttackFind(self->ctx, source_id, NULL, NULL, NULL, 0, 0, 0, 0);

        if (dst && src) {
            // link via dependency...
            dst->dependency = src;
            //ret = MergeAttacks(dst, src);
        }
    }


    return PyInt_FromLong(ret);
}

// enable flushing the network queue to the live wire
static PyObject *PyASC_ScriptEnable(PyAS_Config* self){
    if (self->ctx) self->ctx->script_enable = 1;

    Py_INCREF(Py_None);
    return Py_None; 
}

// enable flushing the network queue to the live wire
static PyObject *PyASC_ScriptDisable(PyAS_Config* self){
    if (self->ctx) self->ctx->script_enable = 0;

    Py_INCREF(Py_None);
    return Py_None; 
}

// enable flushing the network queue to the live wire
static PyObject *PyASC_SpiderLoad(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"filename",0};
    char fname[] = "traceroute";
    char *filename = (char *)&fname;
    

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwd_list, &filename)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx) {
        Spider_Load(self->ctx, filename);
    }

    Py_INCREF(Py_None);
    return Py_None; 
}

// enable flushing the network queue to the live wire
static PyObject *PyASC_SpiderSave(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"filename",0};
    char fname[] = "traceroute";
    char *filename = (char *)&fname;
    

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwd_list, &filename)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx) {
        Spider_Save(self->ctx);
    }

    Py_INCREF(Py_None);
    return Py_None; 
}


static int _skip = 20;

// hack for temporary interactive console to debug
static PyObject *PyASC_Skip(PyAS_Config* self){
    int ret = 0;

    if (_skip-- == 0) {
        ret = 1;

        _skip = 20;
    }

    return PyInt_FromLong(ret);
}

// retry all missing traceroutes
static PyObject *PyASC_TracerouteRetry(PyAS_Config* self){

    if (self->ctx) Traceroute_RetryAll(self->ctx);

    Py_INCREF(Py_None);
    return Py_None; 
}



// show status of current traceroute queue
static PyObject *PyASC_TracerouteStatus(PyAS_Config* self) {
    int i = 0;
    PyObject *PStatusList = NULL;
    long ttl_count[MAX_TTL];
    TracerouteSpider *sptr = NULL;
    int count  = 0;

    memset(ttl_count, 0, sizeof(long)*MAX_TTL);

    if (self->ctx) {
        sptr = self->ctx->traceroute_spider;

        while (sptr != NULL) {
                if (sptr->ttl)  {
                    ttl_count[sptr->ttl]++;
                    count++;
            }
            
            sptr = sptr->next;
        }
            
        if ((PStatusList = PyList_New(MAX_TTL)) == NULL) {
            PyErr_Print();
            return NULL;
        }
        printf("total %d\n", count);

        for (i = 0; i < MAX_TTL; i++) {
            printf("2. ttl_count[%d] = %ld\n", i, ttl_count[i]);
            
            PyList_SET_ITEM(PStatusList, i, PyLong_FromLong(ttl_count[i]));
        }

        return PStatusList; 
    }

    Py_INCREF(Py_None);
    return Py_None; 
}



static PyObject *PyASC_TracerouteResetRetryCount(PyAS_Config* self){
    int ret = 0;
    if (self->ctx) {
        ret = TracerouteResetRetryCount(self->ctx);

    }

    return PyInt_FromLong(ret);
}


static PyObject *PyASC_TracerouteSetPriority(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"address","priority", 0};
    TracerouteQueue *qptr = NULL;
    int ret = 0;
    char *address = NULL;
    int priority = 1;
    uint32_t address_ipv4 = 0;
    int address_is_ipv6 = 0;
    struct in6_addr address_ipv6;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|i", kwd_list, &address, &priority)) {
        PyErr_Print();
        return NULL;
    }

    IP_prepare(address, &address_ipv4, &address_ipv6, &address_is_ipv6);

    if (self->ctx) {
        if ((qptr = TracerouteQueueFindByIP(self->ctx, address_ipv4)) != NULL) {
            ret = qptr->priority = priority;
        }
    }

    return PyInt_FromLong(ret);
}



static PyObject *PyASC_TracerouteSetMax(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"max",0};
    int ret = 0;
    int set_max = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &set_max)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx) {
        self->ctx->traceroute_max_active = set_max;
        Traceroute_AdjustActiveCount(self->ctx);
        ret = set_max;
    }

    return PyInt_FromLong(ret);
}

static PyObject *PyASC_TracerouteRandom(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"completed", 0};
    int completed = 0;
    TracerouteQueue *qptr = NULL;
    int i = 0, count = 0;
    char *_IP = NULL;
    PyObject *ret = NULL;


    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwd_list, &completed)) {
        PyErr_Print();
        return NULL;
    }

    if (self->ctx) {
        count = L_count((LINK *)self->ctx->traceroute_queue);
        i = rand()%count;
        qptr = self->ctx->traceroute_queue;
        while (i--) { qptr = qptr->next; }
        _IP = IP_prepare_ascii(qptr->target_ip, NULL);
        if (_IP) {
            ret = PyString_FromString(_IP);
            free(_IP);
            return ret;
        }
    }

    Py_INCREF(Py_None);
    return Py_None; 
}


static PyObject *PyASC_PCAPCaptureStart(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"filename","skip_filter", 0};
    int ret = 0;
    char *filename = NULL;
    FilterInformation *flt = NULL;
    int skip_filter = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|i", kwd_list, &filename, &skip_filter)) {
        PyErr_Print();
        return NULL;
    }

    if (filename && self->ctx) {
        if (!skip_filter && self->flt.init == 1) {
            flt = (FilterInformation *)calloc(1, sizeof(FilterInformation));
            if (flt) {
                memcpy(flt, &self->flt, sizeof(FilterInformation));
            }
        }

        ret = PCAP_OperationAdd(self->ctx, filename, flt);

    }

    return PyInt_FromLong(ret);
}


static PyObject *PyASC_PCAPCaptureEnd(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"filename",0};
    int ret = 0;
    char *filename = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwd_list, &filename)) {
        PyErr_Print();
        return NULL;
    }

    if (filename && self->ctx) {
        ret = PCAP_OperationRemove(self->ctx, filename);
    }


    return PyInt_FromLong(ret);
}





static PyObject *PyASC_TracerouteQueue(PyAS_Config* self, PyObject *args, PyObject *kwds) {
    static char *kwd_list[] = {"target",0};
    int ret = 0;
    char *target = NULL;
    int is_ipv6;
    uint32_t targetv4;
    struct in6_addr targetv6;
    

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwd_list, &target)) {
        PyErr_Print();
        return NULL;
    }


    IP_prepare(target, &targetv4, &targetv6, &is_ipv6);
    
    if (self->ctx) {
        Traceroute_Queue(self->ctx, targetv4, &targetv6);
    }

    return PyInt_FromLong(ret);
}

// ------------------

static PyMethodDef PyASC_methods[] = {
    // set context (AS_context) to a value.. ill figure out how to do in C later.. from outside python framework
    {"setctx", (PyCFunction)PyASC_CTXSet,    METH_O,    "set context pointer.. automate later" },    
    
    // software does exit(-1) immediately
    {"exit", (PyCFunction)PyASC_DIE,    METH_NOARGS,    "Exits the software immediately.. not gracefully" },
    // *** TODO: graceful shutdown saving all connfiguation, etc

    // disable everything (in top of AS_perform()..) immediately should pause
    {"disable", (PyCFunction)PyASC_Disable,    METH_NOARGS,    "pauses the software" },

    // re-enable
    {"enable", (PyCFunction)PyASC_Enable,    METH_NOARGS,    "continues the software" },

    // clear all attacks and outgoing packets (gracefully.. each section takes care of its own  freeing)
    {"clear", (PyCFunction)PyASC_Clear,    METH_NOARGS,    "clears all outgoing queue, and attack structures" },

    // load sessions from a packet capture into memory as attacks (we need to allow different filters, etc)
    {"pcapload", (PyCFunction)PyASC_PCAPload,    METH_VARARGS | METH_KEYWORDS,    "" },

    // save all outgoing packets as a packet capture (for later), debugging, or repllaying on machines without hte software
    {"pcapsave", (PyCFunction)PyASC_PCAPsave,    METH_O,    "" },

    // retry all tracerouttes
    {"tracerouteretry", (PyCFunction)PyASC_TracerouteRetry,    METH_NOARGS,    "retry missing TTL traceroute responses" },

    // clear all outgoing queue
    {"networkclear", (PyCFunction)PyASC_NetworkClear,    METH_NOARGS,    "clear outgoing network packets" },

    // disable/pause writing to network 
    {"networkoff", (PyCFunction)PyASC_NetworkOff,    METH_NOARGS,    "disable writing to network" },

    // enable/unpause writing to network
    {"networkon", (PyCFunction)PyASC_NetworkOn,    METH_NOARGS,    "enable writing to network" },

    // clear all attacks
    {"attackclear", (PyCFunction)PyASC_AttackClear,    METH_NOARGS,    "clear only attack structures" },
    
    // perform 1 iteration of all attacks (next packet, etc)
    {"attackperform", (PyCFunction)PyASC_AttackPerform,    METH_NOARGS,    "iterate all attack structures once" },

    
    // start a new filter, removing a current one if it was not saved
    {"filtercreate", (PyCFunction)PyASC_FilterCreate,    METH_VARARGS | METH_KEYWORDS,    "" },
    // prepare the fiilter for various flags,, or ips/ports
    {"filterprepare", (PyCFunction)PyASC_FilterPrepare,    METH_VARARGS | METH_KEYWORDS,    "" },
    // then we can do live capture with a filter, and put it into a particular context (and get a call back when X sessions are found)
    // which it can then begin auto attakiing with modifications

    // we want to be able to build instruction sets with python...
    // a script can generate POP, SMTP, etc protocols into attacks directly from python...

    // instructions create (start a new instructions set) clear the current if it wasnt saved into an attack
    {"instructionscreate", (PyCFunction)PyASC_InstructionsCreate,    METH_VARARGS | METH_KEYWORDS,    "" },

    // tcp open connection into the instructions
    {"instructionstcpopen", (PyCFunction)PyASC_InstructionsTCPOpen,   METH_NOARGS,    "" },

    // tcp send data into the instructions (fromm either client or server)
    // the script can perform this as much as needed...
    {"instructionstcpsend", (PyCFunction)PyASC_InstructionsTCPSend,    METH_VARARGS | METH_KEYWORDS,    "" },

    // tcp close connection into instructions
    {"instructionstcpclose", (PyCFunction)PyASC_InstructionsTCPClose,    METH_VARARGS | METH_KEYWORDS,    "" },


    // tcp open connection into the instructions
    //{"instructionstcp6open", (PyCFunction)PyASC_InstructionsTCP6Open,   METH_NOARGS,    "" },

    // tcp send data into the instructions (fromm either client or server)
    // the script can perform this as much as needed...
    //{"instructionstcp6send", (PyCFunction)PyASC_InstructionsTCP6Send,    METH_VARARGS | METH_KEYWORDS,    "" },

    // tcp close connection into instructions
    //{"instructionstcp6close", (PyCFunction)PyASC_InstructionsTCP6Close,    METH_VARARGS | METH_KEYWORDS,    "" },    
    
    // save instructions into an attack structure...
    {"instructionsbuildattack", (PyCFunction)PyASC_InstructionsBuildAttack,    METH_VARARGS | METH_KEYWORDS,    "" },
    
    // build an http session and automatically add as an attack (does ipv4 and ipv6)
    {"buildhttp", (PyCFunction)PyASC_BuildHTTP,    METH_VARARGS | METH_KEYWORDS,    "" },

    // turn on blackhole
    {"blackholeenable", (PyCFunction)PyASC_BlackholeEnable,    METH_NOARGS,    "" },
    // disable blackhole
    {"blackholedisable", (PyCFunction)PyASC_BlackholeDisable,    METH_NOARGS,    "" },
    // clear blackhole list
    {"blackholeclear", (PyCFunction)PyASC_BlackholeClear,    METH_NOARGS,    "" },
    // add to blackhole list
    {"blackholeadd", (PyCFunction)PyASC_BlackholeAdd,    METH_NOARGS,    "" },

    // attackk disable by id, or IP/port (can match all related)
    {"attackdisable", (PyCFunction)PyASC_AttackDisable,    METH_NOARGS,    "" },
    // attack enablle by id, or IP/port
    {"attackenable", (PyCFunction)PyASC_AttackEnable,    METH_NOARGS,    "" },

    // obtain a list of all attacks (figure out whether to return it as an array, dict, or whatever)
    {"attacklist", (PyCFunction)PyASC_AttackList,    METH_VARARGS|METH_KEYWORDS,    "" },

    // enable antiscript to continue executing in C, calling script_perform() inn the python script
    {"scriptenable", (PyCFunction)PyASC_ScriptEnable,    METH_NOARGS,    "enable continous execution, and script_perform()" },

    // disabling script_perform() thus it would exit after the script_perform() which called this, or a python queue script would disable
    {"scriptdisable", (PyCFunction)PyASC_ScriptDisable,    METH_NOARGS,    "enable continous execution, and script_perform()" },

    // merge one attack into another's structure
    {"attackmerge", (PyCFunction)PyASC_MergeAttacks, METH_VARARGS|METH_KEYWORDS, "merges one attack into another (think DNS before WWW,etc)" },

    // queue an address for traceroute research
    {"traceroutequeue", (PyCFunction)PyASC_TracerouteQueue, METH_VARARGS|METH_KEYWORDS, "queue a traceroute" },

    {"traceroutedistance", (PyCFunction)PyASC_TracerouteDistance, METH_VARARGS|METH_KEYWORDS, "find distance between two traceroute analysis structures" },

    {"traceroutesetpriority", (PyCFunction)PyASC_TracerouteSetPriority, METH_VARARGS|METH_KEYWORDS, "prioritize a traceroute" },

    {"traceroutesetmax", (PyCFunction)PyASC_TracerouteSetMax, METH_VARARGS|METH_KEYWORDS, "set max active traceroute queue" },

    {"tracerouteresetretrycount", (PyCFunction)PyASC_TracerouteResetRetryCount, METH_NOARGS, "reset all retry counts" },


    {"tracerouterandom", (  PyCFunction)PyASC_TracerouteRandom,    METH_VARARGS|METH_KEYWORDS,    "" },

    {"tracerouteaddrandomipgeo", (PyCFunction)PyASC_TracerouteGenerateRandomGEO,     METH_VARARGS|METH_KEYWORDS,    "" },

    {"traceroutestatus", (PyCFunction)PyASC_TracerouteStatus,    METH_NOARGS,    "" },

    {"spiderload", (PyCFunction)PyASC_SpiderLoad,    METH_VARARGS|METH_KEYWORDS,    "" },
    {"spidersave", (PyCFunction)PyASC_SpiderSave,    METH_VARARGS|METH_KEYWORDS,    "" },

    // -- for testing.. not really important for later..
    {"incomingqueuecount", (PyCFunction)PyASC_QueueIncomingCount,    METH_NOARGS,    "" },
    {"outgoingqueuecount", (PyCFunction)PyASC_QueueOutgoingCount,    METH_NOARGS,    "" },
    
    {"incomingpoolcount", (PyCFunction)PyASC_QueueIncomingPoolCount,    METH_NOARGS,    "" },
    {"outgoingpoolcount", (PyCFunction)PyASC_QueueOutgoingPoolCount,    METH_NOARGS,    "" },
    // --

    


    {"attackdetails", (PyCFunction)PyASC_AttackDetails,    METH_VARARGS|METH_KEYWORDS,    "gives details about an attack" },
    {"pcapcapturestart", (PyCFunction)PyASC_PCAPCaptureStart,    METH_VARARGS|METH_KEYWORDS,    "captures using current filter to a pcap file" },
    {"pcapcaptureend", (PyCFunction)PyASC_PCAPCaptureEnd,    METH_VARARGS|METH_KEYWORDS,    "ends a pcap capture" },

    // i wanna turn these into structures (getter/setters)
    {"networkcount", (PyCFunction)PyASC_NetworkCount,    METH_NOARGS,    "count network packets" },
    {"attackcount", (PyCFunction)PyASC_AttackCount,    METH_NOARGS,    "count attacks" },
    {"traceroutecount", (PyCFunction)PyASC_TracerouteCount,    METH_VARARGS|METH_KEYWORDS,    "count active traceroutes" },

    // *** remove
    {"skip", (PyCFunction)PyASC_Skip,    METH_NOARGS,    "hack hackish hack" },

    {NULL}  /* Sentinel */
};


/*
for i in FilterSave FilterPrepare FilterCreate InstructionsTCP4Close InstructionsTCP4Send InstructionsTCP4Open InstructionsCreate InstructionsBuildAttack
do
echo "
static PyObject *PyASC_$i(PyAS_Config* self, PyObject *args, PyObject *kwds) {

    Py_INCREF(Py_None);
    return Py_None;
}"
done
*/



static PyTypeObject PyASCType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "antisurveillance.manager",             /* tp_name */
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
    0,   /* tp_traverse */
    0,           /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    PyASC_methods,             /* tp_methods */
    //PyASC_members,             /* tp_members */
    0,                             /* tp_members */
    0,                         /* tp_getset */
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




// initialize python extension
void PyASC_Initialize(void) {
    PyObject* m;

    if (PyType_Ready(&PyASCType) < 0) return;

    // initialize base module name.. antisurveillance
    if ((m = Py_InitModule3("antisurveillance", module_methods, "Anti surveillance management")) == NULL) return;

    Py_INCREF(&PyASCType);

    // create the object? or class? under antisurveillance...
    // so you can perform a = antisurveillance.manager(args)
    PyModule_AddObject(m, "manager", (PyObject *)&PyASCType);
}




// this is fro another project..
// once stable, and moving through itll be redesigned completely...
PyObject *PythonLoadScript(AS_scripts *eptr, char *script_file, char *func_name, PyObject *pArgs) {
    PyObject *pName=NULL, *pModule=NULL, *pFunc=NULL;
    PyObject *pValue=NULL;
    PyObject *ret = NULL;
    char fmt[] = "sys.path.append(\"%s\")";
    char *dirs[] = { "/tmp", "/var/tmp", ".", NULL };
    char buf[1024];
    int i = 0;
    PyObject *pCtx = NULL;
    PyObject *pPerform = NULL;

    if (eptr == NULL) return NULL;
    
    // The script has not been loaded before (the pointer isnt in the structure)
    if (!eptr->pModule) {

        Scripting_ThreadPre(eptr->ctx, eptr);
        
        // initialize python paths etc that we require for operating
        // I'm no python expert. I had to add some directories my first time playing with it.. and here we are.
        PyRun_SimpleString("import sys");
        for (i = 0; dirs[i] != NULL; i++) {
            sprintf(buf, fmt, dirs[i]);
            PyRun_SimpleString(buf);
        }

        // Initialize our extension in python to bridge the script to allow management of the anti surveillance software
        PyASC_Initialize();

        // specify as a python object the name of the file we wish to load
        pName = PyString_FromString(script_file);

        // perform the loading
        pModule = PyImport_Import(pName);
        Py_DECREF(pName);

        // keep for later (for the plumbing/loop)
        if ((eptr->pModule = pModule) == NULL) {
            PyErr_Print();
            ret = NULL;
            goto end;
        }

        // we set the context as a global script variable so it bridges properly to the correct structures for management
        pCtx = PyLong_FromVoidPtr((void *)eptr->ctx);
        PyObject_SetAttrString(pModule, "ctx", pCtx);

        /*
        // *** todo finish
        // new way to get the pointer into the that function
        pASPtr =  PyObject_GetAttrString(pModule, "antisurveillance");
        if (pASPtr) {
            pManager = PyObject_GetAttrString(pASPtr, "manager");
            if (pManager) {
                pSetCTX = PyObject_GetAttrString(pManager, "setctx");

                printf("setctx %p manager %p asptr %p\n", pSetCTX, pManager, pASPtr);
                
                if (pSetCTX && PyCallable_Check(pSetCTX)) {
                    if ((pValue = PyObject_CallObject(pSetCTX, pCtx)) != NULL) {
                        printf("Called OK\n");

                        Py_XDECREF(pValue);
                        pValue = NULL;
                    }
                }
            }
        }
        */

        // lets check if it has a script_perform() function.. if so we will use it later
        pPerform = PyObject_GetAttrString(pModule, (const char *)scripting_main_loop_function);
        if (pPerform && PyCallable_Check(pPerform))
            eptr->perform = 1;

        Scripting_ThreadPost(eptr->ctx, eptr);
    }
    
    // If the module didn't load properly.. then theres no reason to attempt to execute anything
    if ((pModule = eptr->pModule) == NULL) goto end;

    Scripting_ThreadPre(eptr->ctx, eptr);
    
    //PyEval_AcquireThread(evars->python_thread);

    // we want to execute a particular function under this module we imported
    pFunc = PyObject_GetAttrString(pModule, func_name);

    // now we must verify that the function is accurate
    if (!(pFunc && PyCallable_Check(pFunc)))
        goto end;

    pValue = PyObject_CallObject(pFunc, pArgs);
    if (pValue != NULL && !PyErr_Occurred()) {
        // we must extract the integer and return it.. 
        // for init it will contain the module identifier for
        // passing messages between the module & others
        ret = pValue;

        // usually you have to use Py_DECREF() here.. 
        // so if the application requires a more intersting object type from python, then adjust that here   
    }

    Scripting_ThreadPost(eptr->ctx, eptr);

    
    //PyEval_ReleaseThread(evars->python_thread);
end:;
    if (pFunc != NULL) Py_XDECREF(pFunc);
    if (pValue != NULL) Py_XDECREF(pValue);    

    return ret;
}


// use a script's context, and python handles to call a function with a particular message
// this could be used for callbacks, or a copy/paste to finish a proper callback function
int python_call_function(AS_scripts *mptr,  char *message, int size) {
    int ret = -1;
    PyObject *pArgs = NULL;
    PyObject *pMessage = NULL;
    PyObject *pValue = NULL;
        
    Scripting_ThreadPre(mptr->ctx, mptr);

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
                ret = PythonLoadScript(mptr, NULL, (char *)scripting_main_loop_function, pArgs) != NULL;
                
                // free size
                Py_DECREF(pValue);
            }
            // free message
            Py_DECREF(pMessage);
        }
        // free tuple
        Py_DECREF(pArgs);
    }

    Scripting_ThreadPost(mptr->ctx, mptr);

    return ret;
}


// perform one iteration of all scripts (callinng their 'script_perform' function)
int Scripting_Perform(AS_context *ctx) {
    int ret = -1;
    AS_scripts *sptr = NULL;

    if ((ctx == NULL) || ((sptr = ctx->scripts) == NULL)) return 0;

    while (sptr != NULL) {

        // on load did this script contain "script_perform" ?
        if (sptr->perform)
            ret = PythonLoadScript(sptr, NULL, (char *)scripting_main_loop_function, NULL) != NULL;
        
        sptr = sptr->next;
    }

    return ret;
}



// initialize function for the scripting subsystem... simple w just python
int Scripting_Init(AS_context *ctx) {
    int ret = -1;
    
    // initialize python required function
    Py_Initialize();

    // ----
    // https://www.codeproject.com/Articles/11805/Embedding-Python-in-C-C-Part-I


    // pretty sure this is why interactive console was failing..
    // I was missing it..   -- I was wrong.  It was the garbage collector...
    PyEval_InitThreads();


// ----

    ret = 1;

    return ret;           
}


// *** remove from linked list...
int Scripting_Destroy(AS_context *ctx, AS_scripts *mptr) {
    if (mptr == NULL) return -1;
        
    if (mptr->python_thread) {
        Py_EndInterpreter(mptr->python_thread);
        mptr->python_thread = NULL;
    }
    
    return 0;
}


// new scripting structure and initialize python
AS_scripts *Scripting_New(AS_context *ctx) {
    AS_scripts *sctx = NULL;

    if ((sctx = (AS_scripts *)calloc(1, sizeof(AS_scripts))) == NULL) return NULL;

    // set context to the one which is initializing this script
    sctx->ctx = ctx;

    // initialize python for this script
    sctx->python_thread = Py_NewInterpreter();

    // add to script list
    sctx->next = ctx->scripts;
    ctx->scripts = sctx;

    pthread_mutex_init(&sctx->lock_mutex, NULL);

    sctx->mainThreadState = PyThreadState_Get();
    sctx->mainInterpreterState = sctx->mainThreadState->interp;

    return sctx;
}



// this will check all scripts for a callable function by name.. and return the pointer to that
// this will allow several different python files to get loaded, and itll verify each for functions
// it would like to call, or callback
AS_scripts *Scripting_FindFunction(AS_context *ctx, char *func_name) {
    AS_scripts *eptr = ctx->scripts;
    PyObject *pFunc = NULL;
    AS_scripts *ret = NULL;
    

    while (eptr != NULL) {
        if (eptr->pModule) {
            Scripting_ThreadPre(ctx, eptr);

            // we want to execute a particular function under this module we imported
            pFunc = PyObject_GetAttrString(eptr->pModule, func_name);

            // now we must verify that the function is accurate
            if (pFunc && PyCallable_Check(pFunc)) {
                ret = eptr;
                Py_XDECREF(pFunc);
                break;
            }

            Scripting_ThreadPost(ctx, eptr);
        }

        eptr = eptr->next;
    }
    if (eptr) {
        Scripting_ThreadPost(ctx, eptr);
    }

    return ret;
}


// Things that should execute BEFORE python commands begin
int Scripting_ThreadPre(AS_context *ctx, AS_scripts *sptr) {
    int ret = 0;

    if (sptr) {
        pthread_mutex_lock(&sptr->lock_mutex);

        sptr->myThreadState = PyThreadState_New(sptr->mainInterpreterState);
        
        PyEval_ReleaseLock();
        PyEval_AcquireLock();

        sptr->tempState = PyThreadState_Swap(sptr->myThreadState);

        ret = 1;
    }

    return ret;
}

// Things that should execute AFTER python commands are completed
int Scripting_ThreadPost(AS_context *ctx, AS_scripts *sptr) {
    int ret = 0;

    if (sptr) {
        PyThreadState_Swap(sptr->tempState);
        PyEval_ReleaseLock();

        // Clean up thread state
        PyThreadState_Clear(sptr->myThreadState);
        PyThreadState_Delete(sptr->myThreadState);

        sptr->myThreadState = NULL;

        pthread_mutex_unlock(&sptr->lock_mutex);

        ret = 1;

    }

    return ret;
}




PyObject *PyAttackDetails(AS_attacks *aptr) {
    PyObject *pArgs = NULL;

    PyObject *pSrc = NULL;
    PyObject *pDst = NULL;
    PyObject *pPortSrc = NULL;
    PyObject *pPortDst = NULL;
    PyObject *pInstructionsCount = NULL;
    //PyObject *pCurrentPacket = NULL;
    PyObject *pPaused = NULL;
    PyObject *pCount = NULL;
    PyObject *pInterval = NULL;
    PyObject *pCompleted = NULL;
    //PyObject *pFunction = NULL;
    PyObject *pSkipAdjustments = NULL;
    char *Src = NULL;
    char *Dst = NULL;

    Src = (char *)IP_prepare_ascii(aptr->src, &aptr->src6);
    Dst = (char *)IP_prepare_ascii(aptr->dst, &aptr->dst6);
    
    pSrc = PyString_FromString(Src);
    pDst = PyString_FromString(Dst);

    pPortSrc = PyInt_FromLong(aptr->source_port);
    pPortDst = PyInt_FromLong(aptr->destination_port);
    pInstructionsCount = PyInt_FromLong(L_count((LINK *)aptr->packet_build_instructions));
    
    pPaused = PyInt_FromLong(aptr->paused);
    pInterval = PyInt_FromLong(aptr->repeat_interval);
    pCount = PyInt_FromLong(aptr->count);
    pSkipAdjustments = PyInt_FromLong(aptr->skip_adjustments);
    pCompleted = PyInt_FromLong(aptr->completed);


    if ((pArgs = PyTuple_New(10)) == NULL) goto end;

    //def content_generator(language,site_id,site_category,ip_src,ip_dst,ip_src_geo,ip_dst_geo,client_body,client_body_size,server_body,server_body_size):

    PyTuple_SetItem(pArgs, 0, pSrc);
    PyTuple_SetItem(pArgs, 1, pDst);
    PyTuple_SetItem(pArgs, 2, pPortSrc);
    PyTuple_SetItem(pArgs, 3, pPortDst);
    PyTuple_SetItem(pArgs, 4, pInstructionsCount);
    PyTuple_SetItem(pArgs, 5, pPaused);
    PyTuple_SetItem(pArgs, 6, pInterval);
    PyTuple_SetItem(pArgs, 7, pCount);
    PyTuple_SetItem(pArgs, 8, pSkipAdjustments);
    PyTuple_SetItem(pArgs, 9, pCompleted);

    end:;
    return pArgs;
}
