#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
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
#include "picohttpparser.h"

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
    if (GenerateTCP4ConnectionInstructions(&cptr, &build_list) != 1) { ret = -2; goto err; }

    // now we must send data from client to server (http request)
    if (GenerateTCP4SendDataInstructions(&cptr, &build_list, FROM_CLIENT, client_body, client_size) != 1) { ret = -3; goto err; }

    // now we must send data from the server to the client (web page body)
    if (GenerateTCP4SendDataInstructions(&cptr, &build_list, FROM_SERVER, server_body, server_size) != 1) { ret = -4; goto err; }

    // now lets close the connection from client side first
    if (GenerateTCP4CloseConnectionInstructions(&cptr, &build_list, FROM_CLIENT) != 1) { ret = -5; goto err; }

    // that concludes all packets
    aptr->packet_build_instructions = build_list;

    // now lets build the low level packets for writing to the network interface
    BuildTCP4Packets(aptr);

    // all packets done! good to go!
    ret = 1;
    err:;
    return ret;
}


// GZIP initialization
void gzip_init(AS_context *ctx) {
    pthread_mutexattr_t attr;

    if (!ctx->gzip_initialized) {
        ctx->gzip_initialized = 1;
        
        pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_NONE);
        pthread_mutexattr_setprioceiling(&attr, 0); 

        pthread_mutex_init(&ctx->gzip_cache_mutex, NULL);

        
    }

    return;
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

    aptr->paused = 1;

    // GZIP Attack
    GZipAttack(ctx, aptr, &dptr->server_body_size, &dptr->server_body);
 
    // build session using the modified server body w gzip attacks
    i = BuildHTTP4Session(aptr, aptr->dst, aptr->src, aptr->destination_port, dptr->client_body, dptr->client_body_size, 
        dptr->server_body, dptr->server_body_size);
            
    // free the details that were passed to us
    PtrFree((char **)&dptr->server_body);
    PtrFree((char **)&dptr->client_body);
    

    // unpause the thread
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
char *ConnectionData(AS_attacks *attack, int side, int *_size) {
    char *ret = NULL;
    int size = 0;
    AS_attacks *aptr = attack;
    PacketBuildInstructions *iptr = attack->packet_build_instructions;
    char *sptr = NULL;

    // lets get the size first..
    while (iptr != NULL) {
        // make sure its the correct side...
        if (((side == FROM_CLIENT) && (iptr->client == 1)) || ((side == FROM_SERVER) && (iptr->client == 0))) {
            size += iptr->data_size;
        }
        iptr = iptr->next;
    }

    sptr = ret = (char *)malloc(size);
    if (ret == NULL) return NULL;

    iptr = attack->packet_build_instructions;

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
    char buf[4096], *method = NULL, *path = NULL;
    int pret = 0, minor_version = 0;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len = 0, path_len = 0, num_headers = 0;
    ssize_t rret = 0;
    char *hptr = NULL;

    return 0;

    // lets only perform on port 80 for now...
    if (aptr->destination_port != 80) return ret;

    if ((response = ConnectionData(aptr, FROM_SERVER, &response_size)) == NULL) return 0;

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

