/*
Anti Surveillance software...
This is meant to protect your traffic from NSA, and other countries mass surveillance programs.  It can also ensure fiber taps need to
have exponential resources to process information.  I will add a few other module, and a network attack shortly.  

NSA: This is for rape.  I think you guys get it now.  Really thought I'd sit by and do nothing?  Right.  To think..
     if you morons didn't drug & rape me again in 2017,  I may not have done this.  You fucking people and your god complex.
     you won't have that anymore ;)

Oh BTW: feel free to steal more of my intellectual property.. you can use this all you like all over the world ;)

If this is the damage I can do alone... what do you  think will happen in the future?

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "network.h"
#include "antisurveillance.h"
#include "pcap.h"
#include "attacks.h"
#include "packetbuilding.h"
#include "http.h"
#include "utils.h"
#include "network_api.h"


#define TEST


// Perform one iteration of each attack structure that was queued
int AS_perform(AS_context *ctx) {
    AS_attacks *aptr = ctx->attack_list;
    OutgoingPacketQueue *optr = NULL;
    attack_func func;
    int r = 0;  
    int i = 0;

    // the script shouldnt worry about this unless its running on different threads.. only GZIP, and loading fromm large pcaps
    // are currently using different threads
    //if (__sync_lock_test_and_set(&ctx->paused, 0)) return 0;
    if (ctx->paused) return 0;

    // enumerate through each attack in our list
    while (aptr != NULL) {
        //printf("perform: aptr %p\n", aptr);
        // try to lock this mutex
        if (pthread_mutex_trylock(&aptr->pause_mutex) == 0) {
            // if we need to join this thread (just in case pthread will leak otherwise)
            if (aptr->join) {
                pthread_join(aptr->thread, NULL);
                aptr->join = 0;
            }
            
            //printf("aptr %p next %p\n", aptr, aptr->next);
            if (!aptr->paused && !aptr->completed) {
                //printf("seems ok %p\n", aptr->packet_build_instructions);
                r = 0;
                // if we dont have any prepared packets.. lets run the function for this attack
                if (aptr->packets == NULL) {
                    //printf("packes null\n");
                    // call the correct function for performing this attack to build packets.. it could be the first, or some adoption function decided to clear the packets
                    // to call the function again
                    func = (attack_func)aptr->function;
                    if (func != NULL) {
                        //printf("func not null\n");
                        // r = 1 if we created a new thread
                        r = ((*func)(aptr) == NULL) ? 0 : 1;
                    } else {
                        //printf("build packets\n");
                        // no custom function.. lets use build packets
                        BuildPackets(aptr);
                    }
                }

                if (!r && !aptr->paused) {
                    //printf("not pause\n");
                    // If those function were successful then we would have some packets here to queue..
                    if ((aptr->current_packet != NULL) || (aptr->packets != NULL)) {
                        //printf("packet queue\n");
                        // lets execute X iterations (to get 30 packets out for this particular attack)
                        for (i = 0; i < ctx->iterations_per_loop; i++) {
                            PacketLogic(ctx, aptr, &optr);
                        }
                    } else {
                        //printf("completed\n");
                        // otherwise we mark as completed to just free the structure
                        aptr->completed = 1;
                    }
                }
            }

            pthread_mutex_unlock(&aptr->pause_mutex);
        }

        // go to the next
        aptr = aptr->next;
    }

    // every loop lets remove completed sessions... we could choose to perform this every X iterations, or seconds
    // to increase speed at times.. depending on queue, etc
    AS_remove_completed(ctx);

    if (optr) {
        pthread_mutex_lock(&ctx->network_queue_mutex);

        if (ctx->outgoing_queue_last) {
            ctx->outgoing_queue_last->next = optr;
            ctx->outgoing_queue_last = optr;
        } else {
            ctx->outgoing_queue_last = ctx->outgoing_queue = optr;
        }

        pthread_mutex_unlock(&ctx->network_queue_mutex);
    }


    if (!ctx->network_write_threaded) { OutgoingQueueProcess(ctx); }

    // traceroute, blackhole, scripting?, timers?
    Subsystems_Perform(ctx);

    //ctx->free_memory = FreeMemoryMB();
    
    return 1;
}



// If a session has been deemed completed, then this function will remove it and fix up the linked lists
// This was designed separately so that it doesn't force tough pointer tracking, and element removing other places.
void AS_remove_completed(AS_context *ctx) {
    AS_attacks *aptr = ctx->attack_list, *anext = NULL, *alast = NULL;

    // enumerate through all attacks looking for completed ones to remove
    while (aptr != NULL) {
        // try to lock this mutex
        if (pthread_mutex_trylock(&aptr->pause_mutex) == 0) {
            // is this attack structure completed?
            if (aptr->completed == 1) {
                    // we arent using a normal for loop because
                    // it'd have an issue with ->next after free
                    anext = aptr->next;

                    // free all packets from this attack structure..
                    AttackFreeStructures(aptr);

                    if (ctx->attack_list == aptr)
                        ctx->attack_list = anext;
                    else {
                        alast->next = anext;
                    }

                    pthread_mutex_unlock(&aptr->pause_mutex);
                    
                    // free the structure itself
                    free(aptr);

                    aptr = anext;

                    continue;
                }

            pthread_mutex_unlock(&aptr->pause_mutex);
        }

        alast = aptr;

        aptr = aptr->next;
    }

    return;
}


void AS_Clear_All(AS_context *ctx) {
    // clear all attacks (mark all as completed)
    AttacksClear(ctx);
    // clear all outgoing packets in queue (set to ignore)
    ClearPackets(ctx);
}

// create a new context, and initialize some things
AS_context *AS_ctx_new() {
    AS_context *ctx = NULL;

    // seed random number generator by current time (not secure but no biggie here)
    srand(time(0));

    // allocate memory for the main context
    if ((ctx = (AS_context *)calloc(1, sizeof(AS_context))) == NULL) return NULL;


    if ((ctx->network_interface = getgatewayandiface()) == NULL) {
        fprintf(stderr, "error getting default network interface!\n");
        exit(-1);
    }

    ctx->network_interface = strdup("docker0");

    // 25 pools waiting initially for reading packets..
    ctx->initial_pool_count = 0;
    ctx->iterations_per_loop = 5;
    ctx->http_discovery_add_always = 1;
    ctx->ipv6_gen_any = 1;

    // need a strategy for fds here to finish select() support for the 
    ctx->socket_fd = 50;
    
    // pool mutex.. so we can ensure its separate
    pthread_mutex_init(&ctx->network_pool_mutex, NULL);

    // allocate network read pools
    NetworkAllocateReadPools(ctx);
    NetworkAllocateWritePools(ctx);

    // initialize anything related to special attacks in attacks.c
    attacks_init(ctx);

    // initialize traceroute filter & packet analysis function
    Traceroute_Init(ctx);

    // other things in research.c (geoip, etc) maybe move later or redo init/deinit
    Research_Init(ctx);

    // initialize mutex for network queue...
    pthread_mutex_init(&ctx->network_queue_mutex, NULL);

    // initialize pcap network plugin for saving data from the wire
    // now we're a full fledge sniffer.
    PCAP_Init(ctx);

    // start threads after loading.. so we dont have useless packets to process
    Threads_Start(ctx);

    // initialize real time http session discovery.. so we can automatically geenerate attacks for mass surveillance from live arbitrary traffic
    // aint this going to fuck shit up :).. esp on a worm w routers ;).. shittt... good luck
    WebDiscover_Init(ctx);

    // this is a subsystem which will get access to all packets to add IPv6 (mainly) addreses to use for generating new random-ish  addresses
    IPGather_Init(ctx);


    NetworkAPI_Init(ctx);

    return ctx;
}

int Threads_Start(AS_context *ctx) {
    int ret = 0;
    // start network outgoing queue thread
    if (pthread_create(&ctx->network_write_thread, NULL, thread_network_flush, (void *)ctx) == 0) {
        ctx->network_write_threaded = 1;
        ret++;
    }

    // start network incoming queue thread
    if (pthread_create(&ctx->network_read_thread, NULL, thread_read_network, (void *)ctx) == 0) {
        ctx->network_read_threaded = 1;
        ret++;
    }

    return ret;
}

// !!! call subsystems which are active at the moment
// perform iterations of other subsystems...
int Subsystems_Perform(AS_context *ctx) {
    // first we process any incoming packets.. do this BEFORE traceroute since it awaits data
    network_process_incoming_buffer(ctx);

    if (ctx->traceroute_enabled && L_count((LINK *)ctx->traceroute_queue)) {
        // now move any current traceroute research forward
        Traceroute_Perform(ctx);
    }

    if (L_count((LINK *)ctx->blackhole_queue)) {
        // now apply any changes, or further the blackhole attacks
        BH_Perform(ctx);
    }

    if (ctx->http_discovery_enabled) {
        // perform http discovery looking for live http sessions in real time
        WebDiscover_Perform(ctx);
    }

    if (L_count((LINK *)ctx->socket_list)) {
        // our full socket implementation
        NetworkAPI_Perform(ctx);
    }

    return 1;
}



// All binaries (revolving around scripting, or C loops) requires these initialization routines
AS_context *Antisurveillance_Init() {
    int i = 0;
    char *Eaggressive = NULL;
    AS_context *ctx = AS_ctx_new();
    AS_scripts *sctx = NULL;

    if (ctx == NULL) {
        printf("Antisurveillance_init(): Error creating new context\n");
        return NULL;
    }

    // *** redo this.. and allow it to call AggressionSleep() where needed.. set 0-10 in ctx
    if ((Eaggressive = getenv("AGGRESSIVE")) != NULL) {
        i = atoi(Eaggressive);
        if (i > 10) i = 10;
        if (i < 0) i = 0;

        ctx->aggressive = i;
    }

    // initialize scripting subsystem
    Scripting_Init();

    if ((sctx = Scripting_New(ctx)) == NULL) {
        printf("Initialize scripting failed.\n");
        return NULL;
    }

    ctx->scripts = sctx;

    return ctx;
}