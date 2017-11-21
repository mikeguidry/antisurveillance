/*
Anti Surveillance software...
This is meant to protect your traffic from NSA, and other countries mass surveillance programs.  It can also ensure fiber taps need to
have exponential resources to process information.  I will add a few other module, and a network attack shortly.  

NSA: This is for rape.  I think you guys get it now.  Really thought I'd sit by and do nothing?  Right.  To think..
     if you morons didn't drug & rape me again in 2017,  I may not have done this.  You fucking people and your god complex.
     you won't have that anymore ;)


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


#define TEST

// Perform one iteration of each attack structure that was queued
// ***  todo: we can thread off separate threads for different types of attacks later..
// depending on scripting, etc
int AS_perform(AS_context *ctx) {
    AS_attacks *aptr = ctx->attack_list;
    attack_func func;
    int r = 0;
    
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
                    // call the correct function for performing this attack to build packets.. it could be the first, or some adoption function decided to clear the packets
                    // to call the function again
                    func = (attack_func)aptr->function;
                    if (func != NULL) {
                        // r = 1 if we created a new thread
                        r = ((*func)(aptr) == NULL) ? 0 : 1;
                    } else {
                        // no custom function.. lets use build packets
                        BuildPackets(aptr);
                    }
                }

                if (!r && !aptr->paused) {
                    // If those function were successful then we would have some packets here to queue..
                    if ((aptr->current_packet != NULL) || (aptr->packets != NULL)) {
                        PacketQueue(ctx, aptr);
                    } else {
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

    // flush network packets queued to wire
    if (!ctx->network_threaded)
        FlushAttackOutgoingQueueToNetwork(ctx);

    // traceroute, blackhole, scripting?, timers?
    Subsystems_Perform(ctx);

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

// create a new context, and initialize some things
AS_context *AS_ctx_new() {
    AS_context *ctx = NULL;

    srand(time(0));

    if ((ctx = (AS_context *)calloc(1, sizeof(AS_context))) == NULL) return NULL;
    
    // initialize anything related to special attacks in attacks.c
    attacks_init(ctx);

    // initialize mutex for network queue...
    pthread_mutex_init(&ctx->network_queue_mutex, NULL);

    // start network queue thread
    if (pthread_create(&ctx->network_thread, NULL, thread_network_flush, (void *)ctx) == 0)
        ctx->network_threaded = 1;

    return ctx;
}

// perform iterations of other subsystems...
int Subsystems_Perform(AS_context *ctx) {
    Traceroute_Perform(ctx);
    BH_Perform(ctx);
}

int Test_Generate(AS_context *ctx, int argc, char *argv[]) {
    int server_port, client_port;
    uint32_t server_ip, client_ip;
    int count = 1;
    int repeat_interval = 1;
    int r = 0;
    int loop_count = 0;
    int i = 0;

    if (argc == 1) {
        bad_syntax:;
        printf("%s ipv4_client_ip client_port ipv4_server_ip server_port client_body_file server_body_file repeat_count repeat_interval\n",
            argv[0]);
        exit(-1);
    }
    
    // client information
    client_ip       = inet_addr(argv[1]);
    client_port     = atoi(argv[2]);

    // server information
    server_ip       = inet_addr(argv[3]);
    server_port     = atoi(argv[4]);

    // client request data (in a file)
    ctx->G_client_body   = FileContents(argv[5], &ctx->G_client_body_size);
    // server responsse data (in a file)
    ctx->G_server_body   = FileContents(argv[6], &ctx->G_server_body_size);


    // how maany times to repeat this session on the internet?
    // it will randomize source port, etc for each..
    count           = atoi(argv[7]);
    // how many seconds in between each request?
    // this is because its expecting to handling tens of thousands simul from each machine
    // millions depending on how much of an area the box will cover for disruption of the surveillance platforms
    repeat_interval = atoi(argv[8]);

    if (!client_ip || !server_ip || !client_port || !server_port || !ctx->G_client_body ||
             !ctx->G_server_body || !count || !repeat_interval) goto bad_syntax;

    // Initialize an attack structure regarding passed information
    if ((r = AS_session_queue(ctx, 1, client_ip, server_ip, client_port, server_port, count, repeat_interval, 1,
                 (void *)&HTTP4_Create)) != 1) {
        printf("error adding session\n");
        exit(-1);
    }

    return 1;
}


int Test_PCAP(AS_context *ctx, char *filename) {
    int i = 0;

    printf("Loading data from packet capture for attacks: %s\n", filename);

    i = PCAPtoAttack(ctx, filename, 80, 99999, 1);

    printf("Total from PCAP(80) : %d\n", L_count((LINK *)ctx->attack_list));

    return 1;
}



// *** Redesign this.. allowing for tests, generating packets, or loading from PCAP...
// or being controlled by a third party mechanism (script, etc)
int main(int argc, char *argv[]) {
    int i = 0, r = 0;
    int start_ts = time(0);
    char *filename = NULL;
    int loop_count = 0;
    AS_context *ctx = AS_ctx_new();
    int aggressive = 140000;
    char *Eaggressive = NULL;

    // *** redo this.. and allow it to call AggressionSleep() where needed.. set 0-10 in ctx
    if ((Eaggressive = getenv("AGGRESSIVE")) != NULL) {
        i = atoi(Eaggressive);
        if (i > 10) i = 10;
        if (i < 0) i = 0;
        aggressive -= (20000 * i);
        
        printf("Aggressive: %d [%d]\n", i, aggressive);

        ctx->aggressive = i;
    } else {
        ctx->aggressive = 0;
    }

    /*
    {
        test_icmp4(ctx);
        for (i = 0; i < 1000; i++) {
            AS_perform(ctx);
            sleep(1);
        }

        
        
        exit(-1);
    }
*/

    if (argc > 2) {
        if (Test_Generate(ctx, argc, argv) != 1)
            exit(-1);
    } else if (argc == 2) {
        filename = argv[1];
    
        if (Test_PCAP(ctx, filename) != 1)
            exit(-1);        
    }


    loop_count = (L_count((LINK *)ctx->attack_list) > 1000) ? 300 : 30;
    printf("Loop count: %d\n", loop_count);
    
    // We loop to call this abunch of times because theres a chance all packets do not get generated
    // on the first call.  It is designed this way to handle a large amount of fabricated sessions 
    // simultaneously... since this is just a test... let's loop a few times just to be sure
    for (i = 0; i < loop_count; i++) {
        r = AS_perform(ctx);
        if (r != 1) printf("AS_perform() = %d\n", r);

        usleep(500);
    }

    i = 0;

    if (1==0)
    while (++i) {
        AS_perform(ctx);
        if ((i % 5)==0) {
            printf("\rCount: %d                      \t", i);
            fflush(stdout);
        }
        usleep(700000);
    }

    // how many packes are queued in the output supposed to go to the internet?
    printf("network queue: %p\n", ctx->network_queue);
    if (ctx->network_queue)
        printf("packet count ready for wire: %d\n", L_count((LINK *)ctx->network_queue));  


    printf("Gzip Count: %d\n", ctx->total_gzip_count);

    // This is probably the amount of time it'd dumping to network since its all happening simultaneously
    printf("Time before dumping packets to disk: %d seconds\n", (int)(time(0) - start_ts));

    
    PcapSave(ctx, filename ? (char *)"output2.pcap" : (char *)"output.pcap", ctx->network_queue, NULL, 1);
    

    printf("Time to fabricate, and dump packets to disk: %d seconds\n", (int)(time(0) - start_ts));

    exit(0);
}

