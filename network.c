/*
*** since we have packet analysis already developed.. I'll add some raw capturing code in here.  It will allow Quantum Insert
protection to be developed, and this can become the 'third party server' for hundreds of thousands of clients..
-- all in one fuck you to nsa -- this is for rape.


*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "utils.h"





// flushes the attack outgoing queue to the network, and then frees up the lists..
// raw sockets here.. or we could use a writing pcap mode..
// itd be smart to attempt to find a naming scheme, and an instructions file
// so this can be paired with command line tools so things like scp, and ssh can be used
// with a timing mechanism (ntp, or something else which allows correct timing for launching commands)
// so that future pakets can be generated (weeks, days, etc) in advance.. and sent to correct locations
// worldwide to be replayed for particular reasons, or just continous...
// we arent always sure the queues will flush.. so.. we should allow checking, and ensuring some packets can stay in queue
// itd be nice to get them out as quickly as possible since AS_perform() or other commands handle timings
// timings needs to be moved from seconds to milliseconds (for advanced protocol emulation)
int FlushAttackOutgoingQueueToNetwork(AS_context *ctx) {
    int count = 0;
    AttackOutgoingQueue *optr = ctx->network_queue, *onext = NULL;
    struct sockaddr_in rawsin;

    // we need some raw sockets.
    if (ctx->raw_socket <= 0) {
        if (prepare_socket(ctx) <= 0) return -1;
    }
    
    while (optr != NULL) {
        // parameters required to write the spoofed packet to the socket.. it ensures the OS fills in the ethernet layer (src/dst mac
        // addresses for the local IP, and local IP's gateway
        rawsin.sin_family       = AF_INET;
        rawsin.sin_port         = optr->dest_port;
        rawsin.sin_addr.s_addr  = optr->dest_ip;
    
        // write the packet to the raw network socket.. keeping track of how many bytes
        int bytes_sent = 0;//sendto(ctx->raw_socket, optr->buf, optr->size, 0, (struct sockaddr *) &rawsin, sizeof(rawsin));

        // I need to perform some better error checking than just the size..
        if (bytes_sent != optr->size) break;

        // keep track of how many packets.. the calling function will want to keep track
        count++;

        // what comes after? we are about to free the pointer so..
        onext = optr->next;

        // clear buffer
        PtrFree(&optr->buf);

        // free structure..
        free(optr);

        // fix up the linked lists
        if (ctx->network_queue == optr)
            ctx->network_queue = onext;

        if (ctx->network_queue_last == optr)
            ctx->network_queue_last = NULL;

        // move to the next link
        optr = onext;
    }

    // return how many successful packets were transmitted
    return count;
}


// Adds a queue to outgoing packet list which is protected by a thread.. try means return if it fails
// This is so we can attempt to add the packet to the outgoing list, and if it would block then we can
// create a thread... if thread fails for some reason (memory, etc) then itll block for its last call here
int AttackQueueAdd(AS_context *ctx, AttackOutgoingQueue *optr, int only_try) {
    if (only_try) {
        if (pthread_mutex_trylock(&ctx->network_queue_mutex) != 0)
            return 0;
    } else {
        pthread_mutex_lock(&ctx->network_queue_mutex);
    }
    
    if (ctx->network_queue == NULL) {
        ctx->network_queue = ctx->network_queue_last = optr;
    } else {
        if (ctx->network_queue_last != NULL) {
            ctx->network_queue_last->next = optr;
            ctx->network_queue_last = optr;
        }
    }

    pthread_mutex_unlock(&ctx->network_queue_mutex);

    return 1;
}

// thread for queueing into outgoing attack queue.. just to ensure the software doesnt pause from generation of new sessions
void *AS_queue_threaded(void *arg) {
    AttackOutgoingQueue *optr = (AttackOutgoingQueue *)arg;
    AS_context *ctx = optr->ctx;

    AttackQueueAdd(ctx, optr, 0);

    pthread_exit(NULL);
}

// It will move a packet from its PacketInfo (from low level network packet builder) into the
// over all attack structure queue going to the Internet.
int AS_queue(AS_context *ctx, AS_attacks *attack, PacketInfo *qptr) {
    AttackOutgoingQueue *optr = NULL;

    if ((optr = (AttackOutgoingQueue *)calloc(1, sizeof(AttackOutgoingQueue))) == NULL)
        return -1;

    // we move the pointer so its not going to use CPU usage to copy it again...
    // the calling function should release the pointer (set to NULL) so that it doesnt
    // free it too early
    optr->buf = qptr->buf;
    qptr->buf = NULL;

    optr->size = qptr->size;
    qptr->size = 0;

    // required for writing to wire:
    optr->dest_ip = qptr->dest_ip;
    optr->dest_port = qptr->dest_port;

    // Just in case some function later (during flush) will want to know which attack the buffer was generated for
    optr->attack_info = attack;

    optr->ctx = ctx;

    // if we try to lock mutex to add the newest queue.. and it fails.. lets try to pthread off..
    if (AttackQueueAdd(ctx, optr, 0) == 0) {
        // create a thread to add it to the network outgoing queue.. (brings it from 4minutes to 1minute) using a pthreaded outgoing flusher
        if (pthread_create(&optr->thread, NULL, AS_queue_threaded, (void *)optr) != 0) {
            // if we for some reason cannot pthread (prob memory).. lets do it blocking
            AttackQueueAdd(ctx, optr, 0);
        }
    }

    return 1;
}



// another thread for dumping from queue to the network
void *thread_network_flush(void *arg) {
    AS_context *ctx = (AS_context *)arg;
    int count = 0;

    while (1) {
        pthread_mutex_lock(&ctx->network_queue_mutex);

        // how many packets are successful?
        count = FlushAttackOutgoingQueueToNetwork(ctx);
        
        pthread_mutex_unlock(&ctx->network_queue_mutex);

        // if none.. then lets sleep..  
        if (!count)
            usleep(200);
    }
}

// Open a raw socket and use the global variable to store it
int prepare_socket(AS_context *ctx) {
    int rawsocket = 0;
    int one = 1;
    
    if ((rawsocket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) <= 0)
        return -1;

    if (setsockopt(rawsocket, IPPROTO_IP,IP_HDRINCL, (char *)&one, sizeof(one)) < 0)
        return -1;

    ctx->raw_socket = rawsocket;

    return rawsocket;
}

