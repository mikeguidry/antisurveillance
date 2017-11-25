/*

This is where functionality for writing information directly to the networking device is located.  It will also contain
functions for sniffing the network interface for information.  The information can be used as new attack parameters, or
a few other things I must add which will require call back events after passing a filter.

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
#include <net/if.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
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

    // if disabled (used to store after as a pcap) fromm python scripts
    // beware.. if things are marked to be cleared it wont until this flag gets removed and the code below gets executed
    // maybe change later.. ***
    if (ctx->network_disabled) return 0;

    // we need some raw sockets.
    if (ctx->raw_socket <= 0) {
        if (prepare_socket(ctx) <= 0) return -1;
    }
    
    while (optr != NULL) {

#ifdef TESTING_DONT_FREE_OUTGOING
        if (optr->submitted) {
            optr = optr->next;
            continue;
        }
#endif

        if (!optr->ignore) {
            // parameters required to write the spoofed packet to the socket.. it ensures the OS fills in the ethernet layer (src/dst mac
            // addresses for the local IP, and local IP's gateway
            rawsin.sin_family       = AF_INET;
            rawsin.sin_port         = optr->dest_port;
            rawsin.sin_addr.s_addr  = optr->dest_ip;
        
            // write the packet to the raw network socket.. keeping track of how many bytes
            int bytes_sent = sendto(ctx->raw_socket, optr->buf, optr->size, 0, (struct sockaddr *) &rawsin, sizeof(rawsin));

            // I need to perform some better error checking than just the size..
            if (bytes_sent != optr->size) break;

            // keep track of how many packets.. the calling function will want to keep track
            count++;
#ifdef TESTING_DONT_FREE_OUTGOING
            optr->submitted = 1; optr = optr->next; continue;
#endif
        }
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

void ClearPackets(AS_context *ctx) {
    AttackOutgoingQueue *optr = ctx->network_queue, *onext = NULL;

    pthread_mutex_lock(&ctx->network_queue_mutex);

    // mark all as ignore (itll just clear on next loop)
    while (optr != NULL) {

        optr->ignore = 1;

        optr = optr->next;
    }
    
    pthread_mutex_unlock(&ctx->network_queue_mutex);
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

    if (qptr == NULL || qptr->buf == NULL) return -1;

    if ((optr = (AttackOutgoingQueue *)calloc(1, sizeof(AttackOutgoingQueue))) == NULL)
        return -1;

    // we move the pointer so its not going to use CPU usage to copy it again...
    // the calling function should release the pointer (set to NULL) so that it doesnt
    // free it too early
    optr->buf = qptr->buf;
    qptr->buf = NULL;
    optr->type = qptr->type;

    optr->size = qptr->size;
    qptr->size = 0;

    // required for writing to wire:
    optr->dest_ip = qptr->dest_ip;
    optr->dest_port = qptr->dest_port;

    // Just in case some function later (during flush) will want to know which attack the buffer was generated for
    optr->attack_info = attack;

    optr->ctx = ctx;

    // if we try to lock mutex to add the newest queue.. and it fails.. lets try to pthread off..
    if (AttackQueueAdd(ctx, optr, 1) == 0) {
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
    int i = 0;

    while (1) {
        pthread_mutex_lock(&ctx->network_queue_mutex);

        // how many packets are successful?
        count = FlushAttackOutgoingQueueToNetwork(ctx);
        
        pthread_mutex_unlock(&ctx->network_queue_mutex);

        //if (count)printf("Count: %d\n", count);
        // if none.. then lets sleep..  
        if (!count)
            sleep(1);
        else {
            i = (1000000 / 4) - (i * 25000);
            
            usleep(i);
        }
    }
}

// Open a raw socket and use the global variable to store it
int prepare_socket(AS_context *ctx) {
    int rawsocket = 0;
    int one = 1;

    if (ctx->raw_socket > 0) {
        // If we cannot use setsockopt.. there must be trouble!
        if (setsockopt(ctx->raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
            close(ctx->raw_socket);
            ctx->raw_socket = 0;
        }
    }
    
    // open raw socket
    if ((rawsocket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) <= 0)
        return -1;

    // ensure the operating system knows that we will include the IP header within our data buffer
    if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0)
        return -1;

    // set it for later in the overall context
    ctx->raw_socket = rawsocket;

    return rawsocket;
}

#define ETHER_TYPE 0x0800
// http://yusufonlinux.blogspot.com/2010/11/data-link-access-and-zero-copy.html
int prepare_read_socket(AS_context *ctx) {
    int sockfd = 0;
    struct ifreq ifr;
    struct sockaddr_ll sll;

    memset (&ifr, 0, sizeof (struct ifreq));

    if (ctx->read_socket != 0) {
        // if this works properly.. it should already have been initialized
        if (ioctl (ctx->read_socket, SIOCGIFINDEX, &ifr) == 0) goto end;
        close(ctx->read_socket);
        ctx->read_socket = 0;
    }

    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) goto end;
    
    strncpy ((char *) ifr.ifr_name, interface.c_str (), IFNAMSIZ);
    if (ioctl (sockfd, SIOCGIFINDEX, &ifr) != 0) goto end;

    
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons (protocol);

    if (bind(sockfd, (struct sockaddr *) &sll, sizeof(sll)) != 0) goto end;

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) goto end;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1) goto end;

    ctx->read_socket = sockfd;

    end:;
    

    // if it failed for any reason...
    if (ctx->read_socket == 0 && sockfd) close(sockfd);

    // return if it was successful
    return (ctx->read_socket != 0);
}



// this will take a buffer, and size expected to come directly fromm the network driver
// it will process it through filters, and if passing will send to whatever functions, or subsystems
// requested data of that statue
// *** todo: maybe make a filter check which takes a packet buffer instead of
// requiring the build instructions (less cycles)
int process_packet(AS_context *ctx, char *packet, int size) {
    PacketInfo *pptr = NULL;
    NetworkAnalysisFunctions *nptr = ctx->IncomingPacketFunctions;
    PacketBuildInstructions *iptr = NULL;
    int ret = -1;

    // if we dont have any subsystems waiting for packets.. no point
    if (nptr == NULL) goto end;

    // packet needs to be in this structure to get analyzed.. reusing pcap loading routines
    if ((pptr = (PacketInfo *)calloc(1, sizeof(PacketInfo))) == NULL) return -1;

    // prepare the structure with the information
    pptr->buf = packet;
    pptr->size = size;

    // analyze that packet, and turn it into a instructions structure
    if ((iptr = PacketsToInstructions(pptr)) == NULL) goto end;

    // loop looking for any subsystems where it may be required
    while (nptr != NULL) {
        // if the packet passes the filter then call its processing function
        if (FilterCheck(&nptr->flt, iptr)) {
            // maybe verify respoonse, and break the loop inn some case
            nptr->incoming_function(ctx, iptr);
        }

        nptr = nptr->next;
    }

    // worked out alright.
    ret = 1;

    end:;

    // free these structures since they are no longer required
    PacketsFree(&pptr);
    PacketBuildInstructionsFree(&iptr);

    return ret;
}

void *thread_read_network(void *arg) {
    AS_context *ctx = (AS_context *)arg;
    int i = 0;
    char *sptr = NULL;
    int r = 0;
    IncomingBufferQueue *nptr = NULL;
    int paused = 0;

    // open raw reading socket
    i = prepare_read_socket(ctx);

    // if sock didnt open, or we cant allocae space for reading packets
    if (!i) goto end;

    // lets read forever.. until we stop it for some reason
    while (1) {
        // if we cannot allocate a buffer for some reason...
        if ((nptr = (IncomingBufferQueue *)calloc(1, sizeof(IncomingBufferQueue))) == NULL) {
            printf("cannot allocate buffer space!\n");
            goto end;
        }

        nptr->max_buf_size = MAX_BUF_SIZE;

        // reset using our buffer..
        sptr = (char *)&nptr->buf;
        // no need since calloc
        //nptr->cur_packet = 0;
        //nptr->size = 0;

        // read until we run out of packets, or we fill our buffer size by 80%
        do {
            //r = recv(sptr, max_buf_size - size, )
            r = recvfrom(sockfd, &nptr->buf, nptr->max_buf_size - nptr->size, 0, NULL, NULL);

            // if no more packets.. lets break and send it off for processing
            if (r <= 0) break;

            // set where this packet begins
            nptr->packet_starts[nptr->cur_packet++] = size;

            // increase by the amount we read..
            sptr += r;
            // increase the size of our buffer (for pushing to queue)
            nptr->size += r;

            // if we have used 90% of the buffer size...
            if (nptr->size >= ((nptr->max_buf_size / 10) * 9)) break;
            // we only have positions for a max of 1024 packets with this buffer
            if (nptr->cur_packet >= 1024) break;
        } while (r);

        // now lets get the packets into the actual queue as fast as possible
        // we read untiil there isnt anything left before we lock the mutex
        pthread_mutex_lock(&ctx->network_incoming_mutex);    
    
        // link ordered... (maybe slow?) lets try..
        L_link_ordered((LINK **)&ctx->incoming_queue, (LINK *)nptr);

/*
        // alternate if slow.. itll be quick
        // find the last buffer we queued if it exists
        if (ctx->incoming_queue_last) {
            // set the next of that to this new one
            incoming_queue_last->next = nptr;
            // set the last as this one for the next queue
            ctx->incoming_queue_last = nptr;
        } else {
            // buffer is completely empty.. set it, and the last pointer to this one
            incoming_queue = incoming_queue_last = nptr;
        }
*/
        
        // lets unlink just in case
        nptr = NULL;

        // get paused variable from network disabled
        paused = (ctx->network_disabled || ctx->paused);

        // no more variables which we have to worry about readwrite from diff threads
        pthread_mutex_unlock(&ctx->network_incoming_mutex);

        // if paused.. lets sleep for half a second each time we end up here..
        if (paused) {
            usleep(500000);
        } else {
            // timing change w aggressive-ness
            usleep((1000000 / 4) - (ctx->aggressive * 25000));
        }
    }

    end:;

    
    // lets lock mutex sinnce we will change some variables
    pthread_mutex_lock(&ctx->network_incoming_mutex);

    // so we know this thread no longer is executing for other logic
    ctx->network_read_threadded = 0;
    
    // unlock mutex..
    pthread_mutex_unlock(&ctx->network_incoming_mutex);

    // free buffer if it was allocated
    PtrFree(&buf);

    // free nptr if it wasnt passed along before getting here
    PtrFree(&nptr);

    // exit thread
    pthread_exit(NULL);

    return;
}