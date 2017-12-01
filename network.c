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
#include <fcntl.h>
#include <net/ethernet.h>
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
    struct ether_header *ethhdr = NULL;

    // if disabled (used to store after as a pcap) fromm python scripts
    // beware.. if things are marked to be cleared it wont until this flag gets removed and the code below gets executed
    // maybe change later.. ***
    if (ctx->network_disabled) {
        //printf("network disabled\n");
        return 0;
    }

    // we need some raw sockets.
    if (ctx->raw_socket <= 0) {
        if (prepare_socket(ctx) <= 0) {
            //printf("no raw socket\n");
            return -1;
        }
    }
    
    while (optr != NULL) {

#ifdef TESTING_DONT_FREE_OUTGOING
        if (optr->submitted) {
            //printf("testing dont submit outgoing\n");
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

            //printf("sendto bytes sent %d errno %d socket %d\n", bytes_sent, errno, ctx->raw_socket);
            // I need to perform some better error checking than just the size..
            if (bytes_sent != optr->size) {
                // if this packet fails 3 times.. lets ignore it (unroutable??)
                //if (optr->failed++ > 2) optr->ignore = 1;
                //break;
            } else {
                //optr->failed = 0;
                count++;
            }

            // keep track of how many packets.. the calling function will want to keep track
            
#ifdef TESTING_DONT_FREE_OUTGOING
            optr->submitted = 1; optr = optr->next; continue;
#endif
        }

        // if it was successful... free it
        //if (!optr->failed) {

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

            //printf("pushed packet\n");

            // move to the next link
            optr = onext;
        /*} else {
            // else move to the n ext
            optr = optr->next;
        }*/
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
int OutgoingQueueAdd(AS_context *ctx, AttackOutgoingQueue *optr, int only_try) {
    //if (ctx == NULL) return -1;

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

    OutgoingQueueAdd(ctx, optr, 0);

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
    if (OutgoingQueueAdd(ctx, optr, 1) == 0) {
        // create a thread to add it to the network outgoing queue.. (brings it from 4minutes to 1minute) using a pthreaded outgoing flusher
        if (pthread_create(&optr->thread, NULL, AS_queue_threaded, (void *)optr) != 0) {
            // if we for some reason cannot pthread (prob memory).. lets do it blocking
            OutgoingQueueAdd(ctx, optr, 0);
        }
    }

    return 1;
}



// another thread for dumping from queue to the network
void *thread_network_flush(void *arg) {
    AS_context *ctx = (AS_context *)arg;
    int count = 0;
    int i = 0;
    struct sched_param params;
    pthread_t this_thread = pthread_self();

    params.sched_priority = sched_get_priority_max(SCHED_FIFO);
    pthread_setschedparam(this_thread, SCHED_FIFO, &params);


    while (1) {
        pthread_mutex_lock(&ctx->network_queue_mutex);

        // how many packets are successful?
        count = FlushAttackOutgoingQueueToNetwork(ctx);
        
        pthread_mutex_unlock(&ctx->network_queue_mutex);

        //if (count)printf("Network Thread Outgoing count flushed: %d\n", count);
        // if none.. then lets sleep..  
        if (!count) {
            //printf("didnt push any\n");
            sleep(1);
        } else {
            
            i = (1000000 / 4) - (i * 25000);
            
            //printf("usleep %d\n", i);
            i /= 4;
            if (i > 0 && (i <= 1000000))
                usleep(i);
        }
    }
}

// prepare raw outgoing socket (requires root)..
int prepare_socket(AS_context *ctx) {
    int rawsocket = 0;
    int one = 1;
    int bufsize = 1024*1024*1;

    

    if (ctx->raw_socket > 0) {
        // If we cannot use setsockopt.. there must be trouble!
        if (setsockopt(ctx->raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
            close(ctx->raw_socket);
            ctx->raw_socket = 0;
        }
    }
    
    // open raw socket
    if ((rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) <= 0)
        return -1;

    setsockopt(rawsocket, SOL_SOCKET, SO_SNDBUFFORCE, &bufsize, sizeof(bufsize));

    // ensure the operating system knows that we will include the IP header within our data buffer
    if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0)
        return -1;

    // set it for later in the overall context
    ctx->raw_socket = rawsocket;

    return rawsocket;
}


// http://yusufonlinux.blogspot.com/2010/11/data-link-access-and-zero-copy.html
// https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/

// prepare raw incoming socket.. we perform our own filtering so we want all packets
int prepare_read_socket(AS_context *ctx) {
    int sockfd = 0;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    char network[] = "wlp2s0";
    int protocol= IPPROTO_TCP;
    int sockopt = 1;
    int flags = 0;
    struct ifreq if_mac;
    struct ifreq if_ip;
    int one = 1;
    int bufsize = 1024*1024*1   ;

    // set ifr structure to 0
    memset (&ifr, 0, sizeof (struct ifreq));
    memset(&if_mac, 0, sizeof(struct ifreq));
    memset(&if_ip, 0, sizeof(struct ifreq));
    

    // if we have a read socket.. then we wanna make sure its OK.. quick IOCTL call would do it
    if (ctx->read_socket != 0) {
        // if this works properly.. it should already have been initialized
        if (ioctl (ctx->read_socket, SIOCGIFINDEX, &ifr) == 0) goto end;

        // close it if not..
        close(ctx->read_socket);

        // set to 0 since its stale
        ctx->read_socket = 0;
    }

    // initialize a new socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) goto end;

    
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize));
    

    // set the socket inside of the context structure
    //ctx->read_socket = sockfd;
    /*
    // copy the interface we want to use into the ifr structure
    // *** find this automatically
    strncpy((char *) ifr.ifr_name, network, IFNAMSIZ);
    strncpy((char *)if_mac.ifr_name, network, IFNAMSIZ);
    strncpy((char *)if_ip.ifr_name, network, IFNAMSIZ);

    // call ioctl to use this ifr structure (and network interface)
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) != 0) goto end;
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) goto end;
    if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0) goto end;

//sll.sll_ifindex = 

    // prepare sockaddr for binding to this interface
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons (protocol);
    

    printf("interface index %d\n", sll.sll_ifindex);
    printf("IP: %u\n", ((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr);

    // bind to it
    if (bind(sockfd, (struct sockaddr *) &sll, sizeof(sll)) != 0) goto end;

    // set the socket to reuse 
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1) goto end;
    
    // bind to do the network device
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, network, IFNAMSIZ-1) == -1) goto end;
*/
    // set non blocking
    //https://stackoverflow.com/questions/1543466/how-do-i-change-a-tcp-socket-to-be-non-blocking
    flags = fcntl(sockfd, F_GETFL, flags);
    flags |= O_NONBLOCK;
    flags = fcntl(sockfd, F_SETFL, flags);

    // ensure the operating system knows that we will include the IP header within our data buffer
    //if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) return -1;

    // other parts of this application require this socket
    ctx->read_socket = sockfd;

    //printf("open socket %d\n", sockfd);

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
    FILE *fd;
    char fname[1024];
    int r = 0;

    if (size == 0) goto end;

    // if we dont have any subsystems waiting for packets.. no point
    if (nptr == NULL) {
        //printf("NULL pointer\n");
        goto end;
    }

    //sprintf(fname, "packets/pkt_%d_%d.bin", getpid(), rand()%0xFFFFFFFF);

    packet += sizeof(struct ether_header);
    size -= sizeof(struct ether_header);
/*
    if (1==2 && (fd = fopen(fname, "wb")) != NULL) {
        fwrite(packet, size, 1, fd);
        fclose(fd);
    } */

    /*if (size < 40) {
        printf("small pkt?\n");
        goto end;
    }*/

    
    // packet needs to be in this structure to get analyzed.. reusing pcap loading routines
    if ((pptr = (PacketInfo *)calloc(1, sizeof(PacketInfo))) == NULL) {
        //printf("couldnt alloc memory for processinng packet\n");
        return -1;
    }

    // duplicate the packet data.. putting it into this packet structure
    if (PtrDuplicate(packet, size, &pptr->buf, &pptr->size) == 0) {
        //printf("couldnt duplicate data required for processing\n");
        goto end;
    }

    // analyze that packet, and turn it into a instructions structure
    if ((iptr = PacketsToInstructions(pptr)) == NULL) {
        /*printf("couldnt convert to instructions pptr->buf %p pptr->size %d\n", pptr->buf, pptr->size);
            if (1==2 && (fd = fopen(fname, "wb")) != NULL) {
        fwrite(packet, size, 1, fd);
        fclose(fd); } */

        goto end;
    }

    // loop looking for any subsystems where it may be required
    while (nptr != NULL) {

        //printf("SRC IP: %u protocol %d\n", iptr->source_ip, iptr->flags);
        //printf("DST: %u\n", iptr->destination_ip);

        //printf("%s:%d -> %s:%d\n", Asrc_ip, iptr->source_port, Adst_ip, iptr->destination_port);

        // if the packet passes the filter then call its processing function
        if (FilterCheck(nptr->flt, iptr)) {
            // maybe verify respoonse, and break the loop inn some case
            r = nptr->incoming_function(ctx, iptr);
            
            nptr->bytes_processed += size;
            
            if (r) break;
        }

        // move to the next network filter to see if it wants the packet
        nptr = nptr->next;
    }

    // worked out alright.
    ret = 1;

    end:;

    // free these structures since they are no longer required
    PacketsFree(&pptr);
    if (r == 0) PacketBuildInstructionsFree(&iptr);

    return ret;
}

// this will process the incoming buffers
int network_process_incoming_buffer(AS_context *ctx) {
    IncomingPacketQueue *nptr = NULL, *nnext = NULL;
    int ret = 0;
    char *sptr = NULL;
    int cur_packet = 0;
    int packet_size = 0;

    
    // lock thread so we dont attempt to read or write while another thread is
    pthread_mutex_lock(&ctx->network_incoming_mutex);

    // lets pop the buffer we need to read first from the list
    nptr = ctx->incoming_queue;

    // set all to NULL so its awaiting for future packets...
    ctx->incoming_queue = ctx->incoming_queue_last = NULL;

    // unlock thread...
    pthread_mutex_unlock(&ctx->network_incoming_mutex);

    if (nptr == NULL) goto end;

    //printf("network_process_incoming_buffer: first link %p\n", nptr);

    // now lets process all packets we have.. each is a cluster of packets
    while (nptr != NULL) {

        // lets loop for every packet in this structure..
        while (cur_packet < nptr->cur_packet) {
            // sptr starts at the beginning of the buffer
            sptr = (char *)(&nptr->buf);

            //increase it to the startinng place of this packet
            sptr += nptr->packet_starts[cur_packet];

            // calculate the size of this particular packet we are going to process
            packet_size = nptr->packet_ends[cur_packet] - nptr->packet_starts[cur_packet];

            // call the function which processes it by turning it into a packet structure
            // it will then send to the correct functions for analysis, and processing afterwards
            // for whichever subsystem may want it
            process_packet(ctx, sptr, packet_size);

            // move to the next packet
            cur_packet++;
        }

        // we are finished processing that cluster... we can free it
        nnext = nptr->next;

        // free this structure since we are finished with it
        free(nptr);
        
        // go to the next cluster of packets we are processing
        nptr = nnext;
    }

end:;
    return ret;
}


// this attempts to get one cluster of packets from the read socket..
// it can get called from the threaded version, or in general from a function
// which just needs to read on its own timing (or from python)/loops
int network_fill_incoming_buffer(int read_socket, IncomingPacketQueue *nptr) {
    char *sptr = NULL;
    int r = 0;
    int ret = 0;

    //printf("network_fill_incoming_buffer %d %p\n", read_socket, nptr);

    // reset using our buffer..
    sptr = (char *)&nptr->buf;
    // no need since calloc
    nptr->cur_packet = 0;
    nptr->size = 0;

    // read until we run out of packets, or we fill our buffer size by 80%
    do {
        //r = recv(sptr, max_buf_size - size, )
        r = recvfrom(read_socket, sptr, nptr->max_buf_size - nptr->size, MSG_DONTWAIT, NULL, NULL);

        // if no more packets.. lets break and send it off for processing
        if (r <= 0) {
            //printf("NO packets to read\n");
            break;
        }

        //printf("read packet\n");

        // set where this packet begins, and  ends
        nptr->packet_starts[nptr->cur_packet] = nptr->size;
        nptr->packet_ends[nptr->cur_packet] = (nptr->size + r);

        // prep for the next packet
        nptr->cur_packet++;

        // increase by the amount we read..
        sptr += r;
        // increase the size of our buffer (for pushing to queue)
        nptr->size += r;

        // if we have used 90% of the buffer size...
        if (nptr->size >= ((nptr->max_buf_size / 10) * 9)) break;

        // we only have positions for a max of 1024 packets with this buffer
        if (nptr->cur_packet >= MAX_PACKETS) break;
    } while (r);

    // did we get some packets?
    ret = (nptr->cur_packet > 0);

    end:;

    //printf("network_fill_incoming_buffer ret %d\n", ret);
    return ret;
}

// thread to read constantly from the network
void *thread_read_network(void *arg) {
    AS_context *ctx = (AS_context *)arg;
    int i = 0;
    IncomingPacketQueue *nptr = NULL;
    int paused = 0;
    int sleep_interval = 0;
    struct sched_param params;
    pthread_t this_thread = pthread_self();

    //printf("network reading thread\n");
    // open raw reading socket
    i = prepare_read_socket(ctx);

    // if sock didnt open, or we cant allocae space for reading packets
    if (!i) goto end;
 
     // We'll set the priority to the maximum.
    params.sched_priority = sched_get_priority_max(SCHED_FIFO);
    pthread_setschedparam(this_thread, SCHED_FIFO, &params);

    // lets read forever.. until we stop it for some reason
    while (1) {

        //printf("while\n");
        // only alllocate a buffer if we dont have one already... (no need to keep doing it if no packets were found)
        if (nptr == NULL) {
            // if we cannot allocate a buffer for some reason...
            if ((nptr = (IncomingPacketQueue *)calloc(1, sizeof(IncomingPacketQueue))) == NULL) {
                //printf("cannot allocate buffer space for reading incoming packets!\n");
                goto end;
            }

            nptr->max_buf_size = MAX_BUF_SIZE;
        }

        //printf("wanna read from %d\n", ctx->read_socket);

        if (network_fill_incoming_buffer(ctx->read_socket, nptr)) {

            //printf("got packets\n");
            // now lets get the packets into the actual queue as fast as possible
            // we read untiil there isnt anything left before we lock the mutex
            pthread_mutex_lock(&ctx->network_incoming_mutex);    
        
            // link ordered... (maybe slow?) lets try..
            //L_link_ordered((LINK **)&ctx->incoming_queue, (LINK *)nptr);

            // alternate if slow.. itll be quick
            // find the last buffer we queued if it exists
            if (ctx->incoming_queue_last) {
                // set the next of that to this new one
                ctx->incoming_queue_last->next = nptr;
                // set the last as this one for the next queue
                ctx->incoming_queue_last = nptr;
            } else {
                // buffer is completely empty.. set it, and the last pointer to this one
                ctx->incoming_queue = ctx->incoming_queue_last = nptr;
            }

            //printf("packets queued for processing\n");
            
            // lets unlink just in case.. so we allocate a new one
            nptr = NULL;
        }

        // get paused variable from network disabled
        paused = (ctx->network_disabled || ctx->paused);

        // no more variables which we have to worry about readwrite from diff threads
        pthread_mutex_unlock(&ctx->network_incoming_mutex);

        // if paused.. lets sleep for 1/10th a second each time we end up here..
        if (paused) {
            usleep(100000);
        } else {
            
            sleep_interval = (5000000 / 4) - (ctx->aggressive * 25000);
            sleep_interval /= 2;
            if (sleep_interval > 0)
                // timing change w aggressive-ness
                usleep(sleep_interval);
            
        }
    }

    end:;

    
    // lets lock mutex sinnce we will change some variables
    pthread_mutex_lock(&ctx->network_incoming_mutex);

    // so we know this thread no longer is executing for other logic
    ctx->network_read_threaded = 0;
    
    // unlock mutex..
    pthread_mutex_unlock(&ctx->network_incoming_mutex);

    // free nptr if it wasnt passed along before getting here
    PtrFree(&nptr);

    //printf("network reading thread ending\n");

    // exit thread
    pthread_exit(NULL);

    return;
}


int Network_AddHook(AS_context *ctx, FilterInformation *flt, void *incoming_function) {
    NetworkAnalysisFunctions *nptr = NULL;

    if (!flt || !incoming_function) return -1;

    if ((nptr = (NetworkAnalysisFunctions *)calloc(1, sizeof(NetworkAnalysisFunctions))) == NULL)
        return -1;

    nptr->incoming_function = incoming_function;
    nptr->flt = flt;

    // insert so the network functionality will begin calling our function for these paackets
    nptr->next = ctx->IncomingPacketFunctions;
    ctx->IncomingPacketFunctions = nptr;

    return 1;
}


// merge this with the other attackqueueadd.. and make 2 smaller functions for each input type..
int NetworkQueueAddBest(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = 0;
    AttackOutgoingQueue *optr = NULL;

    // allocate a structure for the outgoing packet to get wrote to the network interface
    if ((optr = (AttackOutgoingQueue *)calloc(1, sizeof(AttackOutgoingQueue))) != NULL) {
        // we need to pass it the final packet which was built for the wire
        optr->buf = iptr->packet;
        optr->type = iptr->type;
        optr->size = iptr->packet_size;

        // remove the pointer from the instruction structure so it doesnt get freed in this function
        iptr->packet = NULL;
        iptr->packet_size = 0;

        // the outgoing structure needs some other information
        optr->dest_ip = iptr->destination_ip;
        optr->ctx = ctx;

        // if we try to lock mutex to add the newest queue.. and it fails.. lets try to pthread off..
        if (OutgoingQueueAdd(ctx, optr, 1) == 0) {
            // create a thread to add it to the network outgoing queue.. (brings it from 4minutes to 1minute) using a pthreaded outgoing flusher
            if (pthread_create(&optr->thread, NULL, AS_queue_threaded, (void *)optr) != 0) {
            // if we for some reason cannot pthread (prob memory).. lets do it blocking
                OutgoingQueueAdd(ctx, optr, 0);
            }
        }

        ret = 1;
    }

    return ret; 
}
