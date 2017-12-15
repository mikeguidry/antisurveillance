/*

Full network stack making use of my framework.. It's needed for a few things to come shortly.  It is 'emulated' in a way where regular applications
can use it without requiring any code changes.  This will allow LD_PRELOAD, or other manipulations to activate, and use it.

I need it for a 0day, backdoors without ports, custom VPN, etc...

It should be possible to slim down the entire binary to <200-300kb without python for usage in many real world scenarios w pure C code.

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>  
#include <arpa/inet.h>
#include <stddef.h> /* For offsetof */
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "research.h"
#include "utils.h"
#include "identities.h"
#include "scripting.h"
#include "network_api.h"
#include "instructions.h"
#include <math.h>


// global variable for AS_context since the libc functions for sockets cannot be changed-
AS_context *NetworkAPI_CTX = NULL;



ssize_t my_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t my_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t my_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t my_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t my_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int my_accept4(int sockfd, struct sockaddr *addr,socklen_t *addrlen, int flags);
int my_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int my_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
int my_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen);
int my_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int my_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

// ----
// done
int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int my_socket(int domain, int type, int protocol);
int my_listen(int sockfd, int backlog);
int my_close(int fd);
// ----





// initialize the network stack
int NetworkAPI_Init(AS_context *ctx) {
    int ret = -1;
    NetworkAnalysisFunctions *nptr = NULL;
    FilterInformation *flt = NULL;

    // global pointer required since all network functions API are set is stone..
    // another option is to have the thread itself hold it in TLS
    NetworkAPI_CTX = ctx;

    // lets prepare incoming ICMP processing for our traceroutes
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL) goto end;

    // empty filter.. we want everything.
    FilterPrepare(flt, 0, 0);

    // add into network subsystem so we receive all packets
    if (Network_AddHook(ctx, flt, &NetworkAPI_Incoming) != 1) goto end;

    ret =  1;

    end:;
    return ret;
}


// find a socket context by its file descriptor (our own virtual fds)
ConnectionContext *NetworkAPI_ConnectionByFD(AS_context *ctx, int fd) {
    SocketContext *sptr = NULL;
    ConnectionContext *cptr = NULL;
    ConnectionContext *ret = NULL;

    pthread_mutex_lock(&ctx->socket_list_mutex);

    sptr = ctx->socket_list;
    while (sptr != NULL) {
        if ((cptr = sptr->connections) != NULL) {
            while (cptr != NULL) {
                if (cptr->socket_fd == fd) {
                    ret = cptr;
                    goto end;
                    break;
                }
            
                cptr = cptr->next;
            }
        }

        sptr = sptr->next;
    }


end:;
    pthread_mutex_unlock(&ctx->socket_list_mutex);
    // always return a locked mutex.. this is for BLOCKING activites (connect, etc)
    if (ret) pthread_mutex_lock(&cptr->mutex);

    return ret;
}


// find a socket context by its file descriptor (our own virtual fds)
SocketContext *NetworkAPI_SocketByFD(AS_context *ctx, int fd) {
    SocketContext *sptr = NULL;
    ConnectionContext *cptr = NULL;

    pthread_mutex_lock(&ctx->socket_list_mutex);

    sptr = ctx->socket_list;
    while (sptr != NULL) {
        if (!sptr->completed && sptr->socket_fd == fd)
            break;

        if ((cptr = sptr->connections) != NULL) {
            while (cptr != NULL) {
                if (cptr->socket_fd == fd)
                    break;
            
                cptr = cptr->next;
            }
        }
        sptr = sptr->next;
    }

    pthread_mutex_unlock(&ctx->socket_list_mutex);
    return sptr;
}



// find a context by a state AND a port (or just port).. or just state
SocketContext *NetworkAPI_SocketByStatePort(AS_context *ctx, int state, int port) {
    SocketContext *sptr = NULL;

    pthread_mutex_lock(&ctx->socket_list_mutex);

    sptr = ctx->socket_list;
    while (sptr != NULL) {
        if (!sptr->completed && (!state || ((sptr->state & state))))
            if (port && sptr->port == port)
                break;

        sptr = sptr->next;
    }
    pthread_mutex_unlock(&ctx->socket_list_mutex);

    return sptr;
}


// find a new file descriptor to use.. start at some initial FD and increase until overflow then began at initial again..
// check against socket list to find the first which is available
// !!! this neeeds to change to allow select() which will use 0-1024
int NetworkAPI_NewFD(AS_context *ctx) {
    SocketContext *sptr = NULL;
    int i = ctx->socket_fd;
    int try = 4096;

    do {
        if (i++ < 1024) i = 4096;

        sptr = NetworkAPI_SocketByFD(ctx, i);

    } while (sptr && try--);

    if (try == 0) return -1;

    ctx->socket_fd = ++i;

    return i;
}

// create a new socket context structure and append it to the main list 
SocketContext *NetworkAPI_SocketNew(AS_context *ctx) {
    int i = 0;
    SocketContext *sptr = NULL;

    // if all file descriptors are in use then return NULL
    if ((i = NetworkAPI_NewFD(ctx)) == -1) return NULL;

    // allocate space for a new socket context
    if ((sptr = (SocketContext *)calloc(1, sizeof(SocketContext))) != NULL) {
        sptr->socket_fd = i;
        sptr->ts = time(0);
        sptr->identifier = rand()%0xFFFFFFFF;
        sptr->seq = rand()%0xFFFFFFFF;
        sptr->window_size = 1500 - (20*2+12);

        pthread_mutex_init(&sptr->mutex, NULL);

        pthread_mutex_lock(&ctx->socket_list_mutex);
        L_link_ordered((LINK **)&ctx->socket_list, (LINK *)sptr);
        pthread_mutex_unlock(&ctx->socket_list_mutex);
    }

    return sptr;
}



// create a new connection structure, attach it to a socket context, and lock its mutex
ConnectionContext *NetworkAPI_ConnectionNew(SocketContext *sptr) {
    ConnectionContext *cptr = NULL;

    // allocate space for this structure
    if ((cptr = (ConnectionContext *)calloc(1, sizeof(ConnectionContext))) == NULL)
        return -1;

    cptr->ts = cptr->last_ts = time(0);
    cptr->port = sptr->port;
    cptr->identifier = rand()%0xFFFFFFFF;
    cptr->seq = rand()%0xFFFFFFFF;
    cptr->socket = sptr;

    pthread_mutex_init(&cptr->mutex, NULL);

pthread_mutex_lock(&NetworkAPI_CTX->socket_list_mutex);
    // add the connection to the original socket context structure so it can get accepted by the appllication   
    L_link_ordered((LINK **)&sptr->connections, (LINK *)cptr);
pthread_mutex_unlock(&NetworkAPI_CTX->socket_list_mutex);
    
    pthread_mutex_lock(&cptr->mutex);

    return cptr;
}



// free all IO buffers
void NetworkAPI_FreeBuffers(IOBuf **ioptr) {
    IOBuf *ptr = NULL, *pnext = NULL;

    // if a pointer wasnt passed then we rturn  immediately
    if (ioptr == NULL) return;

    // dereference that pointer to its first element in the list of IO
    ptr = *ioptr;

    // verify there are packets there to begin with
    if (ptr == NULL) return;

    // loop for each element to free all packets
    while (ptr != NULL) {
        // once AS_queue() executes on this.. it moves the pointer over
        // so it wont need to be freed from here (itll happen when outgoing buffer flushes)
        PtrFree(&ptr->buf);

        // free all instruction structures attached to this I/O (mainly used for incoming & debugging)
        if (ptr->iptr)
            PacketBuildInstructionsFree(&ptr->iptr);

        // keep track of the next, then free the current..
        pnext = ptr->next;

        // free this specific structure element
        free(ptr);

        // now use that pointer to move forward..
        ptr = pnext;
    }

    // no more packets left... so lets ensure it doesn't get double freed
    *ioptr = NULL;

    return;
}



void NetworkAPI_ConnectionsCleanup(AS_context *ctx, ConnectionContext **connections) {
    ConnectionContext *cptr = NULL, *cnext = NULL, *clast = NULL;
    int ts = time(0);

    // get the first connection in the list of connections that was passed to us
    cptr = *connections;

    // loop for each connection in that list
    while (cptr != NULL) {
        // try to lock the mutex for each connection so we can determine if it timed out, or other things must take place
        if (pthread_mutex_trylock(&cptr->mutex) == 0) {
            // 30 second keep alive packets
            if ((ts - cptr->last_ts) > 30) {
                // send ACK to attempt to keep connection open..
                if (NetworkAPI_GeneratePacket(ctx, cptr->socket, cptr, TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP) != NULL)
                    cptr->last_ts = ts;
            }

            //timeout = 5 min.. (we can probably remove this for ourselves.. it could be infinite)
            if ((ts - cptr->last_ts) > 300) cptr->completed = 2;

            // if completed is 2 it means we can remove all buffers... and its ready to close for good
            if (cptr->completed == 2) {
                NetworkAPI_FreeBuffers(&cptr->in_buf);
                NetworkAPI_FreeBuffers(&cptr->out_buf);
                PacketBuildInstructionsFree(&cptr->out_instructions);

                cnext = cptr->next;

                // remove this connection from the list.. appending the next in order to the last, or the start of the main list
                if (clast == NULL)
                    *connections = clast = cnext;
                else
                    clast->next = cnext;
                
                pthread_mutex_unlock(&cptr->mutex);

                free(cptr);
                cptr = cnext;

                continue;            
            }
            pthread_mutex_unlock(&cptr->mutex);
        }

        clast = cptr;
        cptr = cptr->next;
    }
}



// socket cleanup for our perform() loop
int NetworkAPI_Cleanup(AS_context *ctx) {
    SocketContext *sptr = NULL, *snext = NULL, *slast = NULL;
    pthread_mutex_lock(&ctx->socket_list_mutex);
    sptr = ctx->socket_list;
    while (sptr != NULL) {
        // first cleanup connections.. we need a timeout on these.. (if connecctions are idle for 5 minutes?)
        NetworkAPI_ConnectionsCleanup(ctx, &sptr->connections);

        // we can only cleanup this socket context if all connections are over (they are linked directly)
        if (sptr->completed && !L_count((LINK *)sptr->connections)) {
            snext = sptr->next;

            if (slast == NULL) {
                ctx->socket_list = snext;
                slast = ctx->socket_list;
            } else {
                slast->next = snext;
            }

            NetworkAPI_FreeBuffers(&sptr->in_buf);
            NetworkAPI_FreeBuffers(&sptr->out_buf);

            //pthread_mutex_unlock(&sptr->mutex);

            free(sptr);

            sptr = snext;
            continue;
        }

        //pthread_mutex_unlock(&sptr->mutex);

        slast = sptr;
        sptr = sptr->next;
    }
    pthread_mutex_unlock(&ctx->socket_list_mutex);
}


// transmits a queued UDP packet
void NetworkAPI_TransmitUDP(AS_context *ctx, ConnectionContext *cptr, IOBuf *ioptr, OutgoingPacketQueue *optr) {
    int i = 0, ret = 0;
    PacketBuildInstructions *iptr = NULL;
   
    // create instruction packet for the ICMP(4/6) packet building functions
    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
        iptr->type = PACKET_TYPE_UDP_4|PACKET_TYPE_UDP;

        iptr->ttl = cptr->socket->ttl;
        iptr->destination_ip = ioptr->addr.sin_addr.s_addr;
        iptr->source_ip = ctx->my_addr_ipv4;
        iptr->source_port = cptr->port;
        iptr->destination_port = ntohs(ioptr->addr.sin_port);
        iptr->header_identifier = cptr->identifier++;

        if ((iptr->data = (char *)calloc(1, ioptr->size)) != NULL) {
            memcpy(iptr->data, ioptr->buf, ioptr->size);     
            iptr->data_size = ioptr->size;
        }

        // build final packet for wire..
        if (iptr->type & PACKET_TYPE_UDP_6)
            i = BuildSingleUDP6Packet(iptr);
        else if (iptr->type & PACKET_TYPE_UDP_4)
            i = BuildSingleUDP4Packet(iptr);

        // prepare it into final structure for wire for calling function
        if (i == 1)
            NetworkQueueAddBest(ctx, iptr, optr);
    }
    end:;

    // we can free the temporary instruction structure we used to have the packet built
    PacketBuildInstructionsFree(&iptr);
}



// transmits a queued ICMP packet
// !!! finish by copying over the icmp4/6 structure
void NetworkAPI_TransmitICMP(AS_context *ctx, ConnectionContext *cptr, IOBuf *ioptr, OutgoingPacketQueue *optr) {
    int i = 0, ret = 0;
    PacketBuildInstructions *iptr = NULL;
   
    // create instruction packet for the ICMP(4/6) packet building functions
    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
        iptr->type = PACKET_TYPE_ICMP_4|PACKET_TYPE_ICMP;

        iptr->ttl = cptr->socket->ttl;
        iptr->destination_ip = ioptr->addr.sin_addr.s_addr;
        iptr->source_ip = ctx->my_addr_ipv4;
        iptr->header_identifier = cptr->identifier++;

        if ((iptr->data = (char *)calloc(1, ioptr->size)) != NULL) {
            memcpy(iptr->data, ioptr->buf, ioptr->size);    
            iptr->data_size = ioptr->size;
        }

        // build final packet for wire..
        if (iptr->type & PACKET_TYPE_ICMP_6)
            i = BuildSingleICMP6Packet(iptr);
        else if (iptr->type & PACKET_TYPE_ICMP_4)
            i = BuildSingleICMP4Packet(iptr);

        // prepare it into final structure for wire for calling function
        if (i == 1)
            NetworkQueueAddBest(ctx, iptr, optr);
    }

    // we can free the temporary instruction structure we used to have the packet built
    PacketBuildInstructionsFree(&iptr);
}


// transmits a TCP packet from a IO queue
void NetworkAPI_TransmitTCP(AS_context *ctx, ConnectionContext *cptr, IOBuf *ioptr, OutgoingPacketQueue *optr) {
    int i = 0, ret = 0;
    PacketBuildInstructions *iptr = NULL;

    // create instruction packet for the ICMP(4/6) packet building functions
    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
        iptr->type = PACKET_TYPE_TCP_4|PACKET_TYPE_TCP;

        // !!! maybe disable PSH or fully support with fragmented outgoing packets (by sending only on the last,
        // and pushing all packets out quickly)
        iptr->flags = TCP_FLAG_PSH|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;

        iptr->ttl = cptr->socket->ttl;
        iptr->tcp_window_size = cptr->socket->window_size;
        iptr->header_identifier = cptr->identifier++;

        iptr->source_ip = ctx->my_addr_ipv4;
        iptr->source_port = cptr->port;

        iptr->destination_ip = cptr->address_ipv4;
        iptr->destination_port = cptr->remote_port;//);//ntohs(ioptr->addr.sin_port);

        // TCP/IP ack/seq is required
        iptr->seq = cptr->seq;
        iptr->ack = cptr->remote_seq;

        //log seq to ioptr structure for verification (in case we have  to retransmit)
        ioptr->seq = cptr->seq + ioptr->size;

        if ((iptr->data = (char *)calloc(1, ioptr->size)) != NULL) {
            memcpy(iptr->data, ioptr->buf, ioptr->size);
            iptr->data_size = ioptr->size;
        }

        // build final packet for wire..
        if (iptr->type & PACKET_TYPE_TCP_6)
            i = BuildSingleTCP6Packet(iptr);
        else if (iptr->type & PACKET_TYPE_TCP_4)
            i = BuildSingleTCP4Packet(iptr);

        // prepare it into final structure for wire for calling function
        if (i == 1)
            NetworkQueueAddBest(ctx, iptr, optr);
    }

    // we can free the temporary instruction structure we used to have the packet built
    PacketBuildInstructionsFree(&iptr);
}





void NetworkAPI_TransmitPacket(AS_context *ctx, ConnectionContext *cptr, IOBuf *ioptr, OutgoingPacketQueue *optr) {
    if (cptr->socket->state & SOCKET_TCP) {
        NetworkAPI_TransmitTCP(ctx, cptr, ioptr, optr);

    } else if (cptr->socket->state & SOCKET_UDP) {
        NetworkAPI_TransmitUDP(ctx, cptr, ioptr, optr);

        // UDP auto verified.. apps take care of that...
        ioptr->verified = 1;
    } else if (cptr->socket->state & SOCKET_ICMP) {
        NetworkAPI_TransmitICMP(ctx, cptr, ioptr, optr);

        // ICMP is also auto verified...
        ioptr->verified = 1;
    }
}




// regular loop for performing duties with our network stack
// timeouts, packet retransmitting (if we didnt receieve an ACK), etc....
// this mainly deals with outgoing buffers, and packet retries...
// incoming buffers are pushed in by another function.. and just have to wait for the application to read
int NetworkAPI_Perform(AS_context *ctx) {
    int i = 0;
    SocketContext *sptr = NULL;
    ConnectionContext *cptr = NULL;
    IOBuf *ioptr = NULL;
    OutgoingPacketQueue *optr = NULL;
    PacketBuildInstructions *iptr = NULL;
    int ts = time(0);

    // loop for all sockets in the list to perform actions
    sptr = ctx->socket_list;
    while (sptr != NULL) {
        // we want to loop for all connections under each socket (one listen socket will have many connections)
        cptr = sptr->connections;
        while (cptr != NULL) {
            
            // lock the connection structure so no other threads affect it while we modify it
            // the IO buffers can change from the network outgoing/ingoing threads
            if (pthread_mutex_lock(&cptr->mutex) == 0) {
                //printf("locked cptr %p\n", cptr);
                // outgoing instructions go first.. always the most important
                if (cptr->out_instructions != NULL) {
                    // pop first instruction
                    iptr = cptr->out_instructions;
                    // fix list to the next
                    cptr->out_instructions = iptr->next;
                    // unchain this one
                    iptr->next = NULL;
                    // add into outgoing queue
                    i = NetworkQueueAddBest(ctx, iptr, &optr);
                } else {
                    //loop to see if we are prepared to distribute another packet (either first time, timeout, or next)
                    ioptr = cptr->out_buf;
                    while (ioptr != NULL) {
                        // either packet hasn't been transmitted.... or we will retransmit
                        if (!ioptr->verified && (!ioptr->transmit_ts || ((ts - ioptr->transmit_ts) > 3))) {
                            if (ioptr->retry++ < 5) {
                                ioptr->transmit_ts = time(0);

                                // call correct packet building for this outgoing buffer
                                NetworkAPI_TransmitPacket(ctx, cptr, ioptr, &optr);
                            } else {

                                // set completed to 1 becauase we want the appllication to have the ability to get the entire incoming packet queue
                                cptr->completed = 1;
                                
                                // send back RST packet...
                                NetworkAPI_GeneratePacket(ctx, sptr, cptr, TCP_FLAG_RST|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP);
                            }
                            break;
                        }
                        ioptr = ioptr->next;
                    }
                }
                pthread_mutex_unlock(&cptr->mutex);
            }
            cptr = cptr->next;
        }
        // check if any connections are timmed out (5min)
        sptr = sptr->next;
    }

    // if we have some outgoing packets from somewhere...
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

    // socket cleanup for completed sockets
    NetworkAPI_Cleanup(ctx);
}


// all packets reacch this function so that we can determine if any are for our network stack
int NetworkAPI_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = 0;
    SocketContext *sptr = NULL;
    IOBuf *bptr = NULL;

    // lets see if we have any connections which want this packet
    sptr = ctx->socket_list;
    while (sptr != NULL) {
        if (!sptr->completed) {
            // if filter is enabled.. verify it... sockets can prepare this to help with the rest of the system..
            // whenever listen() hits, or connect() can prepare that structure to only get packets designated for it
            if (FilterCheck(ctx, &sptr->flt, iptr)) {
                // be sure both are same types (ipv4/6, and TCP/UDP/ICMP)
                if (((sptr->state & PACKET_TYPE_IPV4) && (iptr->type & PACKET_TYPE_IPV4)) ||
                            ((sptr->state & PACKET_TYPE_IPV6) && (iptr->type & PACKET_TYPE_IPV6))) {
                            // if its TCP then call the tcp processor
                            if ((sptr->state & SOCKET_TCP) && (iptr->type & PACKET_TYPE_TCP))
                                ret = NetworkAPI_SocketIncomingTCP(ctx, sptr, iptr);
                            // or call UDP processor
                            else if ((sptr->state & SOCKET_UDP) && (iptr->type & PACKET_TYPE_UDP))
                                ret = NetworkAPI_SocketIncomingUDP(ctx, sptr, iptr);
                            // or call ICMP processor
                            else if ((sptr->state & SOCKET_ICMP) && (iptr->type & PACKET_TYPE_ICMP))
                                ret = NetworkAPI_SocketIncomingICMP(ctx, sptr, iptr);
                    }
                    // if it was processed and returned 1, then no need to test all other sockets.
                    if (ret) break;
            }
        }
        sptr = sptr->next;
    }

    return ret;
}

// find an IO buffer by its sequence number (for proper PSH support)
IOBuf *NetworkAPI_FindIOBySeq(IOBuf *list, uint32_t seq) {
    IOBuf *ioptr = list;

    // find packet by seq in buffer (no need to append twice).. also can be used by incoming to validate outgoing packet seq for transmission of next packet
    while (ioptr != NULL) {
        if (ioptr->seq == seq) break;

        ioptr = ioptr->next;
    }

    return ioptr;
}


// generate a new packet preparing it with a base set of parameters.. it automatically gets appended to the  outgoing list so
// you will have to affect flags, etc after it returns but before it goes out (so fix it up before you unlock the connection mutex)
PacketBuildInstructions *NetworkAPI_GeneratePacket(AS_context *ctx, SocketContext *sptr, ConnectionContext *cptr, int flags) {
    PacketBuildInstructions *bptr = NULL;

    // generate ACK packet to finalize TCP/IP connection opening
    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {

        bptr->type = PACKET_TYPE_TCP_4 | PACKET_TYPE_IPV4 | PACKET_TYPE_TCP;
        bptr->flags = flags;

        bptr->tcp_window_size = sptr->window_size;
        bptr->ttl = sptr->ttl ? sptr->ttl : 64;
        bptr->source_ip = get_local_ipv4();
        bptr->destination_ip = cptr->address_ipv4;
        bptr->source_port = cptr->port;
        bptr->destination_port = cptr->remote_port;
        bptr->header_identifier = cptr->identifier++;

        cptr->socket_fd = cptr->socket_fd;
        bptr->ack = cptr->remote_seq;
        bptr->seq = cptr->seq;

        //printf("ACK %X SEQ %X\n", htons(bptr->ack), htons(bptr->seq));

        L_link_ordered((LINK **)&cptr->out_instructions, (LINK *)bptr);
    }

    return bptr;
}

// find a connection by its remote port (to easily find a connection for an incoming packet from a remote host)
ConnectionContext *NetworkAPI_ConnFindByRemotePort(AS_context *ctx, SocketContext *sptr, int port) {
    ConnectionContext *cptr = NULL;

    cptr = sptr->connections;
    while (cptr != NULL) {
        if (!cptr->completed && (cptr->remote_port == port)) break;

        cptr = cptr->next;
    }

    return cptr;
}


// a packet arrives here if its protocol, and type matches.. this function should determine the rest..
int NetworkAPI_SocketIncomingTCP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr) {
    int ret = 0;
    int new_fd = 0;
    IOBuf *ioptr = NULL;
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    ConnectionContext *cptr = NULL;
    uint32_t rseq = 0;

/*
    printf("Incoming TCP packet data_size %d\n", iptr->data_size);
    if (iptr->flags & TCP_FLAG_FIN) printf("fin\n");
    if (iptr->flags & TCP_FLAG_ACK) printf("ack\n");
    if (iptr->flags & TCP_FLAG_RST) printf("rst\n");
    if (iptr->flags & TCP_FLAG_PSH) printf("psh\n");
*/
    // be sure both are same IP protocol ipv4 vs ipv6
    if (sptr->address_ipv4 && !iptr->source_ip) goto end;

    // verify ports equal to easily disqualify.. go straight to end if not (dont set to 1 since it may relate  to another socket)
    if (sptr->port && (iptr->destination_port != sptr->port)) goto end;

    // lets check if this is for a listening socket
    if (sptr->state & SOCKET_TCP_LISTEN) {
        // SYN = new  connection.. see if we are listening
        if (iptr->flags & TCP_FLAG_SYN) {
            // allocate new file descriptor
            if ((new_fd = NetworkAPI_NewFD(ctx)) == -1) goto end;

            // create new connection structure
            if (!cptr && (cptr = NetworkAPI_ConnectionNew(sptr)) == NULL) goto end;

            // generate packet sending back ACK+SYN
            if ((bptr = NetworkAPI_GeneratePacket(ctx, sptr, cptr, TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP)) == NULL) goto end;
            
            // all properties which are different from NetworkAPI_GenerateResponse() standard
            cptr->socket_fd = new_fd;
            bptr->seq = cptr->seq++;
            cptr->state |= SOCKET_TCP_ACCEPT;
            cptr->last_ts = time(0);

            // no neeed to allow anythiing else to process this packet
            ret = 1;

            goto end;
        }
    }


    // anything else we expect it to be related to a connection structure
    // if we dont have a connection structure yet then we are done.. listening sockets were already verified
    if ((cptr = NetworkAPI_ConnFindByRemotePort(ctx, sptr, iptr->source_port)) == NULL) goto end;

    // lock mutex
    pthread_mutex_lock(&cptr->mutex);

    // mark timestamp for timeout purposes
    cptr->last_ts = time(0);

    // if this packet is an ACK.. we can check first to see if its some packet we sent which needs to be validated to move to the next packet
    if (iptr->flags & TCP_FLAG_ACK) {
        // is it a new outgoing connection?
        if (cptr->state & SOCKET_TCP_CONNECTING) {
            // log remote sides sequence.. and increase ours by 1
            cptr->remote_seq = iptr->seq;

            // remove connecting state
            cptr->state &= ~SOCKET_TCP_CONNECTING;
            // mark as connected now
            cptr->state |= SOCKET_TCP_CONNECTED;

            // send back ACK for this incoming ACK
            if ((bptr = NetworkAPI_GeneratePacket(ctx, sptr, cptr, TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP)) == NULL) goto end;
            //printf("connecting?? fd %d\n", cptr->socket_fd);
            // this packet for connecting requires +1 for remote seq as ack
            bptr->ack = ++cptr->remote_seq;

            // nobody else needs to process this..
            ret = 1;
            goto end;
        }

        // is it a connection being closed? (we sent FIN)
        // anything after we sent ACK+FIN from ACK... would be the last ACK coming in
        // be sure its not a retransmission
        if (cptr->state & SOCKET_TCP_CLOSING && !iptr->data_size) {
            // connection completed... itll get closed during cleanup
            //printf("got closing connection\n");
            cptr->completed = 1;
            if ((bptr = NetworkAPI_GeneratePacket(ctx, sptr, cptr, TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP)) == NULL) {
                //printf("couldnt generate packet\n");
                goto end;
            }
            bptr->ack = ++iptr->seq;
            bptr->seq = cptr->seq;  
            goto end;
        }

        // we need to determine if we were waiting for this ACK to push more data, or otherwise (open connection)
        // ack for a connection could be a connecting finished being established, or a packet data being delivered
        // !!! maybe check by state...we are locked anyways shrug, this kinda kills 2 birds 1 stone (instead of 2 logic checks)
        // if there is an outgoing buffer.. its probably for an established connection
        if (cptr->out_buf != NULL) {
            // does this ACK match the most recently transmitted packet? if so.. its verified
            //printf("verify %p %p\n", iptr->ack, cptr->out_buf->seq);
            if (iptr->ack == cptr->out_buf->seq) {
                // verify the packet as being delivered so we transmit the next packet.
                // disabled so we can remove it all here
                cptr->out_buf->verified = 1;

                // increase our seq by the validated size (it has to be done on verification, and not every transmission)
                // 50-60% of connections were dying the other way because of retransmissions
                cptr->seq += cptr->out_buf->size;

                // free the buffer of this packet since its validated then we wont be using it for retransmission
                free(cptr->out_buf->buf);

                // use as temporary value so we can free the current packet information
                ioptr = cptr->out_buf->next;

                // free the actual packet we were awaiting validation for
                free(cptr->out_buf);

                // if we had some packet instructions attached to this.. lets ensure they are free
                PacketBuildInstructionsFree(&cptr->out_buf->iptr);

                // move pointer in outgoing buffer to the next in our outgoing list of packets
                cptr->out_buf = ioptr;

                // log remote SEQ for next packet transmission
                cptr->remote_seq = iptr->seq;

                goto end;
            }
        }
    }



    // is this attempting to close the connection using a reset packet?
    if ((iptr->flags & TCP_FLAG_RST) || (iptr->flags & TCP_FLAG_FIN)) {
        //printf("handling FIN or RST\n");
        // connection is completed.. keep buffers for our program reading until here
        cptr->completed = 1;
        // no other socket should process this as well
        ret = 1;

        // produce an ACK|RST packet for it
        if ((bptr = NetworkAPI_GeneratePacket(ctx, sptr, cptr, TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP)) == NULL) goto end;

        // since we are handling both situations.. pick the proper flag required for this one
        if (iptr->flags & TCP_FLAG_RST) bptr->flags |= TCP_FLAG_RST;
        if (iptr->flags & TCP_FLAG_FIN) bptr->flags |= TCP_FLAG_FIN;

        // lets be sure we update our remote seq, and use it as the acknowledge number
        bptr->ack = cptr->remote_seq = iptr->seq;
        
        goto end;
    }



    if (iptr->data_size)
        // check if we already have this packet... if so we dont want to put into queue AGAIN
        ioptr = NetworkAPI_FindIOBySeq(cptr->in_buf, iptr->seq);

    // if we have data, and we didnt find it in our buffer already.. then its new data (tcp options SACK support)
    if (iptr->data_size && (ioptr == NULL) && (iptr->seq >= cptr->remote_seq)) {
        // !!! we wanna verify ACK/SEQ here BEFORE allowing the data later.. for proper TCP/IP security

        // put data into incoming buffer for processing by calling app/functions
        if ((ioptr = (IOBuf *)calloc(1,sizeof(IOBuf))) == NULL) {
            // not enough memory to process connection data.. its done. its established so we cannot deal w that
            // !!! later we can allow tcp resuming, or whatever..
            sptr->completed = 2;

            // we dont want any other sockets processing
            ret = 1;

            goto end;
        }

        // append size to remote seq for ACK packet
        rseq = (iptr->seq + iptr->data_size);
        // be sure we update our context w this !!! handle what happens when uint32_t overflows
        if (rseq > cptr->remote_seq) cptr->remote_seq = rseq;

        // move the data itself over from whenever it was processed into an instruction structure
        ioptr->size = iptr->data_size;
        ioptr->buf = iptr->data;

        // remove the data information pointer from the original instruction pointer
        iptr->data = NULL;
        iptr->data_size = 0;

        // !!! can remove later.. for debugging etc
        ioptr->iptr = InstructionsDuplicate(iptr);

        // we need this for the fallthrough...
        iptr->data_size = ioptr->size;

        // thats all...append to this connections buffer
        L_link_ordered((LINK **)&cptr->in_buf, (LINK *)ioptr);

        // fall through so it can send the ACK below
    }

    // if we have a data size, then we ALWAYS should send an ACK back.. regardless of whether it was retransmitted or not
    if (iptr->data_size) {
        // send ACK back for this data...
        // generate ACK packet to finalize TCP/IP connection opening
        if ((bptr = NetworkAPI_GeneratePacket(ctx, sptr, cptr, TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP)) == NULL) goto end;

        // calculate always since our connection structure may be in the 'future' compared to this retransmitted packet
        bptr->ack = (iptr->seq + iptr->data_size);

        // if its a FIN packet.. lets send back FIN with this ACK, and  mark as closing (so we cut it after the  next packet which will be ACK)
        if (iptr->flags & TCP_FLAG_FIN && 1==2) {
            printf("FIN\n");
            // we needed to increase the ACK by one.. no need to update our structure since its the FIN packet.. the +1 is due to its FIN ontop of data
            // *** maybe update correctly for proper-ness but it doesnt matter
            bptr->ack++;
            // add FIN to the packet that is about to go out
            // !!! this FIN is always going out.. sommetimes i see PSH|FIN|ACK and it waits for retransmission???
            bptr->flags |= TCP_FLAG_FIN;

            // mark  socket for reference next incoming (ACK)
            cptr->state |= SOCKET_TCP_CLOSING;
        }

        // packet built lets return
        ret = 1;
        goto end;
    }
    
    // we dont want to allow anyone else to process this packet (save CPU cycles)
    ret = 1;

    end:;
    if (bptr) {
        //if (iptr->flags & TCP_FLAG_PSH) bptr->flags |= TCP_FLAG_PSH;
    }
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ret;
}



// process incoming udp packet, and prepare it for calling application to retrieve the data
int NetworkAPI_SocketIncomingUDP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr) {
    int ret = 0;
    IOBuf *ioptr = NULL;

    // be sure both are same IP protocol ipv4 vs ipv6
    if (sptr->address_ipv4 && !iptr->source_ip) goto end;

    // be sure this UDP socket is bound to that port...
    if (!(sptr->state & SOCKET_UDP_BOUND)) goto end;

    // verify ports equal to easily disqualify
    if ((iptr->destination_port != sptr->port) && (iptr->source_port != sptr->port)) goto end;

    // if ports match.. then we dont want anyone else getting the same packet (since only 1 can bind to a port at a time)
    ret = 1;

    // put into buffer for processing by calling app/functions
    if ((ioptr = (IOBuf *)calloc(1,sizeof(IOBuf))) == NULL) goto end;

    // we use the same data pointer...
    ioptr->size = iptr->data_size;
    ioptr->buf = iptr->data;
    // be sure to remove the link so it doesnt get freed
    iptr->data = NULL;
    iptr->data_size = 0;

    ioptr->iptr = InstructionsDuplicate(iptr);

    // thats all...
    L_link_ordered((LINK **)&sptr->in_buf, (LINK *)ioptr);

    end:;
    return ret;
}


// process incoming ICMP by appending it to the incoming buffer queue
int NetworkAPI_SocketIncomingICMP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr) {
    int ret =  0;
    IOBuf *ioptr = NULL;

    // put into buffer for processing by calling app/functions
    if ((ioptr = (IOBuf *)calloc(1,sizeof(IOBuf))) == NULL) goto end;

    // we use the same data pointer...
    ioptr->size = iptr->data_size;
    ioptr->buf = iptr->data;
    // be sure to remove the link so it doesnt get freed
    iptr->data = NULL;
    iptr->data_size = 0;

    ioptr->iptr = InstructionsDuplicate(iptr);

    // thats all...
    L_link_ordered((LINK **)&sptr->in_buf, (LINK *)ioptr);

    // we can have  multiple ICMP monitoring.. always ret = 0 *for now* !!!
    //ret = 1;

    end:;
    return ret;
}

// count the amount of unverified outgoing packets for this specific connection
// this is required to have blocking send/write
int NetworkAPI_Count_Outgoing_Queue(IOBuf *ioptr) {
    int count = 0;

    while (ioptr != NULL) {
        if (ioptr->verified == 0) count++;
        ioptr = ioptr->next;
    }

    return count;
}

// buffers data into the connections outgoing buffer split up by the window size (fragmented)
IOBuf *NetworkAPI_BufferOutgoing(int sockfd, char *buf, int len) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NULL;
    IOBuf *ioptr = NULL;
    int size = 0;
    char *sptr = buf;
    int count = 0;

    // if we cannot find the connection by its file descriptor.. then we are done (return NULL since ioptr starts as NULL)
    if ((cptr = NetworkAPI_ConnectionByFD(ctx, sockfd)) == NULL) {
        printf("couldnt get connection structure [fd %d]\n", sockfd);
        goto end;
    }

    // if there are too many unvalidated outgoing buffered packets in queue and this connection is blocking..
    // lets wait for at least 1 more to validate before we continue
    // some apps may break, or transmit too much data if this doesnt take plaace
    if (!cptr->noblock) {
        if ((count = NetworkAPI_Count_Outgoing_Queue(cptr->out_buf)) > 0) {
            while (1) {
                pthread_mutex_unlock(&cptr->mutex);
                usleep(50000);
                pthread_mutex_lock(&cptr->mutex);

                // if count of validated (sent successful) changed.. then we are ready to move on
                if (count != NetworkAPI_Count_Outgoing_Queue(cptr->out_buf))
                    break;
            }
        }
    }

    cptr->last_ts = time(0);

    // loop adding all data at max to the tcp window...
    while (len > 0) {
        size = min(cptr->socket->window_size, len);

        if ((ioptr = (IOBuf *)calloc(1, sizeof(IOBuf))) == NULL) {
            printf("cannot allocate for buffer\n");
            goto end;
        }

        if (!PtrDuplicate(sptr, size, &ioptr->buf, &ioptr->size)) {
            PtrFree(&ioptr);
            printf("cannot duplicate data\n");
            goto end;
        }

        sptr += size;

        // append this fragmented packet portion of our data to the outgoing buffer for this connection in order of creation
        L_link_ordered((LINK **)&cptr->out_buf, (LINK *)ioptr);

        len -= size;
    }

end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ioptr;
}





// pops the first (longest lasting) iobuf.. FIFO
IOBuf *NetworkAPI_BufferGetIncoming(int sockfd) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NULL;
    IOBuf *ioptr = NULL;

    if ((cptr = NetworkAPI_ConnectionByFD(ctx, sockfd)) == NULL) goto end;
    
    cptr->last_ts = time(0);

    // FIFO... pop from start of the oredered list
    if (cptr->in_buf) {
        ioptr = cptr->in_buf;
        cptr->in_buf = ioptr->next;
    }

end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ioptr;
}


// takes multiple IOBufs and puts them together into a single one
IOBuf *NetworkAPI_ConsolidateIncoming(int sockfd) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NULL;
    IOBuf *ioptr = NULL, *ionext = NULL;
    IOBuf *ret = NULL;
    int size = 0;
    char *sptr = NULL, *iptr = NULL;

    // did we get a connection from this socket?
    if ((cptr = NetworkAPI_ConnectionByFD(ctx, sockfd)) == NULL) return NULL;

    // first get the full size
    ioptr = cptr->in_buf;
    while (ioptr != NULL) {
        size += (ioptr->size - ioptr->ptr);

        ioptr = ioptr->next;
    }

    // if nothing there.. we are done
    if (!size) goto end;

    // now build a single buffer to handle everything
    if ((ret = (IOBuf *)calloc(1, sizeof(IOBuf))) == NULL) goto end;

    if ((ret->buf = malloc(size)) == NULL) {
        PtrFree(&ret);
        goto end;
    }

    ret->size = size;
    sptr = ret->buf;

    // copy all data into the  new one now..
    ioptr = cptr->in_buf;
    while (ioptr != NULL) {
        // if this specific IO buf has data still (otherwise its here for ensure we dont repeat data
        // which is sent again due to ACK being slow)
        if (ioptr->buf) {
            iptr = ioptr->buf + ioptr->ptr;
            memcpy(sptr, iptr, ioptr->size - ioptr->ptr);

            sptr += (ioptr->size - ioptr->ptr);
            ioptr->ptr += (ioptr->size - ioptr->ptr);
        }
        ionext = ioptr->next;

        if (ioptr->buf) {
            // we wont reuse the data.. mainly just the sequence identifiers
            PtrFree(&ioptr->buf);
            ioptr->ptr = 0;
            ioptr->size = 0;
        }
        ioptr = ionext;
    }
    
    // put the older structures behind the consolidated (so that we dont keep accepting the same data by not finding their SEQs)
    ret->next = cptr->in_buf;
    // we consolidated all of the buffers
    cptr->in_buf = ret;

end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ret;
}


// reads data fromm a socket
int NetworkAPI_ReadSocket(int sockfd, char *buf, int len) {
    int ret = 0;
    AS_context *ctx = NetworkAPI_CTX;
    // consolidate first...
    IOBuf *ioptr = NULL;
    // this  has to be AFTER consolidate since both use mutex
    ConnectionContext *cptr = NULL;
    char *sptr = NULL;

    // get data consolidated.. if NULL then we are done
    if ((ioptr = NetworkAPI_ConsolidateIncoming(sockfd)) == NULL) goto end;

    // find the connection... if none then something is wrong we are  done
    if ((cptr = NetworkAPI_ConnectionByFD(ctx, sockfd)) == NULL) goto end;

    cptr->last_ts = time(0);

    // now lets read as much as possible...
    if (len > ioptr->size) len = ioptr->size;

    sptr = ioptr->buf + ioptr->ptr;
    memcpy(buf, sptr, len);

    ioptr->ptr += len;
    ret = len;

    if ((ioptr->size - ioptr->ptr) == 0) {
            PtrFree(&ioptr->buf);
            ioptr->ptr = 0;
            ioptr->size = 0;
    }

end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ret;
}


ssize_t NetworkAPI_RecvBlocking(int sockfd, void *buf, size_t len) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NULL;
    ssize_t ret = 0;
    
    // first we attempt to read without locking the connection structure.. and we return if that was OK
    if ((ret = NetworkAPI_ReadSocket(sockfd, buf, len)) > 0) goto end;

    // get the connection structure..
    if ((cptr = NetworkAPI_ConnectionByFD(ctx, sockfd)) == NULL) {
        // if there is no connection then theres an error
        ret = -1;
        goto end;
    }

    // if no data left, and completed...
    if (cptr->completed) {
        ret = -1;
        goto end;
    }

    // if this is a blocking connection.. then we want to loop until we receieve some data
    if (!cptr->noblock) {
        // unlock the connection mutex so that other threads can affect it
        pthread_mutex_unlock(&cptr->mutex);

        // set connection pointer to NULL so we dont unlock it again at the end of the function
        cptr = NULL;
        while(1) {
            // we dont want this to be too low since other threads are going to lock/unlock the connection structure
            usleep(50000);

            // read the data into the buffer supplied by the calling function.. and return if it is successful
            ret = NetworkAPI_ReadSocket(sockfd, buf, len);

            // if ret is -1, or more than zero then we return
            if ((ret == -1) || (ret > 0)) goto end;
            
            // if not successful we just continue waiting for a change
        }
    }

    end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ret;
}


int NetworkAPI_ConnectSocket(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NULL;
    PacketBuildInstructions *bptr = NULL;
    SocketContext *sptr = NULL;
    int start = 0, state = 0, r = 0, ret = 0;

    // if we dont have a socket for that file descriptor then there must be an error
    if ((sptr = NetworkAPI_SocketByFD(ctx, sockfd)) == NULL) return -1;

    // if the connection structure doesnt exist, then try to allocate one.. it could be a new connection out
    if ((cptr = NetworkAPI_ConnectionByFD(ctx, sockfd)) == NULL)
        if ((cptr = NetworkAPI_ConnectionNew(sptr)) == NULL)
            return -1;

    // !!!  ipv6
    if ((addrlen == sizeof(struct sockaddr)) && (addr->sin_family == AF_INET)) {
        cptr->address_ipv4 = addr->sin_addr.s_addr;
        cptr->remote_port = ntohs(addr->sin_port);
    }

    // we always want to know when this connection socket began
    cptr->ts = time(0);
    // and the last activity (same as initial for now)
    cptr->last_ts = cptr->ts;
    // pick random source port for this new connection
    cptr->port = 1024+(rand()%(65536-1024));
    // make sure the original socket context has this port we just chose
    sptr->port = cptr->port;
    // pick random identifier for the header of this connections packets
    cptr->identifier = rand()%0xFFFFFFFF;
    // pick a random uint32 value to start the sequence for the TCP/IP security portion
    cptr->seq = rand()%0xFFFFFFFF;
    // ensure this connection has easy access to its socket structure
    cptr->socket = sptr;

    // generate SYN packet
    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) {
        pthread_mutex_unlock(&cptr->mutex);
        return NULL;
    }

    // set socket for future uses (packet gen, etc)
    cptr->socket_fd = sockfd;
    // set state so we know its actively connecting
    cptr->state |= SOCKET_TCP_CONNECTING;

    // we wanna send an initial SYN packet to open this connection
    if ((bptr = NetworkAPI_GeneratePacket(ctx, sptr, cptr, TCP_FLAG_SYN|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW)) == NULL) goto end;
    bptr->ack = 0;
    bptr->seq = cptr->seq++;

    // it was locked in NAPI_ConnectionNew() or NAPI_ConnectionFind*
    pthread_mutex_unlock(&cptr->mutex);

    // if we ARE blocking.. give 30 seconds, and monitor for state changes (linux timeout is somemthing like 22-25 seconds?)
    if (!sptr->noblock) {
        start = time(0);
        state = cptr->state;
        while (((start - time(0)) < 30) && !r) {
            // we dont want this to happen too fast because other threads are locking/changing client structures
            usleep(50000);

            pthread_mutex_lock(&cptr->mutex);
            // check to see if the state has changed since we began
            if (cptr->state != state) {
                r = 1;
                break;
            }
            pthread_mutex_unlock(&cptr->mutex);
        }

        // did it connect? we need a return value for the calling function...
        ret = (cptr->state & SOCKET_TCP_CONNECTED) ? 0 : ECONNREFUSED;

        pthread_mutex_unlock(&cptr->mutex);

        goto end;
    } else
        // for non blocking.. we let the caller know its in progress
        ret = EINPROGRESS;

end:;
    return ret;
}


// -------------- all networkAPI (our functions) above here..





// -------------- all emulated API (libc/etc) for directly replacing applications to use our stack below here




// accept a connection which is connecting to a listening socket
int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int ret = -1;
    AS_context *ctx = NetworkAPI_CTX;
    SocketContext *sptr = NULL;
    SocketContext *pptr = NULL;
    ConnectionContext *cptr = NULL;
    struct sockaddr_in conninfo;
    struct sockaddr_in6 conninfo6;

    // if we cannot find this socket... then return error
    if ((sptr = NetworkAPI_SocketByFD(ctx, sockfd)) == NULL) goto end;

    // iterate through all connections
    cptr = sptr->connections;

    // if no connections to check against and non blocking then we return
    if (sptr->noblock && !cptr) goto end;

    while (1) {
        // cant have any connections waiting to be accepted if we didnt add it into the list
        while (cptr != NULL) {
            // we need to lock before verifying the state since  it could change from another thread
            pthread_mutex_lock(&cptr->mutex);

            // we have a new connection we can offer for accept()
            if (cptr->state & SOCKET_TCP_ACCEPT)
                break;

            // unlock before we iterate to the next
            pthread_mutex_unlock(&cptr->mutex);
            
            cptr = cptr->next;
        }

        // if its non blocking, then we always return here..or if we found one
        if (cptr || sptr->noblock)
            break;
        
        // we assum ehere that we ended the list.. lets reiterate
        usleep(50000);
        
        // restart connections since its blocking and we must return one
        cptr = sptr->connections;
    }

    // if we have nothing by here.. we return
    if (!cptr) goto end;

    // its no longer waiting... remove TCP accept since it was accepted..
    cptr->state &= ~SOCKET_TCP_ACCEPT;
    // now add TCP_CONNECTED since its just like an outgoing connection
    cptr->state |= SOCKET_TCP_CONNECTED;
 
    // fill up the structurs for the calling structures
    if (addrlen) {
        if (*addrlen == sizeof(struct sockaddr_in)) {
            conninfo.sin_family = AF_INET;
            conninfo.sin_port = htons(sptr->remote_port);
            conninfo.sin_addr.s_addr = cptr->address_ipv4;

            *addrlen = sizeof(struct sockaddr_in);
            memcpy(addr, &conninfo, sizeof(struct sockaddr_in));
        } else if (*addrlen == sizeof(struct sockaddr_in6)) {
            memset(&conninfo6, 0, sizeof(struct sockaddr_in6));

            //conninfo6.sin6_len = sizeof(struct sockaddr_in6);
            conninfo6.sin6_family = AF_INET6;
            conninfo6.sin6_port = htons(sptr->remote_port);

            CopyIPv6Address(&conninfo6.sin6_addr, &cptr->address_ipv6);
        }
    }

    // we want to return the file descriptor of this new connection
    ret = cptr->socket_fd;

    end:;

    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ret;
}


// socket function.. allocates a socket
int my_socket(int domain, int type, int protocol) {
    SocketContext *sptr = NULL;

    // if we were unable to get a file descriptor then we return -1
    if ((sptr = NetworkAPI_SocketNew(NetworkAPI_CTX)) == NULL) return -1;

    // ensure socket has details  of the type we expect it to be
    sptr->domain = domain;
    sptr->type = type;
    sptr->protocol = protocol;

    // prepare correct masks...
    if (domain == AF_INET) {
        sptr->state |= PACKET_TYPE_IPV4;
    } else if (domain == AF_INET6) {
        sptr->state |= PACKET_TYPE_IPV6;
    }

    // prepare our internal socket states depending on the configuration given through [my_]socket()
    if (protocol == IPPROTO_TCP) {
        sptr->state |= PACKET_TYPE_TCP|SOCKET_TCP;

        if (sptr->state & PACKET_TYPE_IPV6) sptr->state |= PACKET_TYPE_TCP_6;
        else if (sptr->state & PACKET_TYPE_IPV4) sptr->state |= PACKET_TYPE_TCP_4;
    } else if (protocol == IPPROTO_UDP) {
        sptr->state |= PACKET_TYPE_UDP|SOCKET_UDP;

        if (sptr->state & PACKET_TYPE_IPV6) sptr->state |= PACKET_TYPE_UDP_6;
        else if (sptr->state & PACKET_TYPE_IPV4) sptr->state |= PACKET_TYPE_UDP_4;

    } else if (protocol == IPPROTO_ICMP) {
        sptr->state |= PACKET_TYPE_ICMP|SOCKET_ICMP;

        if (sptr->state & PACKET_TYPE_IPV6) sptr->state |= PACKET_TYPE_ICMP_6;
        else if (sptr->state & PACKET_TYPE_IPV4) sptr->state |= PACKET_TYPE_ICMP_4;
    }

    return sptr->socket_fd;
}


// bind/listen to a port
int my_listen(int sockfd, int backlog) {
    AS_context *ctx = NetworkAPI_CTX;
    SocketContext *sptr = NULL;
    SocketContext *pptr = NULL;

    // if we cannot find this socket... then return error
    if ((sptr = NetworkAPI_SocketByFD(ctx, sockfd)) == NULL)
        return -1;

    // verify no other socket is listening.. if we find another return an error
    if ((pptr = NetworkAPI_SocketByStatePort(ctx, SOCKET_TCP_LISTEN, sptr->port)) != NULL)
        return -1;

    // enable listening on the socket
    sptr->state |= SOCKET_TCP_LISTEN;

    // prepare filter for it just so we dont have to process packets which arent used by this socket context
    FilterPrepare(&sptr->flt, FILTER_PACKET_TCP|FILTER_SERVER_PORT, sptr->port);

    // no error
    return 0;
}


int my_close(int fd) {
    AS_context *ctx = NetworkAPI_CTX;
    SocketContext *sptr = NULL;

    // if we cannot find this socket... then return error
    if ((sptr = NetworkAPI_SocketByFD(ctx, fd)) == NULL)
        return -1;

    // set state to 0
    sptr->state = 0;
    // set completed to 2 (program isnt going to require any data in the buffer)
    sptr->completed = 2;

    return 0;
}





ssize_t my_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    IOBuf *ioptr = NULL;

    // if we cannot add this information as a buffered IO queue entry.. then we return an error
    if ((ioptr = NetworkAPI_BufferOutgoing(sockfd, (char *)buf, (int)len)) == NULL) {
        return -1;
    }

    // copy over the other properties used in this API
    if (addrlen == sizeof(struct sockaddr))
        memcpy(&ioptr->addr, dest_addr, addrlen);

    return ioptr->size;
}



// call sendto()
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) {
    return my_sendto(sockfd, buf, len, flags, NULL, 0);
}

ssize_t my_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    //IOBuf *ioptr = NetworkAPI_BufferOutgoing(sockfd, (char *)buf, (int)len);
    //if (ioptr == NULL) return -1;
    //return ioptr->size;
    return 0;
}



ssize_t my_recv(int sockfd, void *buf, size_t len, int flags) {
    return NetworkAPI_RecvBlocking(sockfd, buf, len);
}


ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    //NetworkAPI_ReadSocket(sockfd, buf, len);
}



ssize_t my_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NULL;
    IOBuf *ioptr = NULL;
    ssize_t ret = 0;

    // copy the data first.. if not successful then return immediately
    if ((ret = NetworkAPI_RecvBlocking(sockfd, buf, len)) <= 0) return ret;

    // if it was successful, then find the connection structure by its file descriptor
    if ((cptr = NetworkAPI_ConnectionByFD(ctx, sockfd)) == NULL) return -1;
    
    // lock the mutex so nothing else can affect it while we are using it
    pthread_mutex_lock(&cptr->mutex);

    // copy the information about the address from the incoming buffer
    if ((ioptr = cptr->in_buf) != NULL) {   
        // copy over the other properties used in this API
        if (*addrlen == sizeof(struct sockaddr) && src_addr)
            memcpy(src_addr, &ioptr->addr, *addrlen);
    }

    pthread_mutex_unlock(&cptr->mutex);

    return ret;
}




// !!! support ipv4 (sockaddr to sockaddr6), etc
// connect to a remote host via TCP/IP.. initializes by sending packet, and preparing our structures required
int my_connect(int sockfd,  const struct sockaddr_in *addr, socklen_t addrlen) {
    return NetworkAPI_ConnectSocket(sockfd, addr, addrlen);
}