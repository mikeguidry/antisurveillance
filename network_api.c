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

    NetworkAPI_CTX = ctx;

    // lets prepare incoming ICMP processing for our traceroutes
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL)
        goto end;

    // empty filter.. we want everything.
    FilterPrepare(flt, 0, 0);

    // add into network subsystem so we receive all packets
    if (Network_AddHook(ctx, flt, &NetworkAPI_Incoming) != 1)
        goto end;

    ret =  1;

    end:;
    //printf("NetworkAPI Init: %d\n", ret);
    return ret;
}


// find a socket context by its file descriptor (our own virtual fds)
ConnectionContext *NetworkAPI_ConnectionByFD(AS_context *ctx, int fd) {
    SocketContext *sptr = ctx->socket_list;
    ConnectionContext *cptr = NULL;

    while (sptr != NULL) {
        if ((cptr = sptr->connections) != NULL) {

            while (cptr != NULL) {
                if (cptr->socket_fd == fd)
                    break;
            
                cptr = cptr->next;
            }

        }

        sptr = sptr->next;
    }

    // always return a locked mutex.. this is for BLOCKING activites (connect, etc)
    if (cptr) pthread_mutex_lock(&cptr->mutex);

    return cptr;
}


// find a socket context by its file descriptor (our own virtual fds)
SocketContext *NetworkAPI_SocketByFD(AS_context *ctx, int fd) {
    SocketContext *sptr = ctx->socket_list;
    ConnectionContext *cptr = NULL;

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
    return sptr;
}



// find a context by a state AND a port (or just port).. or just state
SocketContext *NetworkAPI_SocketByStatePort(AS_context *ctx, int state, int port) {
    SocketContext *sptr = ctx->socket_list;

    while (sptr != NULL) {

        if (!sptr->completed && (!state || ((sptr->state & state))))
            if (port && sptr->port == port)
                break;

        sptr = sptr->next;

    }

    return sptr;
}


int NetworkAPI_NewFD(AS_context *ctx) {
    SocketContext *sptr = NULL;
    int i = ctx->socket_fd;
    int try = 4096;

    do {
        if (i++ < 1024) i = 4096;

        sptr = NetworkAPI_SocketByFD(ctx, i);

    } while (sptr && try--);

    if (try == 0)
        return -1;

    ctx->socket_fd = ++i;

    return i;
}


SocketContext *NetworkAPI_SocketNew(AS_context *ctx) {
    int i = NetworkAPI_NewFD(ctx);
    SocketContext *sptr = NULL;

    if (i == -1) return NULL;

    // allocate space for a new socket context
    if ((sptr = (SocketContext *)calloc(1, sizeof(SocketContext))) != NULL) {
        sptr->socket_fd = i;
        sptr->ts = time(0);
        sptr->identifier = rand()%0xFFFFFFFF;
        sptr->seq = rand()%0xFFFFFFFF;

        pthread_mutex_init(&sptr->mutex, NULL);
        //pthread_mutex_lock(&sptr->mutex);

        L_link_ordered((LINK **)&ctx->socket_list, (LINK *)sptr);
    }

    return sptr;
}

ConnectionContext *ConnectionNew(SocketContext *sptr) {
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

    // add the connection to the original socket context structure so it can get accepted by the appllication   
    L_link_ordered((LINK **)&sptr->connections, (LINK *)cptr);
    
    pthread_mutex_lock(&cptr->mutex);

    return cptr;
}


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
            if (cptr->state & SOCKET_TCP_ACCEPT) break;

            // unlock before we iterate to the next
            pthread_mutex_unlock(&cptr->mutex);
            
            cptr = cptr->next;
        }

        // if its non blocking, then we always return here..
        if (cptr || sptr->noblock) break;
        
        // we assum ehere that we ended the list.. lets reiterate
        sleep(1);
        
        // restart connections
        cptr = sptr->connections;
    }

    if (!cptr) goto end;

    //pthread_mutex_lock(&cptr->mutex);

    // its no longer waiting...
    cptr->state |= ~SOCKET_TCP_ACCEPT;
    // we will connect this new socket..
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

    ret = cptr->socket_fd;

    end:;

    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ret;
}


// socket function.. allocates a socket
int my_socket(int domain, int type, int protocol) {
    SocketContext *sptr = NetworkAPI_SocketNew(NetworkAPI_CTX);

    if (sptr == NULL) return -1;

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

    sptr->state = 0;
    sptr->completed = 1;

    return 0;
}

// free all packets within an attack structure
void NetworkAPI_FreeBuffers(IOBuf **ioptr) {
    IOBuf *ptr = NULL, *pnext = NULL;

    if (ioptr == NULL) return;

    ptr = *ioptr;

    // verify there are packets there to begin with
    if (ptr == NULL) return;

    // free all packets
    while (ptr != NULL) {
        // once AS_queue() executes on this.. it moves the pointer over
        // so it wont need to be freed from here (itll happen when outgoing buffer flushes)
        PtrFree(&ptr->buf);

        if (ptr->iptr) {
            PacketBuildInstructionsFree(&ptr->iptr);
        }

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

void ConnectionsCleanup(ConnectionContext **connections) {
    ConnectionContext *cptr = NULL, *cnext = NULL, *clast = NULL;
    int ts = time(0);

    cptr = *connections;

    while (cptr != NULL) {
        
        if (pthread_mutex_trylock(&cptr->mutex) == 0) {

        // !!! keep alive?
        //timeout = 5 min.. (we can probably remove this for ourselves.. it could be infinite)
        if ((ts - cptr->last_ts) > 300) {
            cptr->completed = 1;
        }

        if (cptr->completed) {
            printf("cleaning up a connection %p\n", cptr);

            NetworkAPI_FreeBuffers(&cptr->in_buf);
            NetworkAPI_FreeBuffers(&cptr->out_buf);
            PacketBuildInstructionsFree(&cptr->out_instructions);

            cnext = cptr->next;

            if (clast == NULL) {
                *connections = clast = cnext;
            } else {
                clast->next = cnext;
            }

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




int NetworkAPI_Cleanup(AS_context *ctx) {
    SocketContext *sptr = NULL, *snext = NULL, *slast = NULL;
    
    sptr = ctx->socket_list;
    while (sptr != NULL) {

        //pthread_mutex_lock(&sptr->mutex);

        // first cleanup connections.. we need a timeout on these.. (if connecctions are idle for 5 minutes?)
        ConnectionsCleanup(&sptr->connections);

        // we can only cleanup this socket context if all connections are over (they are linked directly)
        if (sptr->completed && !L_count((LINK *)sptr->connections)) {
            printf("cleaning up a socket\n");
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
}

void NetworkAPI_TransmitUDP(AS_context *ctx, ConnectionContext *cptr, IOBuf *ioptr, OutgoingPacketQueue *optr) {
    int i = 0, ret = 0;
    PacketBuildInstructions *iptr = NULL;
   
    // create instruction packet for the ICMP(4/6) packet building functions
    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
        iptr->ttl = cptr->socket->ttl;
    
        iptr->type = PACKET_TYPE_UDP_4|PACKET_TYPE_UDP;
        iptr->destination_ip = ioptr->addr.sin_addr.s_addr;
        iptr->source_ip = ctx->my_addr_ipv4;

        iptr->source_port = cptr->port;
        iptr->destination_port = ntohs(ioptr->addr.sin_port);

        iptr->data_size = ioptr->size;
        iptr->header_identifier = cptr->identifier++;

        if ((iptr->data = (char *)calloc(1, iptr->data_size)) != NULL) {
            memcpy(iptr->data, ioptr->buf, ioptr->size);    
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

    // we can free the temporary instruction structure we used to have the packet built
    PacketBuildInstructionsFree(&iptr);
   
    end:;
}




void NetworkAPI_TransmitICMP(AS_context *ctx, ConnectionContext *cptr, IOBuf *ioptr, OutgoingPacketQueue *optr) {
    int i = 0, ret = 0;
    PacketBuildInstructions *iptr = NULL;
   
    // create instruction packet for the ICMP(4/6) packet building functions
    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
        iptr->ttl = cptr->socket->ttl;
    
        iptr->type = PACKET_TYPE_ICMP_4|PACKET_TYPE_ICMP;
        iptr->destination_ip = ioptr->addr.sin_addr.s_addr;
        iptr->source_ip = ctx->my_addr_ipv4;

        iptr->data_size = ioptr->size;
        iptr->header_identifier = cptr->identifier++;

        if ((iptr->data = (char *)calloc(1, iptr->data_size)) != NULL) {
            memcpy(iptr->data, ioptr->buf, ioptr->size);    
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
   
    end:;
}



void NetworkAPI_TransmitTCP(AS_context *ctx, ConnectionContext *cptr, IOBuf *ioptr, OutgoingPacketQueue *optr) {
    int i = 0, ret = 0;
    PacketBuildInstructions *iptr = NULL;
   
    // create instruction packet for the ICMP(4/6) packet building functions
    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
        iptr->type = PACKET_TYPE_TCP_4|PACKET_TYPE_TCP;
        // !!! maybe disable PSH
        iptr->flags = TCP_FLAG_PSH|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        iptr->ttl = cptr->socket->ttl;
        iptr->tcp_window_size = 1500 - (20*2+12);
        iptr->destination_ip = ioptr->addr.sin_addr.s_addr;
        iptr->source_ip = ctx->my_addr_ipv4;
        iptr->source_port = cptr->port;
        iptr->destination_port = ntohs(ioptr->addr.sin_port);
        iptr->header_identifier = cptr->identifier++;

        iptr->seq = cptr->seq;
        iptr->ack = cptr->remote_seq;

        //log seq to ioptr structure for verification (in case we have  to retransmit)
        ioptr->seq = iptr->seq;

        iptr->data_size = ioptr->size;
        if ((iptr->data = (char *)calloc(1, iptr->data_size)) != NULL) {
            memcpy(iptr->data, ioptr->buf, ioptr->size);    
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
   
    end:;
}





void NetworkAPI_TransmitPacket(AS_context *ctx, ConnectionContext *cptr, IOBuf *ioptr, OutgoingPacketQueue *optr) {
    if (cptr->state & SOCKET_TCP) {

        NetworkAPI_TransmitTCP(ctx, cptr, ioptr, optr);

    } else if (cptr->state & SOCKET_UDP) {

        NetworkAPI_TransmitUDP(ctx, cptr, ioptr, optr);

        // UDP auto verified.. apps take care of that...
        ioptr->verified = 1;

    } else if (cptr->state & SOCKET_ICMP) {

        NetworkAPI_TransmitICMP(ctx, cptr, ioptr, optr);

        // ICMP is also auto verified...
        ioptr->verified = 1;
    }
}

// regular loop for performing duties with our network stack
// timeouts, packet retransmitting (if we didnt receieve an ACK), etc....
// this mainly deals with outgoing buffers, and packet retries...
// incoming buffers are pushed inn by another function.. and just have to wait for the application to read
int NetworkAPI_Perform(AS_context *ctx) {
    SocketContext *sptr = NULL;
    ConnectionContext *cptr = NULL;
    int ts = time(0);
    IOBuf *ioptr = NULL;
    OutgoingPacketQueue *optr = NULL;
    PacketBuildInstructions *iptr = NULL;
    int i = 0;

    printf("network api perform\n");

    sptr = ctx->socket_list;
    while (sptr != NULL) {
        cptr = sptr->connections;
        while (cptr != NULL) {
            if (pthread_mutex_trylock(&cptr->mutex) == 0) {
                // outgoing instructions go first.. always the most important
                if (cptr->out_instructions != NULL) {
                    // pop first instruction
                    iptr = cptr->out_instructions;
                    // fix list to the next
                    cptr->out_instructions = iptr->next;
                    // unchain this one
                    iptr->next = NULL;
                    // add into outgoing queue

                    // !!! move retry to connection instead of single packet
                    i = NetworkQueueAddBest(ctx, iptr, &optr);
                } else {

                    //loop to see if we are prepared to distribute another packet (either first time, timeout, or next)
                    ioptr = cptr->out_buf;
                    while (ioptr != NULL) {
                        printf("found outgoing buf\n");
                        // either packet hasn't been transmitted.... or we will retransmit
                        if (!ioptr->verified && (!ioptr->transmit_ts || ((ts - ioptr->transmit_ts) > 3))) {

                            if (ioptr->retry++ < 5) {
                                ioptr->transmit_ts = time(0);

                                // call correct packet building for this outgoing buffer
                                NetworkAPI_TransmitPacket(ctx, cptr, ioptr, &optr);
                            } else {
                                // bad.. 5*3 = 15.. in 15 seconds of nothing.. itll disconnect the connection
                                // lets just mark connection as closed
                                // !!! send back RST/FIN
                                printf("marking as completed? cptr %p\n", cptr);
                                cptr->completed = 1;
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

        // check if we didnt receieve ack for some data we sent.. we need to resend if so.. verify against outbuf and its seq/ack

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

    printf("\n---------------------\nIncoming packet from raw network stack\n");

    // lets see if we have any connections which want this packet
    sptr = ctx->socket_list;
    while (sptr != NULL) {
        if (!sptr->completed) {
            // if filter is enabled.. verify it... sockets can prepare this to help with the rest of the system..
            // whenever listen() hits, or connect() can prepare that structure to only get packets designated for it
            if (FilterCheck(ctx, &sptr->flt, iptr)) {

                printf("1 socket ipv4 %d packet ipv4 %d\n",(sptr->state & PACKET_TYPE_IPV4) , (iptr->type & PACKET_TYPE_IPV4));
                printf("2 socket ipv6 %d packet ipv6 %d\n",(sptr->state & PACKET_TYPE_IPV6) , (iptr->type & PACKET_TYPE_IPV6));

                // be sure both are same types (ipv4/6, and TCP/UDP/ICMP)
                if (((sptr->state & PACKET_TYPE_IPV4) && (iptr->type & PACKET_TYPE_IPV4)) ||
                            ((sptr->state & PACKET_TYPE_IPV6) && (iptr->type & PACKET_TYPE_IPV6))) {

                            printf("socket tcp %d packet type %d\n", (sptr->state & SOCKET_TCP), (iptr->type & PACKET_TYPE_TCP));

                            // if its TCP then call the tcp processor
                            if ((sptr->state & SOCKET_TCP) && (iptr->type & PACKET_TYPE_TCP))
                                ret = SocketIncomingTCP(ctx, sptr, iptr);
                            // or call UDP processor
                            else if ((sptr->state & SOCKET_UDP) && (iptr->type & PACKET_TYPE_UDP))
                                ret = SocketIncomingUDP(ctx, sptr, iptr);
                            // or call ICMP processor
                            else if ((sptr->state & SOCKET_ICMP) && (iptr->type & PACKET_TYPE_ICMP))
                                ret = SocketIncomingICMP(ctx, sptr, iptr);

                    }

                    // if it was processed and returned 1, then no need to test all other sockets.
                    if (ret) break;
            }
        }

        sptr = sptr->next;
    }

    return ret;
}





PacketBuildInstructions *BuildBasePacket(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr, int flags) {
    PacketBuildInstructions *bptr = NULL;

    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) return NULL;

    bptr->flags = flags;
    bptr->ttl = sptr->ttl ? sptr->ttl : 64;

    // ipv4?
    if (iptr->source_ip) {   
        bptr->type = PACKET_TYPE_TCP_4 | PACKET_TYPE_IPV4 | PACKET_TYPE_TCP;

        bptr->source_ip = iptr->destination_ip;
        bptr->destination_ip = iptr->source_ip;
    } else {
        // or ipv6?
        bptr->type = PACKET_TYPE_TCP_6 | PACKET_TYPE_IPV6 | PACKET_TYPE_TCP;

        CopyIPv6Address(&bptr->source_ipv6, &iptr->destination_ipv6);
        CopyIPv6Address(&bptr->destination_ipv6, &iptr->source_ipv6);
    }

    bptr->source_port = iptr->destination_port;
    bptr->destination_port = iptr->source_port;
    bptr->header_identifier = sptr->identifier++;

    return bptr;
}



/*
notes:
seq gets increased on validation of a packet being delivered from the ACK. this makes it simple for retransmission.. and
the way the platform uses loops for *_Perform() its perfect...

*/


// a packet arrives here if its protocol, and type matches.. this function should determine the rest..
int SocketIncomingTCP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr) {
    int ret = 0;
    int new_fd = 0;
    IOBuf *ioptr = NULL;
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    ConnectionContext *cptr = NULL;

    printf("Incoming TCP packet\n");

    printf("Address %u packet %u\n", sptr->address_ipv4, iptr->source_ip);
    printf("socket port %d packet port %d\n", sptr->port, iptr->destination_port);


    // be sure both are same IP protocol ipv4 vs ipv6
    if (sptr->address_ipv4 && !iptr->source_ip)
        goto end;

    // verify ports equal to easily disqualify
    if (sptr->port && (iptr->destination_port != sptr->port))// && (iptr->source_port != sptr->port))
        goto end;

    // find this connection if it exists in the list
    cptr = sptr->connections;
    while (cptr != NULL) {
        if (!cptr->completed && (cptr->remote_port == iptr->source_port)) break;

        cptr = cptr->next;
    }

    if (cptr)
        pthread_mutex_lock(&cptr->mutex);

    printf("got connection \n");


    // is this an ACK to some packet we sent?
    if (iptr->flags & TCP_FLAG_ACK) {
        // we need to determine if we were waiting for this ACK to push more data, or otherwise (open connection)
        // ack for a connection could be a connecting finished being established, or a packet data being delivered
        if (cptr) {
            // !!! maybe check by state...we are locked anyways shrug, this kinda kills 2 birds 1 stone (instead of 2 logic checks)
            // if there is an outgoing buffer.. its probably for an established connection
            if (cptr->out_buf) {
                if (iptr->ack == cptr->out_buf->seq) {
                    // verify the packet as being delivered so we transmit the next packet.
                    cptr->out_buf->verified = 1;
                    // log remote SEQ for next packet transmission
                    cptr->remote_seq = iptr->seq;

                    // increase seq by size of the verified packet
                    cptr->seq += cptr->out_buf->size;
                }
            } else {
                // probably for an outgoing connection
                if (cptr->state & SOCKET_TCP_CONNECTING) {

                    // log remote sides sequence.. and increase ours by 1
                    cptr->remote_seq = iptr->seq;
                    cptr->seq++;

                    // mark as connected now
                    cptr->state |= ~SOCKET_TCP_CONNECTING;
                    cptr->state |= SOCKET_TCP_CONNECTED;


                    // generate ACK packet to finalize TCP/IP connection opening
                    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) goto end;

                    bptr->type = PACKET_TYPE_TCP_4 | PACKET_TYPE_IPV4 | PACKET_TYPE_TCP;                    
                    bptr->flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;

                    bptr->ttl = sptr->ttl ? sptr->ttl : 64;
                    bptr->source_ip = get_local_ipv4();
                    bptr->destination_ip = cptr->address_ipv4;
                    bptr->source_port = cptr->port;
                    bptr->destination_port = cptr->remote_port;
                    bptr->header_identifier = cptr->identifier++;

                    cptr->socket_fd = cptr->socket_fd;
                    bptr->ack = cptr->remote_seq;
                    bptr->seq = cptr->seq;

                    L_link_ordered((LINK **)&cptr->out_instructions, (LINK *)bptr);

                }
            }
        }

    }

    // SYN = new  connection.. see if we are listening
    if (iptr->flags & TCP_FLAG_SYN) {
        // ensure the state is listening
        if (sptr->state & SOCKET_TCP_LISTEN) {

            if ((new_fd = NetworkAPI_NewFD(ctx)) == -1) goto end;

            if (!cptr && (cptr = ConnectionNew(sptr)) == NULL) goto end;

            if ((bptr = (PacketBuildInstructions *)BuildBasePacket(ctx, sptr, iptr, TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW)) == NULL)
                goto end;

            bptr->ttl = sptr->ttl ? sptr->ttl : 64;
            bptr->flags = TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
            bptr->type = PACKET_TYPE_TCP_4 | PACKET_TYPE_IPV4 | PACKET_TYPE_TCP;
            bptr->ack = iptr->seq;
            bptr->seq = cptr->seq++;
            bptr->header_identifier = cptr->identifier++;
            bptr->source_ip = get_local_ipv4();
            bptr->destination_ip = cptr->address_ipv4;
            bptr->source_port = cptr->port;
            bptr->destination_port = cptr->remote_port;

            cptr->socket_fd = new_fd;
            cptr->state |= SOCKET_TCP_ACCEPT;
            cptr->last_ts = time(0);

            L_link_ordered((LINK **)&cptr->out_instructions, (LINK *)bptr);

            ret = 1;
        }

        goto end;
    }

    if (!cptr) goto end;

    pthread_mutex_lock(&cptr->mutex);

    cptr->last_ts = time(0);

    // !!! verify ACK/SEQ here...we will add last .. its irrelevant right now. things happen in serial


    // get the remote sides sequence for the next packet going out
    cptr->remote_seq = iptr->seq;

    // is this attempting to close the connection? 
    if ((iptr->flags & TCP_FLAG_RST) || (iptr->flags & TCP_FLAG_FIN)) {
        // !!! send back ACK, and our FIN here...
        cptr->completed = 1;

        ret = 1;
        goto end;
    }


    // put data into incoming buffer for processing by calling app/functions
    if ((ioptr = (IOBuf *)calloc(1,sizeof(IOBuf))) == NULL) {
        // not enough memory to process connection data.. its done. its established so we cannot deal w that
        // !!! later we can allow tcp resuming, or whatever..
        sptr->completed = 1;

        // we dont want any other sockets processing
        ret = 1;

        goto end;
    }

    // we use the same data pointer...
    ioptr->size = iptr->data_size;
    ioptr->buf = iptr->data;

    // be sure to remove the link so it doesnt get freed
    iptr->data = NULL;
    iptr->data_size = 0;

    ioptr->iptr = InstructionsDuplicate(iptr);

    // thats all...append to this connections buffer
    L_link_ordered((LINK **)&cptr->in_buf, (LINK *)ioptr);

    // send ACK back for this data...

    ret = 1;

    end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ret;
}

// process incoming udp packet, and prepare it for calling application to retrieve the data
int SocketIncomingUDP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr) {
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
int SocketIncomingICMP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr) {
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

// appends an outgoing buffer into a connection
// it has to break it up by the window size....
IOBuf *NetworkAPI_BufferOutgoing(int sockfd, char *buf, int len) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NetworkAPI_ConnectionByFD(ctx, sockfd);
    IOBuf *ioptr = NULL;
    int size = 0;
    char *sptr = buf;

    if (cptr == NULL) goto end;

    cptr->last_ts = time(0);

    // loop adding all data at max to the tcp window...
    while (len > 0) {
        size = min((1500 - (20*2+12)), len);

        if ((ioptr = (IOBuf *)calloc(1, sizeof(IOBuf))) == NULL) goto end;

        if (!PtrDuplicate(sptr, size, &ioptr->buf, &ioptr->size)) {
            free(ioptr);
            goto end;
        }

        sptr += size;

        // FIFO for connection
        L_link_ordered((LINK **)&cptr->out_buf, (LINK *)ioptr);

        len -= size;
    }

end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ioptr;
}


ssize_t my_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    IOBuf *ioptr = NetworkAPI_BufferOutgoing(sockfd, (char *)buf, (int)len);
    if (ioptr == NULL) return -1;

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


// pops the first (longest lasting) iobuf.. FIFO
IOBuf *NetworkAPI_BufferIncoming(int sockfd) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NetworkAPI_ConnectionByFD(ctx, sockfd);
    IOBuf *ioptr = NULL;

    if (cptr == NULL) goto end;
    
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
    ConnectionContext *cptr = NetworkAPI_ConnectionByFD(ctx, sockfd);
    IOBuf *ioptr = NULL, *ionext = NULL;
    IOBuf *ret = NULL;
    int size = 0;
    char *sptr = NULL;
    char *iptr = NULL;

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
        free(ret);
        goto end;
    }

    ret->size = size;
    sptr = ret->buf;

    // copy all data into the  new one now..
    ioptr = cptr->in_buf;
    while (ioptr != NULL) {
        iptr = ioptr->buf + ioptr->ptr;

        memcpy(sptr, iptr, ioptr->size - ioptr->ptr);

        sptr += (ioptr->size - ioptr->ptr);

        ionext = ioptr->next;

        free(ioptr);

        ioptr = ionext;
    }
    
    // we consolidated all of the buffers
    cptr->in_buf = ret;

end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return ret;
}

int NetworkAPI_ReadSocket(int sockfd, char *buf, int len) {
    int ret = 0;
    AS_context *ctx = NetworkAPI_CTX;
    // consolidate first...
    IOBuf *ioptr = NetworkAPI_ConsolidateIncoming(sockfd);
    // this  has to be AFTER consolidate since both use mutex
    ConnectionContext *cptr = NetworkAPI_ConnectionByFD(ctx, sockfd);
    char *sptr = NULL;

    if (!ioptr) goto end;

    cptr->last_ts = time(0);

    // now lets read as much as possible...
    if (len > ioptr->size) len = ioptr->size;

    sptr = ioptr->buf + ioptr->ptr;
    memcpy(buf, sptr, len);

    ioptr->ptr += len;

    if ((ioptr->size - ioptr->ptr) == 0) {
        free(ioptr);
        // we are done with the single buffer we consolidated.. so its empty.
        cptr->in_buf = NULL;
    }

end:;
    if (cptr) pthread_mutex_unlock(&cptr->mutex);

    return len;
}


ssize_t my_recv(int sockfd, void *buf, size_t len, int flags) {
    return NetworkAPI_ReadSocket(sockfd, buf, len);
}


ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    //NetworkAPI_ReadSocket(sockfd, buf, len);
}



ssize_t my_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    AS_context *ctx = NetworkAPI_CTX;
    ConnectionContext *cptr = NetworkAPI_ConnectionByFD(ctx, sockfd);
    IOBuf *ioptr = NULL;

    if (cptr == NULL) return -1;
    
    pthread_mutex_lock(&cptr->mutex);

    if ((ioptr = cptr->in_buf) != NULL) {   
        // copy over the other properties used in this API
        if (*addrlen == sizeof(struct sockaddr) && src_addr)
            memcpy(src_addr, &ioptr->addr, *addrlen);
    }


    pthread_mutex_unlock(&cptr->mutex);

    ssize_t ret = NetworkAPI_ReadSocket(sockfd, buf, len);

    return ret;
}


// !!! support ipv4 (sockaddr to sockaddr6), etc
int my_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen) {
    AS_context *ctx = NetworkAPI_CTX;
    SocketContext *sptr = NetworkAPI_SocketByFD(ctx, sockfd);
    ConnectionContext *cptr = NetworkAPI_ConnectionByFD(ctx, sockfd);
    PacketBuildInstructions *bptr = NULL;
    int start = 0;
    int state = 0;
    int r = 0;
    int ret = 0;

    if (sptr == NULL) return -1;

    if (cptr == NULL) {
        if ((cptr = (ConnectionContext *)calloc(1, sizeof(ConnectionContext))) == NULL) {
            return -1;
        } else {

            cptr->ts = cptr->last_ts = time(0);

            pthread_mutex_init(&cptr->mutex, NULL);

            // init mutex here...
            L_link_ordered((LINK **)&sptr->connections, (LINK *)cptr);
        }
    }

    pthread_mutex_lock(&cptr->mutex);

    // !!!  ipv6
    if ((addrlen == sizeof(struct sockaddr)) && (addr->sin_family == AF_INET)) {
        //memcpy(&cptr->address_ipv4, addr, addrlen);
        cptr->address_ipv4 = addr->sin_addr.s_addr;
        cptr->remote_port = ntohs(addr->sin_port);
    }

    cptr->ts = time(0);
    // pick random source port
    cptr->port = 1024+(rand()%(65536-1024));
    // make sure the original socket context has this port we just chose
    sptr->port = cptr->port;
    cptr->identifier = rand()%0xFFFFFFFF;
    cptr->seq = rand()%0xFFFFFFFF;
    cptr->socket = sptr;

    // generate SYN packet
    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) {
        pthread_mutex_unlock(&cptr->mutex);
        return NULL;
    }

    bptr->flags = TCP_FLAG_SYN|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW;
    bptr->ttl = sptr->ttl ? sptr->ttl : 64;

    // ipv4?
    //if (iptr->source_ip) {   
        bptr->type = PACKET_TYPE_TCP_4 | PACKET_TYPE_IPV4 | PACKET_TYPE_TCP;

        bptr->source_ip = get_local_ipv4();
        bptr->destination_ip = addr->sin_addr.s_addr;
    //}
    /* else {
        // or ipv6?
        bptr->type = PACKET_TYPE_TCP_6 | PACKET_TYPE_IPV6 | PACKET_TYPE_TCP;

        CopyIPv6Address(&bptr->source_ipv6, &iptr->destination_ipv6);
        CopyIPv6Address(&bptr->destination_ipv6, &iptr->source_ipv6);
    }*/

    bptr->source_port = cptr->port;
    bptr->destination_port = cptr->remote_port;
    bptr->header_identifier = cptr->identifier++;

    cptr->socket_fd = sockfd;
    bptr->ack = 0;
    bptr->seq = cptr->seq++;

    cptr->state = SOCKET_TCP|SOCKET_TCP_CONNECTING;

    L_link_ordered((LINK **)&cptr->out_instructions, (LINK *)bptr);
    
    pthread_mutex_unlock(&cptr->mutex);

    // building outgoing SYN packet done by this point

    // if we ARE blocking.. give 30 seconds, and monitor for state changes (linux timeout is somemthing like 22-25 seconds?)
    if (!sptr->noblock) {
        printf("blocking connect\n");
        start = time(0);
        state = cptr->state;
        while (((start - time(0)) < 30) && !r) {
            printf("loop waiting for state change\n");
            sleep(1);

            pthread_mutex_lock(&cptr->mutex);
            // check to see if conneccted.. or change...
            if (cptr->state != state) {
                r = 1;
                break;
            }

            pthread_mutex_unlock(&cptr->mutex);
        }

        //pthread_mutex_lock(&cptr->mutex);

        ret = (cptr->state & SOCKET_TCP_CONNECTED) ? 0 : ECONNREFUSED;

        pthread_mutex_unlock(&cptr->mutex);

        goto end;

    } else
        ret = EINPROGRESS;

end:;
    return ret;
}