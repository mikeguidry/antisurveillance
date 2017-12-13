/*

Full network stack making use of my framework.. It's needed for a few things to come shortly.  It is 'emulated' in a way where regular applications
can use it without requiring any code changes.  This will allow LD_PRELOAD, or other manipulations to activate, and use it.

I need it for a 0day, backdoors w out ports, custom VPN, etc...

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
#include <math.h>

AS_context *NetworkAPI_CTX = NULL;

ssize_t my_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t my_sendmsg(int sockfd, const struct msghdr *msg, int flags);

ssize_t my_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t my_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int my_accept4(int sockfd, struct sockaddr *addr,socklen_t *addrlen, int flags);

int my_socket(int domain, int type, int protocol);
int my_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int my_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int my_listen(int sockfd, int backlog);
int my_close(int fd);
int my_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int my_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);





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
    return ret;

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
    }

    return sptr;
}

ConnectionContext *ConnectionNew(SocketContext *sptr) {
    ConnectionContext *cptr = NULL;

    // allocate space for this structure
    if ((cptr = (ConnectionContext *)calloc(1, sizeof(ConnectionContext))) == NULL)
        return -1;

    cptr->ts = time(0);
    cptr->port = sptr->port;
    cptr->identifier = rand()%0xFFFFFFFF;
    cptr->seq = rand()%0xFFFFFFFF;

    // add the connection to the original socket context structure so it can get accepted by the appllication
    L_link_ordered((LINK **)&sptr->connections, (LINK *)cptr);
    
    return cptr;
}

int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    AS_context *ctx = NetworkAPI_CTX;
    SocketContext *sptr = NetworkAPI_SocketByFD(NetworkAPI_CTX, sockfd);
    SocketContext *pptr = NULL;
    ConnectionContext *cptr = NULL;
    struct sockaddr_in conninfo;
    struct sockaddr_in6 conninfo6;

    // if we cannot find this socket... then return error
    if ((sptr = NetworkAPI_SocketByFD(ctx, sockfd)) == NULL)
        return -1;

    // cant have any connections waiting to be accepted if we didnt add it into the list
    if ((cptr = sptr->connections) == NULL) return -1;

    while (cptr != NULL) {

        // we have a new connection we can offer for accept()
        if (cptr->state & SOCKET_TCP_ACCEPT) break;

        cptr = cptr->next;
    }

    if (cptr == NULL) return -1;

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

            conninfo6.sin6_len = sizeof(struct sockaddr_in6);
            conninfo6.sin6_family = AF_INET6;
            conninfo6.sin6_port = htons(sptr->remote_port);

            CopyIPv6Address(&conninfo6.sin6_addr, &cptr->address_ipv6);
        }
    }

    return cptr->socket_fd;
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
        sptr->state |= PACKET_TYPE_TCP;

        if (sptr->state & PACKET_TYPE_IPV6) sptr->state |= PACKET_TYPE_TCP_6;
        else if (sptr->state & PACKET_TYPE_IPV4) sptr->state |= PACKET_TYPE_TCP_4;
    } else if (protocol == IPPROTO_UDP) {
        sptr->state |= PACKET_TYPE_UDP;

        if (sptr->state & PACKET_TYPE_IPV6) sptr->state |= PACKET_TYPE_UDP_6;
        else if (sptr->state & PACKET_TYPE_IPV4) sptr->state |= PACKET_TYPE_UDP_4;

    } else if (protocol == IPPROTO_ICMP) {
        sptr->state |= PACKET_TYPE_ICMP;

        if (sptr->state & PACKET_TYPE_IPV6) sptr->state |= PACKET_TYPE_ICMP_6;
        else if (sptr->state & PACKET_TYPE_IPV4) sptr->state |= PACKET_TYPE_ICMP_4;
    }

    return sptr->socket_fd;
}


// bind/listen to a port
int my_listen(int sockfd, int backlog) {
    AS_context *ctx = NetworkAPI_CTX;
    SocketContext *sptr = NetworkAPI_SocketByFD(NetworkAPI_CTX, sockfd);
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

    // no error.
    return 0;
}

int my_close(int fd) {
    AS_context *ctx = NetworkAPI_CTX;
    SocketContext *sptr = NetworkAPI_SocketByFD(NetworkAPI_CTX, fd);

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

int NetworkAPI_Cleanup(AS_context *ctx) {
    SocketContext *sptr = NULL, *snext = NULL, *slast = NULL;

    sptr = ctx->socket_list;
    while (sptr != NULL) {
        if (sptr->completed) {
            snext = sptr->next;

            if (slast == NULL) {
                ctx->socket_list = snext;
                slast = ctx->socket_list;
            } else {
                slast->next = snext;
            }

            NetworkAPI_FreeBuffers(&sptr->in_buf);
            NetworkAPI_FreeBuffers(&sptr->out_buf);

            free(sptr);

            sptr = snext;
            continue;
        }

        slast = sptr;
        sptr = sptr->next;
    }
}

// regular loop for performing duties with our network stack
// timeouts, packet retransmitting (if we didnt receieve an ACK), etc....
int NetworkAPI_Perform(AS_context *ctx) {
    SocketContext *sptr = NULL;

    sptr = ctx->socket_list;
    while (sptr != NULL) {
        if (!sptr->completed) {

        }

        sptr = sptr->next;
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
            // if filter is enabled.. verify it...
            if (FilterCheck(ctx, &sptr->flt, iptr)) {
                // be sure both are same types (ipv4/6, and TCP/UDP/ICMP)
                if (((sptr->state & PACKET_TYPE_IPV4) && (iptr->type & PACKET_TYPE_IPV4)) ||
                            ((sptr->state & PACKET_TYPE_IPV6) && (iptr->type & PACKET_TYPE_IPV6))) {

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


// a packet arrives here if its protocol, and type matches.. this function should determine the rest..
int SocketIncomingTCP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr) {
    int ret = 0;
    int new_fd = 0;
    IOBuf *ioptr = NULL;
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    ConnectionContext *cptr = NULL;

    // be sure both are same IP protocol ipv4 vs ipv6
    if (sptr->address_ipv4 && !iptr->source_ip)
        goto end;

    // verify ports equal to easily disqualify
    if ((iptr->destination_port != sptr->port))// && (iptr->source_port != sptr->port))
        goto end;

    // find this connection if it exists in the list
    cptr = sptr->connections;
    while (cptr != NULL) {
        if (!cptr->completed && (cptr->remote_port == iptr->source_port)) break;

        cptr = cptr->next;
    }

    // is this an ACK to some packet we sent?
    if (iptr->flags & TCP_FLAG_ACK) {
        // we need to determine if we were waiting for this ACK to push more data, or otherwise (open connection)

    }

    // SYN = new  connection.. see if we are listening
    if (iptr->flags & TCP_FLAG_SYN) {
        // ensure the state is listening
        if (sptr->state & SOCKET_TCP_LISTEN) {

            if ((new_fd = NetworkAPI_NewFD(ctx)) == -1) goto end;

            if ((cptr = ConnectionNew(sptr)) == NULL) goto end;

            if ((bptr = (PacketBuildInstructions *)BuildBasePacket(ctx, sptr, iptr, TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW)) == NULL)
                goto end;

            cptr->socket_fd = new_fd;
            bptr->ack = iptr->seq;
            bptr->seq = cptr->seq++;

            cptr->state |= SOCKET_TCP_ACCEPT;

            ret = 1;
        }

        goto end;
    }


    if (!cptr) goto end;

    

    // verify ACK/SEQ here...we will add last .. its irrelevant right now. things happen in serial


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