/*
    Base networking functionality for processing large amounts of Incoming, and Outgoing traffic.  It also can be used for IPv4, or
    IPv6, and the usual protocols: TCP/UDP/ICMP.
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
#include "instructions.h"
#include <errno.h>

/*
incoming and outgoing queue allocation holds for a large amount of packets, and up to a buffer size.  this is to release tension on
malloc during operations.
*/

OutgoingPacketQueue *OutgoingQueueAlloc(AS_context *ctx) {
    char *buf = NULL;
    int size = 0;
    OutgoingPacketQueue *optr = NULL;
    
    size = sizeof(OutgoingPacketQueue);

    // also needs size of buffer
    size += ctx->queue_buffer_size;

    size += (ctx->queue_max_packets * sizeof(OutgoingPacketInformation));

    // malloc instead of calloc so we dont waste cycles zero'ing the packet buffer
    if ((buf = malloc(size)) == NULL) return NULL;

    optr = (OutgoingPacketQueue *)buf;
    // zero structure information    
    memset(buf, 0, sizeof(OutgoingPacketQueue));
    optr->max_packets = ctx->queue_max_packets;
    optr->max_buf_size = ctx->queue_buffer_size;

    optr->packets = (OutgoingPacketInformation *)(buf + sizeof(OutgoingPacketQueue));
    
    // prepare structure pointers
    optr->buf = (char *)(buf + sizeof(OutgoingPacketQueue) + (ctx->queue_max_packets * sizeof(OutgoingPacketInformation)));

    //printf("outgoing alloc %p\n", optr);
    //printf("%p optr max buf %d optr size %d cur pkt %d max %d\n", optr,
    //optr->max_buf_size, optr->size, optr->cur_packet, optr->max_packets);


    return optr;
} 

IncomingPacketQueue *IncomingQueueAlloc(AS_context *ctx) {
    char *buf = NULL;
    int size = 0;
    IncomingPacketQueue *iptr = NULL;
    
    size = sizeof(IncomingPacketQueue);

    // also needs size of buffer
    size += ctx->queue_buffer_size;

    // also size of packet_starts
    size += (ctx->queue_max_packets * sizeof(IncomingPacketInformation));

    if ((buf = malloc(size)) == NULL) return NULL;


    iptr = (IncomingPacketQueue *)buf;

    memset(buf, 0, sizeof(IncomingPacketQueue));
    iptr->max_packets = ctx->queue_max_packets;
    iptr->max_buf_size = ctx->queue_buffer_size;

    //printf("new incom %d size %d\n", ctx->queue_max_packets, ctx->queue_buffer_size);

    iptr->packets = (IncomingPacketInformation  *)(buf + sizeof(IncomingPacketQueue));
    
    // prepare structure pointers
    iptr->buf = (char *)(buf + sizeof(IncomingPacketQueue) + (ctx->queue_max_packets * sizeof(IncomingPacketInformation)));

    //printf("incom alloc %p\n", iptr);

    return iptr;
} 


OutgoingPacketQueue *OutgoingPoolGet(AS_context *ctx) {
    OutgoingPacketQueue *optr = NULL;

    // get outgoing packet queue structure from buffer
    pthread_mutex_lock(&ctx->network_pool_mutex);

    // we wanna be able to filter out our own sessions.. and since we are going to perfor so many at a time
    // the ports may change in the actual attack strucctures.. so we must verify against older already sent packets
    optr = ctx->outgoing_pool_waiting;

    // loop for all outgoing queues...
  /*  while (optr != NULL) {

        // if the memory is below 200 megabytes, then we do not hold it for 3 seconds...
        if (ctx->free_memory && ctx->free_memory < 200) break;

        // be sure its existed for at least 3 seconds...
        if ((ts - optr->ts) > 3) {
            // if so then we can use it.. we will assume that all packets were verified properly
            break;
        }

        optr = optr->next;
    } */

    if (optr) {
        ctx->outgoing_pool_waiting = optr->next;
        optr->next = NULL;
    }
    //if (optr != NULL) L_unlink((void **)&ctx->outgoing_pool_waiting, (LINK *)optr);

    pthread_mutex_unlock(&ctx->network_pool_mutex);
    
    // if we didnt then will allocate a new  one which will go to the pool whenever are complete
    if (optr == NULL) {   
        if ((optr = OutgoingQueueAlloc(ctx)) == NULL) return NULL;
        //printf("pool empty %p\n", optr);
    }

    optr->cur_packet = 0;
    optr->size = 0;
    optr->ts = time(0);
    
    return optr;
}


void DebugTCPPacket(OutgoingPacketQueue *optr, int cur_packet) {
    struct packet *p = NULL;
    char *sptr = NULL;

    sptr = optr->packets[cur_packet].buf;
    p = (struct packet *)sptr;

CLR_RED();
    printf("WIRE SEQ: ID %04X %08X ACK: %08X addr: %p %p raw: %08X %08X\n",
    ntohs(p->ip.id),
    ntohl(p->tcp.seq), ntohl(p->tcp.ack_seq),
    &p->tcp.seq, &p->tcp.ack_seq,
    p->tcp.seq, p->tcp.ack_seq);
CLR_RESET();
}


// this is the iterface between the packet queue, and the operating system to send packets..
// it is the final place a packet buffer should rest before its discarded
int FlushOutgoingQueueToNetwork(AS_context *ctx, OutgoingPacketQueue *optr) {
    int count = 0;
    OutgoingPacketQueue *onext = NULL;
    OutgoingPacketQueue *pool = NULL, *plast = NULL;
    struct sockaddr_in raw_out_ipv4;
    struct sockaddr_in6 raw_out_ipv6;
    int bytes_sent = 0;
    char *sptr = NULL;
    int cur_packet = 0;
    int packet_size = 0;

/*
    // we need some raw sockets.
    if (ctx->write_socket[0][0] <= 0) {
        if (prepare_write_sockets(ctx) <= 0) {
            //printf("no raw socket\n");
            return -1;
        }
    }
*/

    while (optr != NULL) {
        //printf("optr %p optr->next %p\n", optr, optr->next);
        cur_packet = 0;
        // be sure it wasnt marked to get ignored
        if (!optr->ignore) {
            while (cur_packet < optr->cur_packet) {
                
                // sptr starts at the beginning of the buffer

                sptr = optr->packets[cur_packet].buf;
                packet_size = optr->packets[cur_packet].size;


                //printf("processing outgoing packet %p/%d\n", sptr, packet_size);
                //if (optr->packet_protocol[cur_packet] == PROTO_TCP) DebugTCPPacket(optr, cur_packet);

                // calculate the size of this particular packet we are going to process
                packet_size = optr->packets[cur_packet].size;
                if (optr->packets[cur_packet].dest_ip) {
                    // IPv4
                    raw_out_ipv4.sin_family       = AF_INET;
                    raw_out_ipv4.sin_port         = htons(optr->packets[cur_packet].dest_port);
                    raw_out_ipv4.sin_addr.s_addr  = optr->packets[cur_packet].dest_ip;

                    // write the packet to the raw network socket.. keeping track of how many bytes
                    bytes_sent = sendto(ctx->write_socket[optr->packets[cur_packet].protocol][optr->packets[cur_packet].ipversion], sptr, packet_size, 0, (struct sockaddr *) &raw_out_ipv4, sizeof(raw_out_ipv4));
                    
                } else {
                    // ipv6...
                    memset(&raw_out_ipv6, 0, sizeof(raw_out_ipv6));
                    raw_out_ipv6.sin6_family = AF_INET6;
                    raw_out_ipv6.sin6_port   = 0;//htons(optr->packets[cur_packet].dest_port);
                    CopyIPv6Address(&raw_out_ipv6.sin6_addr, &optr->packets[cur_packet].dest_ipv6);

                    bytes_sent = sendto(ctx->write_socket[optr->packets[cur_packet].protocol][optr->packets[cur_packet].ipversion], sptr, packet_size, 0, (const struct sockaddr *) &raw_out_ipv6, sizeof(raw_out_ipv6));
                }

                // if sent matches size then we count it
                if (bytes_sent == packet_size) {
                    //printf("Wrote packet to network\n");
                    count++;
                } else {
                    //printf("wrote wrong %d\n", errno);
                }

                // move to the next packet
                cur_packet++;
            }
        }


        // we set the timer here so we can use old outgoing  packet structures for X seconds to filter 'incoming' packet from our own
        // if the kernel decided to deliver them to use (i believe  it does, but it may depend on the type of socket.. so the protocol and domain)
        optr->ts = time(0);

        // remove flag so it can be used again in future
        if (optr->ignore) {
            optr->ignore = 0;
        }

        onext = optr->next;
        

        if (plast == NULL) {
            pool = plast = optr;
        } else {
            plast->next = optr;
            plast = optr;
        }
        optr->next = NULL;

        //L_link_ordered((LINK **)&pool, (LINK *)optr);

        //free(optr);
        
        // put into local stack pool to get moved to global pool at end of the function
        //optr->next = pool;
        //pool = optr; 

        optr = onext;
    }

    if (pool) {
        //printf("pool\n");
        // put back into pool after for use again.. without requiring infinite reallocations
        pthread_mutex_lock(&ctx->network_pool_mutex);

        
        //L_link_ordered((LINK **)&ctx->outgoing_pool_waiting, (LINK *)pool);
        plast->next = ctx->outgoing_pool_waiting;
        ctx->outgoing_pool_waiting = pool;

        /*
        printf("out count %d\n", L_count((LINK *)ctx->outgoing_pool_waiting));

        int y = 0;
        for (optr = ctx->outgoing_pool_waiting; optr != NULL; optr = optr->next) {
            printf("%d. %p\n", y, optr);
            y++;
        }
        */

        pthread_mutex_unlock(&ctx->network_pool_mutex);
    }

    return count;
}

void ClearPackets(AS_context *ctx) {
    OutgoingPacketQueue *optr = ctx->outgoing_queue;

    pthread_mutex_lock(&ctx->network_queue_mutex);

    // mark all as ignore (itll just clear on next loop)
    while (optr != NULL) {

        optr->ignore = 1;

        optr = optr->next;
    }
    
    pthread_mutex_unlock(&ctx->network_queue_mutex);
}


int OutgoingQueueProcess(AS_context *ctx) {
    OutgoingPacketQueue *optr = NULL;
    int count = 0;
    //printf("out\n");

    if (!ctx->network_disabled) {
        pthread_mutex_lock(&ctx->network_queue_mutex);

        optr = ctx->outgoing_queue;
        ctx->outgoing_queue_last = ctx->outgoing_queue = NULL;

        pthread_mutex_unlock(&ctx->network_queue_mutex);

        if (optr != NULL) {
            count = FlushOutgoingQueueToNetwork(ctx, optr);

            optr = NULL;
        }
    }

    return count;
}



// another thread for dumping from queue to the network
void *thread_network_flush(void *arg) {
    AS_context *ctx = (AS_context *)arg;
    int count = 0;
    int i = 0;
    //pthread_t this_thread = pthread_self()

    // prioritize this pthread as high
    //params.sched_priority = sched_get_priority_max(SCHED_FIFO);
    //pthread_setschedparam(this_thread, SCHED_FIFO, &params);

    while (1) {
        count = OutgoingQueueProcess(ctx);
        
        //if (count)printf("Network Thread Outgoing count flushed: %d\n", count);
        // if none.. then lets sleep..  
        if (!count) {
            //printf("didnt push any\n");
            //sleep(1);
            usleep(5000);
        } else {
            
            //i = (1000000 / 4) - (i * 25000);
            
            
            //i /= 4;
            i = 1000;
            //printf("usleep %d\n", i);
            if (i > 0 && (i <= 1000000)) usleep(i);
        }
    }
}



// prepare raw outgoing socket (requires root)..
int prepare_write_sockets(AS_context *ctx) {
    int one = 1;
    int ip_ver = 0, proto = 0;
    int which_proto = 0, which_domain = 0;
    int bufsize = 1024*1024*10;
    int flags = 0;

    for (proto = 0; proto < 3; proto++) {
        for (ip_ver = 0; ip_ver < 2; ip_ver++) {

            // if the sockets already exist.. lets just make sure its still usable
            if (ctx->write_socket[proto][ip_ver] > 0) {
                // If we cannot use setsockopt.. there must be trouble!
                if (setsockopt(ctx->write_socket[proto][ip_ver], ip_ver ? IPPROTO_IPV6 : IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
                    close(ctx->write_socket[proto][ip_ver]);
                    ctx->write_socket[proto][ip_ver] = 0;
                } else
                    // socket is OK
                    continue;
            }
            
            // if it was not usable.. lets initialize a new one

            // use correct settings for correct ipv4/6 or tcp/udp/icmp..
            // not pretty maybe use a structure  later.. quick dev
            switch (proto) {
                //case PROTO_TCP: which_proto = IPPROTO_TCP; break;
                case PROTO_TCP: which_proto = (ip_ver == IPVER_6) ? IPPROTO_RAW : IPPROTO_TCP; break;
                case PROTO_UDP: which_proto = (ip_ver == IPVER_6) ? IPPROTO_RAW : IPPROTO_UDP; break;
                case PROTO_ICMP: which_proto = IPPROTO_ICMP; break;
            }

            switch (ip_ver) {
                case IPVER_6: which_domain = AF_INET6; break;
                case IPVER_4: which_domain = AF_INET; break;
            }
            //which_domain = PF_PACKET;
            
            // open raw socket
            if ((ctx->write_socket[proto][ip_ver] = socket(which_domain, SOCK_RAW, which_proto)) <= 0) {
                fprintf(stderr, "couldnt open raw socket.. are we root?\n");
                exit(-1);
                return -1;
            }


            flags = fcntl(ctx->write_socket[proto][ip_ver], F_GETFL, flags);
            flags |= O_NONBLOCK;
            flags = fcntl(ctx->write_socket[proto][ip_ver], F_SETFL, flags);

            //https://stackoverflow.com/questions/12177708/raw-socket-promiscuous-mode-not-sniffing-what-i-write
            //memcpy(&ifr.ifr_name, ctx->network_interface, IFNAMSIZ);
            //ioctl(ctx->write_socket[proto][ip_ver], SIOCGIFINDEX, &ifr);

            //mreq.mr_ifindex = ifr.ifr_ifindex;
            //mreq.mr_type = PACKET_MR_PROMISC;
            //mreq.mr_alen = 6;

            // enable promisc -- !!! not working properly.. come fix.. for now ip addr add <1-255>
            //setsockopt(ctx->write_socket[proto][ip_ver],SOL_PACKET,PACKET_ADD_MEMBERSHIP,(void*)&mreq,(socklen_t)sizeof(mreq));

            setsockopt(ctx->write_socket[proto][ip_ver], SOL_SOCKET, SO_SNDBUFFORCE, &bufsize, sizeof(bufsize));

            // ensure the operating system knows that we will include the IP header within our data buffer
            setsockopt(ctx->write_socket[proto][ip_ver], (ip_ver == IPVER_6) ? IPPROTO_IPV6 : IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one));
        }
    }

    return 1;
}


// http://yusufonlinux.blogspot.com/2010/11/data-link-access-and-zero-copy.html
// https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linuxin
// prepare raw incoming socket.. we perform our own filtering so we want all packets
int prepare_read_sockets(AS_context *ctx) {
    int ret = 0;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int flags = 0;
    struct ifreq if_mac;
    struct ifreq if_ip;
    int bufsize = 1024*1024*10;
    int ip_ver = 0;
    int which_proto = 0, proto = 0, which_domain = 0;

    struct packet_mreq mreq;

    // set ifr structure to 0
    memset (&ifr, 0, sizeof (struct ifreq));
    memset(&if_mac, 0, sizeof(struct ifreq));
    memset(&if_ip, 0, sizeof(struct ifreq));
    memset(&mreq, 0, sizeof(mreq));

    for (proto = 0; proto < 3; proto++) {
        for (ip_ver = 0; ip_ver < 2; ip_ver++) {
            // if we have a read socket.. then we wanna make sure its OK.. quick IOCTL call would do it
            if (ctx->read_socket[proto][ip_ver] != 0) {
                // if this works properly.. it should already have been initialized
                if (ioctl (ctx->read_socket[proto][ip_ver], SIOCGIFINDEX, &ifr) == 0) {
                    // close it if not..
                    close(ctx->read_socket[proto][ip_ver]);

                    // set to 0 since its stale
                    ctx->read_socket[proto][ip_ver] = 0;

                    //printf("bad\n");
                    goto end;
                } else {
                    continue;
                }

            }

            switch (proto) {
                case PROTO_TCP: which_proto = IPPROTO_TCP; break;
                //case PROTO_UDP: which_proto = (ip_ver == IPVER_6) ? IPPROTO_RAW : IPPROTO_UDP; break;
                case PROTO_UDP: which_proto = IPPROTO_UDP; break;
                case PROTO_ICMP: which_proto = (ip_ver == IPVER_6) ? IPPROTO_ICMPV6 : IPPROTO_ICMP; break;
            }

            switch (ip_ver) {
                case 0: which_domain = AF_INET; break;
                case 1: which_domain = AF_INET6; break;
            }

            int socket_type = SOCK_RAW;
#define NEW_RAW            
#ifdef NEW_RAW

            if (proto == 0) {
                which_proto = htons(ip_ver ? ETH_P_IPV6 : ETH_P_IP);
            }
            //socket_type = SOCK_PACKET;
            which_domain = PF_PACKET;
#endif

            //printf("allocating socket proto %d ip ver %d\n", proto, ip_ver);
            // initialize a new socket
            if ((ctx->read_socket[proto][ip_ver] = socket(which_domain, socket_type, which_proto)) == -1) {
                fprintf(stderr, "couldnt open raw socket.. are we root?\n");
                exit(-1);
            }
#ifdef NEW_RAW            
            strncpy((char *)ifr.ifr_name, ctx->network_interface, IFNAMSIZ);
            if((ioctl(ctx->read_socket[proto][ip_ver], SIOCGIFINDEX, &ifr)) == -1) {
                printf("couldnt find interface\n");
                return -1;
            }

            sll.sll_family = PF_PACKET;
            sll.sll_ifindex = ifr.ifr_ifindex;
            sll.sll_protocol = which_proto;

            if((bind(ctx->read_socket[proto][ip_ver], (struct sockaddr *)&sll, sizeof(sll)))== -1) {
                printf("couldnt bind to socket\n");
                return -1;
            }                       
            //printf("bound to index %d\n", ifr.ifr_ifindex);
#endif
            setsockopt(ctx->read_socket[proto][ip_ver], SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize));
            
            // set non blocking
            //https://stackoverflow.com/questions/1543466/how-do-i-change-a-tcp-socket-to-be-non-blocking
            flags = fcntl(ctx->read_socket[proto][ip_ver], F_GETFL, flags);
            flags |= O_NONBLOCK;
            flags = fcntl(ctx->read_socket[proto][ip_ver], F_SETFL, flags);
        }
    }

    ret = 1;
    //printf("open socket %d\n", sockfd);

    end:;
    
    // if it failed for any reason...
    //if (ctx->read_socket == 0 && sockfd) close(sockfd);

    // return if it was successful
    return ret;//(ctx->read_socket != 0);
}


// this will take a buffer, and size expected to come directly fromm the network driver
// it will process it through filters, and if passing will send to whatever functions, or subsystems
// requested data of that statue
// *** todo: maybe make a filter check which takes a packet buffer instead of
// requiring the build instructions (less cycles)
int process_packet(AS_context *ctx, char *packet, int size) {
    NetworkAnalysisFunctions *nptr = ctx->IncomingPacketFunctions;
    PacketBuildInstructions *iptr = NULL;
    int ret = -1;
    //FILE *fd;
    //char fname[1024];

    //if (size == 0) goto end;

    // if we dont have any subsystems waiting for packets.. no point
    //if (nptr == NULL) goto end;

    /*if (1==2 && (fd = fopen(fname, "wb")) != NULL) {
        fwrite(packet, size, 1, fd);
        fclose(fd);
    }*/

    // analyze that packet, and turn it into a instructions structure
    if ((iptr = (PacketBuildInstructions *)PacketsToInstructions(ctx, packet, size)) == NULL) goto end;
    
    //printf("processing packet\n");
    // loop looking for any subsystems where it may be required
    while (nptr != NULL) {
        // if the packet passes the filter then call its processing function
        if (!nptr->flt || FilterCheck(ctx, nptr->flt, iptr)) {
            //printf("pass filter iptr %p funnc %p\n", iptr, nptr->incoming_function);
            // maybe verify respoonse, and break the loop inn some case
            nptr->incoming_function(ctx, iptr);

            ret = 1;
            
            nptr->bytes_processed += size;
        }

        // move to the next network filter to see if it wants the packet
        nptr = nptr->next;
    }

    // worked out alright.
    ret = 0;

    end:;

    // dont free.. function wanted it.
    PacketBuildInstructionsFree(&iptr);

    return ret;
}


// this will process the incoming buffers
int network_process_incoming_buffer(AS_context *ctx) {
    IncomingPacketQueue *nptr = NULL, *nnext = NULL;
    IncomingPacketQueue *pool = NULL, *plast = NULL;
    int ret = 0;
    int cur_packet = 0;

    //printf("process incomming buffer\n");
    
    // lock thread so we dont attempt to read or write while another thread is
    pthread_mutex_lock(&ctx->network_incoming_mutex);

    // lets pop the buffer we need to read first from the list
    nptr = ctx->incoming_queue;

    // set all to NULL so its awaiting for future packets...
    ctx->incoming_queue = ctx->incoming_queue_last = NULL;

    //printf("nptr count %d\n", L_count((LINK *)nptr)); 

    // unlock thread...
    pthread_mutex_unlock(&ctx->network_incoming_mutex);

    //if (nptr == NULL) goto end;

    //printf("\n\nnetwork_process_incoming_buffer: first link %p\n", nptr);

    // now lets process all packets we have.. each is a cluster of packets
    while (nptr != NULL) {
        cur_packet = 0;

        // lets loop for every packet in this structure..
        while (cur_packet < nptr->cur_packet) {
            //increase it to the startinng place of this packet
            //sptr += nptr->packet_starts[cur_packet];

            // call the function which processes it by turning it into a packet structure
            // it will then send to the correct functions for analysis, and processing afterwards
            // for whichever subsystem may want it
            process_packet(ctx, nptr->packets[cur_packet].buf, nptr->packets[cur_packet].size);
            
            // move to the next packet
            cur_packet++;
        }

        // we are finished processing that cluster... we can free it
        nnext = nptr->next;

        if (plast == NULL) {
            pool = plast = nptr;
        } else {
            plast->next = nptr;
            plast = nptr;
        }
        nptr->next = NULL;
        
        // free this structure since we are finished with it
        //free(nptr);
        
        // go to the next cluster of packets we are processing
        nptr = nnext;
    }

    if (pool) {
        // lets the empty queue 
        pthread_mutex_lock(&ctx->network_pool_mutex);

        
        // put back into waiting pool so we dont allocate over and over
        //L_link_ordered((LINK **)&ctx->incoming_pool_waiting, (LINK *)pool);
        plast->next = ctx->incoming_pool_waiting;
        ctx->incoming_pool_waiting = pool;

        //printf("2 count %d\n", L_count((LINK *)ctx->incoming_pool_waiting));
        //printf("incom count %d\n", L_count((LINK *)ctx->incoming_pool_waiting));

        pthread_mutex_unlock(&ctx->network_pool_mutex);
    }

    //end:;
    return ret;
}

int NetworkReadSocket(IncomingPacketQueue *nptr, int socket, int proto, int ip_ver) {
    char *sptr = NULL;
    int r = 0;
    int ret = 0;    


    //printf("ReadSocket %d proto %d ip %d\n", socket, proto, ip_ver);
    
    // increase pointer to the correct location (After the last packet)
    sptr = (char *)nptr->buf + nptr->size;

    r = recvfrom(socket, sptr, nptr->max_buf_size - nptr->size, 0, NULL, NULL); //&sll, sll_len);
    
    // if no more packets.. lets break and send it off for processing
    if (r > 0) {
        nptr->packets[nptr->cur_packet].size = r;
        nptr->packets[nptr->cur_packet].protocol = proto;
        nptr->packets[nptr->cur_packet].ipversion = ip_ver;
        nptr->packets[nptr->cur_packet].buf = sptr;

        // prep for the next packet
        nptr->cur_packet++;

        // so the next packet gets its own space
        nptr->size += r;

        ret = 1;
    }
    
    return ret;
}

// this attempts to get one cluster of packets from the read socket..
// it can get called from the threaded version, or in general from a function
// which just needs to read on its own timing (or from python)/loops
int network_fill_incoming_buffer(AS_context  *ctx, IncomingPacketQueue *nptr) {
    int ret = 0;
    int r = 0;
    int proto = 0;
    int ip_ver = 0;
    int packet_count = 0;
    int waiting_size = 0;

    // enumerate for each protocol and packet type to read into our buffer
    for (proto = 0; proto < 3; proto++) {
        for (ip_ver = 0; ip_ver < 2; ip_ver++) {            
            do {
                // we only have positions for a max of X packets with this buffer
                if (nptr->cur_packet >= (nptr->max_packets - 1)) {
                    //printf("too much\n");
                    goto too_much;
                }

                waiting_size = 0;
                ioctl(ctx->read_socket[proto][ip_ver], FIONREAD, &waiting_size);
                if (waiting_size >= (nptr->max_buf_size - nptr->size)) {
                    goto too_much;
                }

                r = NetworkReadSocket(nptr, ctx->read_socket[proto][ip_ver], proto, ip_ver);

                if (r == -1) goto end;

                packet_count += r;
            } while (r);
        }

        /*
        // if we have used 90% of the buffer size...
        if (nptr->size >= ((nptr->max_buf_size / 10) * 9)) goto too_much;

        // we only have positions for a max of X packets with this buffer
        if (nptr->cur_packet >= MAX_PACKETS) goto too_much;
        */
    }

    goto end;

    too_much:;
    //printf("too much\n");

    // did we get some packets?
    end:;

    ret = (nptr->cur_packet > 0);


    return ret;
}



int NetworkAllocateReadPools(AS_context *ctx) {
    int i = 0;
    IncomingPacketQueue *pqptr = NULL;

    pthread_mutex_lock(&ctx->network_pool_mutex);
    
    // allocate X pools for reading.. (some will get queued awaiting processing, etc)..
    // this should cut down on memory allocations
    while (i < ctx->initial_pool_count) {
        pqptr = IncomingQueueAlloc(ctx);

        if (pqptr != NULL) {
            // put into the pool
            pqptr->next = ctx->incoming_pool_waiting;
            ctx->incoming_pool_waiting = pqptr;
        }
        i++;
    }

    pthread_mutex_unlock(&ctx->network_pool_mutex);

    return 1;
}



int NetworkAllocateWritePools(AS_context *ctx) {
    int i = 0;
    OutgoingPacketQueue *pqptr = NULL;

    pthread_mutex_lock(&ctx->network_pool_mutex);
    
    // allocate X pools for reading.. (some will get queued awaiting processing, etc)..
    // this should cut down on memory allocations
    while (i < ctx->initial_pool_count) {
        pqptr = (OutgoingPacketQueue *)OutgoingQueueAlloc(ctx);

        if (pqptr != NULL) {
            // put into the pool
            pqptr->next = ctx->outgoing_pool_waiting;
            ctx->outgoing_pool_waiting = pqptr;
        }
        i++;
    }

    pthread_mutex_unlock(&ctx->network_pool_mutex);

    return 1;
}




// thread to read constantly from the network
int network_read_loop(AS_context *ctx) {
    int ret = 0;
    IncomingPacketQueue *nptr = NULL;

    //printf("network read loop\n");

    pthread_mutex_lock(&ctx->network_pool_mutex);

    // grab one from the pool
    nptr = ctx->incoming_pool_waiting;
    // remove from pool queue
    if (nptr) {
        ctx->incoming_pool_waiting = nptr->next;
        nptr->next = NULL;
    }

    pthread_mutex_unlock(&ctx->network_pool_mutex);

    if (nptr == NULL) {
        if ((nptr = IncomingQueueAlloc(ctx)) == NULL) {
            goto end;
        }
    }

    // so its not still linked to the  pool
    nptr->cur_packet = 0;
    nptr->size = 0;

    network_fill_incoming_buffer(ctx, nptr);


    if (nptr->cur_packet > 0) {
        pthread_mutex_lock(&ctx->network_incoming_mutex);

        if (ctx->incoming_queue_last != NULL) {
            // set the next of that to this new one
            ctx->incoming_queue_last->next = nptr;
            // set the last as this one for the next queue
            ctx->incoming_queue_last = nptr;

            ret = 1;
        } else {
            // buffer is completely empty.. set it, and the last pointer to this one
            ctx->incoming_queue = ctx->incoming_queue_last = nptr;
        }

        // no more variables which we have to worry about readwrite from diff threads
        pthread_mutex_unlock(&ctx->network_incoming_mutex);

        nptr = NULL;

        //if (!ctx->network_read_threaded) { network_process_incoming_buffer(ctx); }
    }
    
    // put back in pool for usage
    if (nptr != NULL) {
        //free(nptr);
        pthread_mutex_lock(&ctx->network_pool_mutex);
        nptr->next = ctx->incoming_pool_waiting;
        ctx->incoming_pool_waiting = nptr;
        pthread_mutex_unlock(&ctx->network_pool_mutex);
    }

    //printf("network read end\n");
    end:;
    return ret;
}


void *thread_read_network(void *arg) {
    AS_context *ctx = (AS_context *)arg;
    //pthread_t this_thread = pthread_self();
    int paused = 0;
 
     // We'll set the priority to the maximum.
    //params.sched_priority = sched_get_priority_max(SCHED_FIFO);
    //pthread_setschedparam(this_thread, SCHED_FIFO, &params);
    while (1) {
        network_read_loop(ctx);

                // get paused variable from network disabled
            paused = (ctx->network_disabled || ctx->paused);


        // if paused.. lets sleep for 1/10th a second each time we end up here..
        if (paused) {
            usleep(50000);
        } else {            
            //sleep_interval = (5000000 / 4) - (ctx->aggressive * 25000);
            //sleep_interval /= 2;
            //if (sleep_interval > 0)
                // timing change w aggressive-ness
              //  usleep(sleep_interval);
              usleep(20000);
              //sleep(1);
            
        }


    }

    
    // lets lock mutex sinnce we will change some variables
    pthread_mutex_lock(&ctx->network_incoming_mutex);

    // so we know this thread no longer is executing for other logic
    ctx->network_read_threaded = 0;
    
    // unlock mutex..
    pthread_mutex_unlock(&ctx->network_incoming_mutex);

    // free nptr if it wasnt passed along before getting here
    //PtrFree(&nptr);

    // exit thread
    pthread_exit(NULL);

    return 0;
}


int Network_AddHook(AS_context *ctx, FilterInformation *flt, void *incoming_function) {
    NetworkAnalysisFunctions *nptr = NULL;

    if (!flt || !incoming_function) return -1;

    if ((nptr = (NetworkAnalysisFunctions *)calloc(1, sizeof(NetworkAnalysisFunctions))) == NULL)
        return -1;

    nptr->incoming_function = incoming_function;
    nptr->flt = flt;

    //printf("Hook added: %p\n", incoming_function);
    // insert so the network functionality will begin calling our function for these paackets
    L_link_ordered((LINK **)&ctx->IncomingPacketFunctions, (LINK *)nptr);

    return 1;
}

void OutgoingQueueLink(AS_context *ctx, OutgoingPacketQueue *optr) {
    pthread_mutex_lock(&ctx->network_queue_mutex);

    // Link outgoing packets ordered
    if (ctx->outgoing_queue_last) {
        ctx->outgoing_queue_last->next = optr;
        ctx->outgoing_queue_last = optr;
    } else {
        ctx->outgoing_queue_last = ctx->outgoing_queue = optr;
    }

    optr->next = NULL;
    
    pthread_mutex_unlock(&ctx->network_queue_mutex);

    //printf("Linked in %p\n", optr);
}



// merge this with the other attackqueueadd.. and make 2 smaller functions for each input type..
int NetworkQueueInstructions(AS_context *ctx, PacketBuildInstructions *iptr, OutgoingPacketQueue **_optr) {
    int ret = 0;
    OutgoingPacketQueue *optr = NULL;
    char *sptr = NULL;
    int which_protocol = 0;

/*CLR_YELLOW();
    printf("nqueue %04X %08X %08X [seq %p ack %p] %p\n", iptr->header_identifier, iptr->seq, iptr->ack, &iptr->seq, &iptr->ack, iptr->packet);
CLR_RESET();*/

    if (iptr->packet == NULL)
        BuildPacketInstructions(iptr);

    if (iptr->packet == NULL) return -1;

    if (((optr = *_optr)) == NULL) {
        *_optr = optr = OutgoingPoolGet(ctx);
        if (optr == NULL) {
            return -1;
        }
    }
    
    // if this packet queue doesn't have enough space for the  entire packet.. we need to allocate a new one
    if ((iptr->packet_size > (optr->max_buf_size - optr->size) || (optr->cur_packet >= optr->max_packets))) {
        //printf("%p iptr size %d optr max buf %d optr size %d cur pkt %d max %d\n", optr, iptr->packet_size,
        //optr->max_buf_size, optr->size, optr->cur_packet, optr->max_packets);
        // it needs to get moved into the outgoing buffer first
        OutgoingQueueLink(ctx, optr);

        // now allocate a new buffer
        if ((optr = *_optr = OutgoingPoolGet(ctx)) == NULL)
            return -1;
    }

    // copy packet into outgoing packet queue structure (many together)
    // for speed and to not use many threads, or malloc, etc
    sptr = (char *)(optr->buf + optr->size);

    memcpy(sptr, iptr->packet, iptr->packet_size);

    optr->packets[optr->cur_packet].buf = sptr;
    optr->packets[optr->cur_packet].size = iptr->packet_size;

    optr->packets[optr->cur_packet].dest_ip = iptr->destination_ip;
    CopyIPv6Address(&optr->packets[optr->cur_packet].dest_ipv6, &iptr->destination_ipv6);
    optr->packets[optr->cur_packet].dest_port = iptr->destination_port;
    //optr->attack_info[optr->cur_packet] = aptr;
    optr->ctx = ctx;

    if (iptr->type & PACKET_TYPE_TCP) {
        which_protocol = PROTO_TCP;
    } else if (iptr->type & IPPROTO_UDP) {
        which_protocol = PROTO_UDP;
    } else if (iptr->type & IPPROTO_ICMP) {
        which_protocol = PROTO_ICMP;
    }

    // mark protocol
    optr->packets[optr->cur_packet].protocol = which_protocol;
    // mark if its ipv6 by checking if ipv4 is empty
    optr->packets[optr->cur_packet].ipversion = (iptr->destination_ip == 0);

    optr->size += iptr->packet_size;

    // prepare for the next packet
    optr->cur_packet++;

    ret = 1;

    return ret; 
}
