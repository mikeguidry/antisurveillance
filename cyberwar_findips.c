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

int r_count = 0;
FILE *fd2 = NULL;

int CW_FindIP_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    struct in_addr src;
    // we will use >60000 ports for scanning.. to make it quick here
    if (iptr->source_port < 60000 && iptr->destination_port < 60000) return 0;

    // we only care about RST...
    if (!(iptr->flags & TCP_FLAG_RST)) return 0;

    if (fd2) {
        r_count++;
        src.s_addr = iptr->source_ip;
        fprintf(fd2, "%s\n", inet_ntoa(src));
    }

    return 0;
}


int CW_FindIP_Init(AS_context *ctx) {
    int ret = -1;
    NetworkAnalysisFunctions *nptr = NULL;
    FilterInformation *flt = NULL;

    // lets prepare incoming ICMP processing for our traceroutes
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL) goto end;

    // empty filter.. we want everything.
    FilterPrepare(flt, 0, 0);

    // add into network subsystem so we receive all packets
    if (Network_AddHook(ctx, flt, &CW_FindIP_Incoming) != 1) goto end;

    ret =  1;

    end:;
    return ret;
}



int main(int argc, char *argv[]) {
    AS_context *ctx = Antisurveillance_Init();
    char buf[1024];
    char *sptr = NULL;
    uint32_t ip = 0;
    PacketBuildInstructions *bptr = NULL;
    OutgoingPacketQueue *optr = NULL;
    int count = 0;
    int start = 0;
    uint32_t our_ip = get_local_ipv4();

    // input IPs to check
    FILE *fd = fopen("input_ip","r");
    // store which ones respond (they are NOT to be used)
    fd2 = fopen("output_ip","w");
    // initialize the module

    if (fd == NULL || fd2 == NULL) {
        fprintf(stderr, "couldnt open file\n");
        exit(-1);
    }

    // prepare the function above to receive packets
    Module_Add(ctx, &CW_FindIP_Init, NULL);

    while (fgets(buf,1024,fd)) {
        if ((sptr = strchr(buf,'\n')) != NULL) *sptr = 0;
        if ((sptr = strchr(buf,'\r')) != NULL) *sptr = 0;

        ip = inet_addr(buf);
        
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
    }

    // anytjing  left
    if (optr) OutgoingQueueLink(ctx, optr);

    // close input files
    fclose(fd);
    
    // process packets for 3 seconds
    start = time(0);
    while(1) {
        AS_perform(ctx);
        usleep(5000);

        if ((time(0) - start) > 3) break;
    }

    // done
    printf("Done. %d responded\n", r_count);

    // close output file
    fflush(fd2);
    fclose(fd2);

    exit(0);
}