#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <resolv.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <zlib.h>
#include <pthread.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include "network.h"
#include "antisurveillance.h"
#include "attacks.h"
#include "pcap.h"
#include "packetbuilding.h"
#include "instructions.h"
#include "utils.h"


// How many packets before we use pthreads to load the sessions?
#define MAX_SINGLE_THREADED 100000



// dump all outgoing queued network packets to a pcap file (to be viewed/analyzed, or played directly to the Internet)
// Changing to support PacketInfo (which will be raw packets from wire when we capture soon for quantum insert protection,
// etc)
int PcapSave(AS_context *ctx, char *filename, AttackOutgoingQueue *packets, PacketInfo *ipackets, int free_when_done) {    
    AttackOutgoingQueue *ptr = packets;
    AttackOutgoingQueue *qnext = NULL;

    PacketInfo *pptr = NULL;
    PacketInfo *pnext = NULL;
    pcap_hdr_t hdr;
    pcaprec_hdr_t packet_hdr;
    FILE *fd;
    struct timeval tv;
    struct ether_header ethhdr;
    int ts = 0;

    gettimeofday(&tv, NULL);

    ts = tv.tv_sec;

    // since we are just testinng how our packet looks fromm the generator.. lets just increase usec by 1
    char dst_mac[] = {1,2,3,4,5,6};
    char src_mac[] = {7,8,9,10,11,12};

    // zero these..
    memset((void *)&packet_hdr, 0, sizeof(pcaprec_hdr_t)); 
    memset((void *)&hdr, 0, sizeof(pcap_hdr_t));
    
    // prepare global header for the pcap file format
    hdr.magic_number = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.network = 1;//layer = ethernet

    // set ether header (enough for wireshark, tcpdump, or whatever)
    memset(&ethhdr, 0, sizeof(struct ether_header));
    ethhdr.ether_type = ntohs(ETHERTYPE_IP);
    memcpy((void *)&ethhdr.ether_dhost, dst_mac, 6);
    memcpy((void *)&ethhdr.ether_dhost, src_mac, 6);

    // open output file
    if ((fd = fopen(filename, "wb")) == NULL) return -1;
    
    // write the global header...
    fwrite((void *)&hdr, 1, sizeof(pcap_hdr_t), fd);

    // for each packet we have in the outgoing queue.. write it to disk
    while (ptr != NULL) {
        packet_hdr.ts_sec = ts;

        //packet_hdr.ts_usec += 200; 
        //packet_hdr.ts_sec = 0;

        packet_hdr.incl_len = ptr->size + sizeof(struct ether_header);
        packet_hdr.orig_len = ptr->size + sizeof(struct ether_header);

        fwrite((void *)&packet_hdr, 1, sizeof(pcaprec_hdr_t), fd);
        fwrite((void *)&ethhdr, 1, sizeof(struct ether_header), fd);
        fwrite((void *)ptr->buf, 1, ptr->size, fd);

        if (free_when_done) {
            PtrFree(&ptr->buf);

            qnext = ptr->next;
            
            PtrFree((char **)&ptr);

            ptr = qnext;
        } else {
            ptr = ptr->next;
        }

        //if (out_count++ > 1000) break;
    }

    while (pptr != NULL) {
        packet_hdr.ts_sec = ts;
        
        packet_hdr.incl_len = pptr->size + sizeof(struct ether_header);
        packet_hdr.orig_len = pptr->size + sizeof(struct ether_header);

        fwrite((void *)&packet_hdr, 1, sizeof(pcaprec_hdr_t), fd);
        fwrite((void *)&ethhdr, 1, sizeof(struct ether_header), fd);
        fwrite((void *)pptr->buf, 1, ptr->size, fd);

        if (free_when_done) {
            PtrFree(&pptr->buf);

            pnext = pptr->next;
            
            PtrFree((char **)&pptr);

            pptr = qnext;
        } else {
            pptr = pptr->next;
        }
                
    }

    fclose(fd);

    return 1;

}






// Load an old format (not NG) packet capture into PacketInfo structures to populate information required
// to perform an attack with the connections
PacketInfo *PcapLoad(char *filename) {
    FILE *fd = NULL;
    PacketInfo *ret = NULL, *pptr = NULL, *plast = NULL;
    pcap_hdr_t hdr;
    pcaprec_hdr_t packet_hdr;
    struct ether_header ethhdr;
    char *pkt_buf = NULL;
    int pkt_size = 0;

    if ((fd = fopen(filename, "rb")) == NULL) goto end;

    if (fread((void *)&hdr,1,sizeof(pcap_hdr_t), fd) != sizeof(pcap_hdr_t)) goto end;

    // pcapng format...
    if (hdr.magic_number == 0x0A0D0D0A) {
        //http://www.algissalys.com/network-security/pcap-vs-pcapng-file-information-and-conversion
        //editcap -F pcap <input-pcapng-file> <output-pcap-file>
        printf("Convert to pcap from pcapNG: http://www.algissalys.com/network-security/pcap-vs-pcapng-file-information-and-conversion\n");
        return NULL;
    }
    // check a few things w the header to ensure its processable
    if ((hdr.magic_number != 0xa1b2c3d4) || (hdr.network != 1)) {
        //printf("magic fail %X on pcap file\n", hdr.magic_number);
        goto end;
    }

    while (!feof(fd)) {
        // first read the packet header..
        fread((void *)&packet_hdr, 1, sizeof(pcaprec_hdr_t), fd);

        // be sure the size is acceptable
        if (!packet_hdr.incl_len || (packet_hdr.incl_len > packet_hdr.orig_len)) break;

        // read the ether header (for type 1 w ethernet layer)
        if (fread(&ethhdr, 1, sizeof(struct ether_header), fd) != sizeof(struct ether_header)) break;
        
        // calculate size of packet.. its the size of the packet minus the ether header
        pkt_size = packet_hdr.incl_len - sizeof(struct ether_header);

        // allocate space for the packets buffer
        if ((pkt_buf = (char *)malloc(pkt_size + 1)) == NULL) break;
        
        // read the full packet into that buffer
        if (fread((void *)pkt_buf, 1, pkt_size, fd) != pkt_size) break;

        // allocate a new packetinfo structure for this
        if ((pptr = (PacketInfo *)calloc(1, sizeof(PacketInfo))) == NULL) break;

        // set parameters in that new structure for other functions to analyze the data
        pptr->buf = pkt_buf;
        pptr->size = pkt_size;

        // link in the correct order to the list that will be returned to the caller..
        //L_link_ordered((LINK **)&ret, (LINK *)pptr);

        // i was loading hundreds of millions of packets, and it was extremely slow.. so i decided to do it this way ordered..
        if (plast != NULL)
            plast->next = pptr;
        else
            ret = pptr;

        plast = pptr;
    }

    end:;
    if (fd != NULL) fclose(fd);
    
    // return any packets we may have retrieved out of that pcap to the calling function
    return ret;
}



// Loads a PCAP file looking for a particular destination port (for example, www/80)
// and sets some attack parameters after it completes the process of importing it
int PCAPtoAttack(AS_context *ctx, char *filename, int dest_port, int count, int interval) {
    PacketInfo *packets = NULL;
    PacketBuildInstructions *packetinstructions = NULL;
    PacketBuildInstructions *final_instructions = NULL;
    FilterInformation flt;
    AS_attacks *aptr = NULL;
    AS_attacks *ret = NULL;
    int total = 0;
    //int start_ts = time(0);

    // load pcap file into packet information structures
    if ((packets = PcapLoad(filename)) == NULL) return 0;
    
    // turn those packet structures into packet building instructions via analysis, etc
    if ((packetinstructions = PacketsToInstructions(packets)) == NULL) goto end;

    printf("count: %d\n", L_count((LINK *)packetinstructions));
    
    // prepare the filter for detination port
    FilterPrepare(&flt, FILTER_PACKET_FAMILIAR|FILTER_SERVER_PORT, dest_port);
    
    // If its more than 100k lets use multiple threads to complete it faster
    if (L_count((LINK *)packetinstructions) > MAX_SINGLE_THREADED) {
        // for high amounts of connections.. we want to use pthreads..
        if ((aptr = ThreadedInstructionsFindConnection(ctx, &packetinstructions, &flt, 16, count, interval)) == NULL) goto end;
    
        total += L_count((LINK *)aptr);

        // it needs to be add ordered.. if we add it first in the list then it will cut off packets 2 -> end
        L_link_ordered((LINK **)&ctx->attack_list,(LINK *) aptr);
    } else {
        // loop and load as many of this type of connection as possible..
        while (1) {
            final_instructions = NULL;

            // find the connection for some last minute things required for building an attack
            // from the connection
            if ((final_instructions = InstructionsFindConnection(&packetinstructions, &flt)) == NULL) goto end;
        
            if (final_instructions == NULL) break;

            // create the attack structure w the most recent filtered packet building parameters
            if ((aptr = InstructionsToAttack(ctx, final_instructions, count, interval)) == NULL) goto end;

            // add to the attack list being executed now
            aptr->next = ctx->attack_list;
            ctx->attack_list = aptr;

            total++;
        }
    }

    // if it all worked out...
    ret = aptr;

    //printf("perfecto we generated an attack directly from a packet capture..\n%d count\n", total);
    end:;
    //printf("\r\nTime to load full file: %d\n", time(0) - start_ts);
    PacketsFree(&packets);

    PacketBuildInstructionsFree(&packetinstructions);

    if (ret == NULL)
        PacketBuildInstructionsFree(&final_instructions);

    return total;
}