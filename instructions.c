#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <errno.h>  
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "utils.h"
#include "attacks.h"
#include "instructions.h"
#include "adjust.h"


#define MAX_THREAD 16



void FilterPrepare(FilterInformation *fptr, int type, uint32_t value) {
    if (fptr->init != 0xAABBCCDD) {
        memset((void *)fptr, 0, sizeof(FilterInformation));
        fptr->init = 0xAABBCCDD;
    }

    // does this filter allow looking for specific packet propertieS? like SYN/ACK/PSH/RST
    if (type & FILTER_PACKET_FLAGS) {
        fptr->flags |= FILTER_PACKET_FLAGS;
        fptr->packet_flags = value;
    }

    // will it look for both sides of the connection? ie: port 80 would allow stuff from server to client as well
    if (type & FILTER_PACKET_FAMILIAR) {
        fptr->flags |= FILTER_PACKET_FAMILIAR;
    }

    // does the IP address match?
    if (type & FILTER_CLIENT_IP) {
        fptr->flags |= FILTER_CLIENT_IP;
        fptr->source_ip = value;
    }

    // does the server IP match?
    if (type & FILTER_SERVER_IP) {
        fptr->flags |= FILTER_SERVER_IP;
        fptr->destination_ip = value;
    }

    // does the server port match?
    if (type & FILTER_SERVER_PORT) {
        fptr->flags |= FILTER_SERVER_PORT;
        fptr->destination_port = value;
    }

    // does the source port (usually random on client) match?
    if (type & FILTER_CLIENT_PORT) {
        fptr->flags |= FILTER_CLIENT_PORT;
        fptr->source_port = value;
    }
}


// Filters through packets ensuring that it matches a criteria of something being looked for..
int FilterCheck(FilterInformation *fptr, PacketBuildInstructions *iptr) {
    int ret = 0;

    //return 1;

    // if the filter is empty... its allowed
    if (fptr->flags == 0 || fptr->init != 0xAABBCCDD) return 1;

    // verify client IP
    if (fptr->flags & FILTER_CLIENT_IP)
        if (iptr->source_ip != fptr->source_ip)
            if (!(fptr->flags & FILTER_PACKET_FAMILIAR) ||
             ((fptr->flags & FILTER_PACKET_FAMILIAR) && (iptr->destination_ip != fptr->source_ip)))
                goto end;

    // verify server IP
    if (fptr->flags & FILTER_SERVER_IP)
        if (iptr->destination_ip != fptr->destination_ip)
            if (!(fptr->flags & FILTER_PACKET_FAMILIAR) ||
             ((fptr->flags & FILTER_PACKET_FAMILIAR) && (iptr->source_ip != fptr->destination_ip)))
                goto end;

    // verify server port (for instance www 80)
    if (fptr->flags & FILTER_SERVER_PORT)
        if (iptr->destination_port != fptr->destination_port)
            if (!(fptr->flags & FILTER_PACKET_FAMILIAR) ||
             ((fptr->flags & FILTER_PACKET_FAMILIAR) && (iptr->source_port != fptr->destination_port)))
                goto end;
    
    // verify client source port
    if (fptr->flags & FILTER_CLIENT_PORT)
        if (iptr->source_port != fptr->source_port)
            if (!(fptr->flags & FILTER_PACKET_FAMILIAR) ||
             ((fptr->flags & FILTER_PACKET_FAMILIAR) && (iptr->destination_port != fptr->source_port)))
                goto end;

    // looking for a specific type of packet by its flags..
    if (fptr->flags & FILTER_PACKET_FLAGS) {
        if (fptr->packet_flags & TCP_FLAG_SYN)
            if (!(iptr->flags & TCP_FLAG_SYN)) goto end;
        if (fptr->packet_flags & TCP_FLAG_ACK)
            if (!(iptr->flags & TCP_FLAG_ACK)) goto end;
        if (fptr->packet_flags & TCP_FLAG_PSH)
            if (!(iptr->flags & TCP_FLAG_PSH)) goto end;
        if (fptr->packet_flags & TCP_FLAG_FIN)
            if (!(iptr->flags & TCP_FLAG_FIN)) goto end;
        if (fptr->packet_flags & TCP_FLAG_RST)
            if (!(iptr->flags & TCP_FLAG_RST)) goto end;
    }

    ret = 1;

    end:;
    return ret;
}







// creates the base structure for instruction to build a for the wire packet..
PacketBuildInstructions *BuildInstructionsNew(PacketBuildInstructions **list, uint32_t source_ip, uint32_t destination_ip, int source_port, int dst_port, int flags, int ttl) {
    PacketBuildInstructions *bptr = NULL;

    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) return NULL;

    bptr->source_ip = source_ip;
    bptr->source_port = source_port;

    bptr->destination_ip = destination_ip;
    bptr->destination_port = dst_port;

    bptr->flags = flags;
    bptr->ttl = ttl;

    // this relates to operating system emulation.. i'll get the variable here soon
    // ***
    // pcap uses its own allocator to be quicker (instead of the ordered below) so this wont affect it..
    bptr->tcp_window_size = 1500;

    // FIFO ordering
    L_link_ordered((LINK **)list, (LINK *)bptr);

    return bptr;
}





// Generates instructions for fabricating a TCP connection being opened between two hosts..
int GenerateTCP4ConnectionInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    int packet_flags = 0;
    int packet_ttl = 0;
    int ret = -1;

    // first we need to generate a connection syn packet..
    packet_flags = TCP_FLAG_SYN|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW;
    packet_ttl = cptr->client_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, cptr->client_ip, cptr->server_ip, cptr->client_port, cptr->server_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = cptr->client_identifier++;
    bptr->client = 1; // so it can generate source port again later... for pushing same messages w out full reconstruction
    bptr->ack = 0;
    bptr->seq = cptr->client_seq++;  

    // then nthe server needs to respond acknowledgng it
    packet_flags = TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW;
    packet_ttl = cptr->server_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, cptr->server_ip, cptr->client_ip, cptr->server_port, cptr->client_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = cptr->server_identifier++;
    bptr->ack = cptr->client_seq;
    bptr->seq = cptr->server_seq++;

    // then the client must respond acknowledging that servers response..
    packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = cptr->client_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, cptr->client_ip, cptr->server_ip, cptr->client_port, cptr->server_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->header_identifier = cptr->client_identifier++;
    bptr->client = 1;
    bptr->ack = cptr->server_seq;
    bptr->seq = cptr->client_seq;

    L_link_ordered((LINK **)final_build_list, (LINK *)build_list);

    return 1;
    err:;
    return ret;
}




// Generates the instructions for the fabrication of TCP data transfer between two hosts
// Its general enough to be used with binary protocols, and supports client or server side to opposite

// notes from old HTTP building function: (i want to support packet loss over a large amount of sessions soon.. even if 1-5%)
// later we can emulate some packet loss in here.. its just  random()%100 < some percentage..
// with a loop resending the packet.. super simple to handle.  we can also falsify other scenarios
// involving ICMP etc.. some very nasty tricks coming.  
int GenerateTCP4SendDataInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list, int from_client, char *data, int size) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    int packet_flags = 0;
    int packet_size;
    char *data_ptr = data;
    int data_size = size;
    int packet_ttl = 0;
    uint32_t source_ip;
    uint32_t source_port;
    uint32_t dest_ip;
    uint32_t dest_port;
    uint32_t *src_identifier = NULL;
    uint32_t *dst_identifier = NULL;
    uint32_t *my_seq = NULL;
    uint32_t *remote_seq = NULL;

    // prepare variables depending on the side of the that the data is going from -> to
    if (from_client) {
        source_ip = cptr->client_ip;
        source_port = cptr->client_port;
        dest_ip = cptr->server_ip;
        dest_port = cptr->server_port;
        src_identifier = &cptr->client_identifier;
        dst_identifier = &cptr->server_identifier;
        my_seq = &cptr->client_seq;
        remote_seq = &cptr->server_seq;
    } else {
        source_ip = cptr->server_ip;
        source_port = cptr->server_port;
        dest_ip = cptr->client_ip;
        dest_port = cptr->client_port;
        src_identifier = &cptr->server_identifier;
        dst_identifier = &cptr->client_identifier;
        my_seq = &cptr->server_seq;
        remote_seq = &cptr->client_seq;
    }


    // now the sending side must loop until it sends all daata
    while (data_size > 0) {
        packet_size = min(data_size, from_client ? cptr->max_packet_size_client : cptr->max_packet_size_server);

        // if something wasn't handled properly.. (when i turned off OSPick().. i had to search for hours to find this =/)
        if (packet_size < 0) return -1;

        // the client sends its request... split into packets..
        packet_flags = TCP_FLAG_PSH|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        packet_ttl = from_client ? cptr->client_ttl : cptr->server_ttl;
        if ((bptr = BuildInstructionsNew(&build_list, source_ip, dest_ip, source_port, dest_port, packet_flags, packet_ttl)) == NULL) goto err;
        if (DataPrepare(&bptr->data, data_ptr, packet_size) != 1) goto err;
        bptr->data_size = packet_size;
        bptr->header_identifier = (*src_identifier)++;
        bptr->client = from_client;
        bptr->ack = *remote_seq;
        bptr->seq = *my_seq;
    
        *my_seq += packet_size;
        data_size -= packet_size;
        data_ptr += packet_size;

        // receiver sends ACK packet for this packet
        packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
        packet_ttl = from_client ? cptr->server_ttl : cptr->client_ttl;
        if ((bptr = BuildInstructionsNew(&build_list, dest_ip, source_ip, dest_port, source_port, packet_flags, packet_ttl)) == NULL) goto err;
        bptr->header_identifier = (*dst_identifier)++;
        bptr->ack = *my_seq;
        bptr->seq = *remote_seq;
        bptr->client = !from_client;

    }

    L_link_ordered((LINK **)final_build_list, (LINK *)build_list);


    return 1;
    err:;
    return 0;
}



// Generates fabricated packets required to disconnect a TCP session between two hosts.. starting with one side (client or server)
int GenerateTCP4CloseConnectionInstructions(ConnectionProperties *cptr, PacketBuildInstructions **final_build_list, int from_client) {
    PacketBuildInstructions *bptr = NULL;
    PacketBuildInstructions *build_list = NULL;
    int packet_flags = 0;
    //int packet_size = 0;

    uint32_t source_ip=0;
    uint32_t source_port=0;
    uint32_t dest_ip=0;
    uint32_t dest_port=0;
    uint32_t *src_identifier = NULL;
    uint32_t *dst_identifier = NULL;
    uint32_t *my_seq = NULL;
    uint32_t *remote_seq = NULL;
    int packet_ttl = 0;

    // prepare variables depending on the side of the that the data is going from -> to
    if (from_client) {
        source_ip = cptr->client_ip;
        source_port = cptr->client_port;
        dest_ip = cptr->server_ip;
        dest_port = cptr->server_port;
        src_identifier = &cptr->client_identifier;
        dst_identifier = &cptr->server_identifier;
        my_seq = &cptr->client_seq;
        remote_seq = &cptr->server_seq;
    } else {
        source_ip = cptr->server_ip;
        source_port = cptr->server_port;
        dest_ip = cptr->client_ip;
        dest_port = cptr->client_port;
        src_identifier = &cptr->server_identifier;
        dst_identifier = &cptr->client_identifier;
        my_seq = &cptr->server_seq;
        remote_seq = &cptr->client_seq;
    }


    // source (client or server) sends FIN packet...
    packet_flags = TCP_FLAG_FIN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = from_client ? cptr->client_ttl : cptr->server_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, source_ip, dest_ip, source_port, dest_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->client = from_client;
    bptr->header_identifier =  (*src_identifier)++;
    bptr->ack = *remote_seq;
    bptr->seq = (*my_seq)++;
    
    
    
    // other side needs to respond..adds its own FIN with its ACK
    packet_flags = TCP_FLAG_FIN|TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = from_client ? cptr->server_ttl : cptr->client_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, dest_ip, source_ip, dest_port, source_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->client = !from_client;
    bptr->header_identifier = (*dst_identifier)++;
    bptr->ack = *my_seq;
    bptr->seq = (*remote_seq)++;
    


    // source (client or server) sends the final ACK packet...
    packet_flags = TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP;
    packet_ttl = from_client ? cptr->client_ttl : cptr->server_ttl;
    if ((bptr = BuildInstructionsNew(&build_list, source_ip, dest_ip, source_port, dest_port, packet_flags, packet_ttl)) == NULL) goto err;
    bptr->client = from_client;
    bptr->header_identifier = (*src_identifier)++;
    bptr->ack = *remote_seq;
    bptr->seq = *my_seq;
    

    L_link_ordered((LINK **)final_build_list, (LINK *)build_list);

    return 1;
    err:;
    return 0;
}





// Process sessions from a pcap packet capture into building instructions to replicate, and massively replay
// those sessions :) BUT with new IPs, and everything else required to fuck shit up.
PacketBuildInstructions *PacketsToInstructions(PacketInfo *packets) {
    PacketBuildInstructions *ret = NULL;
    PacketBuildInstructions *list = NULL, *llast = NULL;
    PacketBuildInstructions *iptr = NULL;
    PacketInfo *pptr = NULL;
    struct packet *p = NULL;
    int flags = 0;
    int data_size = 0;
    char *data = NULL;
    char *sptr = NULL;
    uint16_t pkt_chk = 0;
    struct pseudo_tcp *p_tcp = NULL;
    char *checkbuf = NULL;
    int tcp_header_size = 0;

    pptr = packets;

    while (pptr != NULL) {
        // set structure for reading information from this packet
        p = (struct packet *)pptr->buf;

        // be sure its ipv4..
        if (p->ip.version == 4) {

            /*

            if (p->ip.protocol == IPPROTO_ICMP) {

            }

            if (p->ip.protocol == IPPROTO_UDP) {

            }

            */

            // for processing IPv4 TCP
            if (p->ip.protocol == IPPROTO_TCP) {
                flags = 0;
                if (p->tcp.syn) flags |= TCP_FLAG_SYN;
                if (p->tcp.ack) flags |= TCP_FLAG_ACK;
                if (p->tcp.psh) flags |= TCP_FLAG_PSH;
                if (p->tcp.fin) flags |= TCP_FLAG_FIN;
                if (p->tcp.rst) flags |= TCP_FLAG_RST;

                // Lets do this here.. so we can append it to the list using a jump pointer so its faster
                // was taking way too long loading a 4gig pcap (hundreds of millions of packets)
                if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) goto end;

                // ensure the type is set
                iptr->type = PACKET_TYPE_TCP_4;

                if (llast == NULL)
                    list = llast = iptr;
                else {
                    llast->next = iptr;
                    llast = iptr;
                }

                // source IP, and port from the IP/TCP headers
                iptr->source_ip = p->ip.saddr;
                iptr->source_port = ntohs(p->tcp.source);
                
                // destination IP, and port from the TCP/IP headers
                iptr->destination_ip = p->ip.daddr;
                iptr->destination_port = ntohs(p->tcp.dest);
                
                // TCP/IP flags..
                iptr->flags = flags;

                // IP packet TTL (time to live)..  (OS emu)
                iptr->ttl = p->ip.ttl;

                // TCP window size (OS emu)
                iptr->tcp_window_size = ntohs(p->tcp.window);

                // start OK.. until checksum.. or disqualify for other reasons
                iptr->ok = 1;

                // total size from IPv4 header
                data_size = ntohs(p->ip.tot_len);

                // subtract header size from total packet size to get data size..
                data_size -= (p->ip.ihl << 2) + (p->tcp.doff << 2);

                if (data_size > 0) {
                    // allocate memory for the data
                    if ((data = (char *)malloc(data_size + 1)) == NULL) {
                        goto end;
                    }

                    // pointer to where the data starts in this packet being analyzed
                    sptr = (char *)(pptr->buf + ((p->ip.ihl << 2) + (p->tcp.doff << 2)));

                    // copy into the newly allocated buffer the tcp/ip data..
                    memcpy(data, sptr, data_size);

                    // ensure the instructions structure has this new pointer containing the data
                    iptr->data = data;
                    data = NULL; // so we dont free it below..
                    iptr->data_size = data_size;

                    
                }

                // lets move the packet buffer into this new instruction structure as well
                // *** if we have no use for this later.. remove it (or let it get freed inside of the packetinfo structure)
                iptr->packet = pptr->buf;
                pptr->buf = NULL;
                iptr->packet_size = pptr->size;
                pptr->size = 0;

                // header identifier from IP header
                iptr->header_identifier = ntohs(p->ip.id);

                // ack/seq are important for tcp/ip (used to transmit lost packets, etc)
                // in future for quantum insert protection it will be important as well...
                iptr->seq = ntohl(p->tcp.seq);
                iptr->ack = ntohl(p->tcp.ack_seq);

                // start checksum...
                // get tcp header size (so we know if it has options, or not)
                tcp_header_size = p->tcp.doff << 2;
        
                // start of packet checksum verifications
                // set a temporary buffer to the packets IP header checksum
                pkt_chk = p->ip.check;

                // set packets IP checksum to 0 so we can calculate and verify here
                p->ip.check = 0;

                // calculate what it should be
                p->ip.check = (unsigned short)in_cksum((unsigned short *)&p->ip, IPHSIZE);
                // verify its OK.. if not mark this packet as bad (so we can verify how many bad/good and decide
                // on discarding or not)

                // this is failing! fix!
                if (p->ip.check != pkt_chk) iptr->ok = 0;

                // lets put the IP header checksum back
                p->ip.check = pkt_chk;

                // now lets verify TCP header..
                // copy the packets header..
                pkt_chk = p->tcp.check;

                // set the packet header to 0 so we can calculate it like an operatinng system would
                p->tcp.check = 0;

                // it needs to be calculated with a special pseudo structure..
                checkbuf = (char *)calloc(1,sizeof(struct pseudo_tcp) + tcp_header_size + iptr->data_size + iptr->options_size);
                if (checkbuf == NULL) goto end;

                // code taken from ipv4 tcp packet building function
                p_tcp = (struct pseudo_tcp *)checkbuf;
                
                // set psuedo header parameters for calculating checksum
                p_tcp->saddr 	= p->ip.saddr;
                p_tcp->daddr 	= p->ip.daddr;
                p_tcp->mbz      = 0;
                p_tcp->ptcl 	= IPPROTO_TCP;
                p_tcp->tcpl 	= htons(tcp_header_size + iptr->data_size);
        
                // copy tcp header into the psuedo structure
                memcpy(&p_tcp->tcp, &p->tcp, tcp_header_size);

                // copy tcp/ip options into its buffer
                if (iptr->options_size)
                    memcpy(checkbuf + sizeof(struct pseudo_tcp), iptr->options, iptr->options_size);

                // now copy the data itself of the packet
                if (iptr->data_size) {
                    //printf("has data header %d opt %d data %p data size %d\n",tcp_header_size, iptr->options_size, iptr->data, iptr->data_size);
                    memcpy(checkbuf + sizeof(struct pseudo_tcp) + iptr->options_size, iptr->data, iptr->data_size);        
                }
        
                // put the checksum into the correct location inside of the header
                p->tcp.check = (unsigned short)in_cksum((unsigned short *)checkbuf, tcp_header_size + PSEUDOTCPHSIZE + iptr->data_size + iptr->options_size);
        
                // free that buffer
                free(checkbuf);

                // TCP header verification failed
                // *** this is failing!
                if (p->tcp.check != pkt_chk) {
                    printf("TCP checksum failed!\n");
                    //iptr->ok = 0;
                }

                // put the original value back
                p->tcp.check = pkt_chk;
                // done w checksums..

                // moved other analysis to the next function which builds the attack structure
            }
            
        }

        // move on to the next element in the list of packets
        pptr = pptr->next;
    }

    ret = list;

    /*
    iptr = list;
    while (iptr != NULL) {
        printf("%d:%d -> %d:%d %p %d\n", iptr->source_ip, iptr->source_port, iptr->destination_ip,
            iptr->destination_port, iptr->data, iptr->data_size);   

        iptr = iptr->next;
    }*/


    end:;


    // if something got us here without ret, and some list.. remove it
    if (ret == NULL && list != NULL) {
        PacketBuildInstructionsFree(&list);
    }

    PtrFree(&data);

    // this gets freed on calling function.. since a pointer to the pointer (to mark as freed) wasnt passed
    //PacketsFree(&packets);

    return ret;
}



// This will filter the main list of information from PacketsToInstructions() by ports, or IPs and then
// return those connections separately..
// It is loopable, and it used to load an entire PCAP in a different function.
// However.. when given millions of packets.. I believe its too slow.
// In progress: divide & conquer.. ill create several threads (which could easily be branched into processes)
// which could only return packets whiich can be verified last.. for example if 2 threads have packets from a session
PacketBuildInstructions *InstructionsFindConnection(PacketBuildInstructions **instructions, FilterInformation *flt) {
    PacketBuildInstructions *iptr = *instructions;
    PacketBuildInstructions *ilast = NULL, *inext = NULL;
    uint32_t src_ip=0, dst_ip=0;
    uint16_t src_port=0, dst_port=0;
    PacketBuildInstructions *packets = NULL;
    PacketBuildInstructions *ret = NULL;
    FilterInformation fptr;
    int got_fin_ack = 0;
    //int count = 0, ccount = 0, fcount = 0;

    //printf("InstructionsFindConnection count of incoming packets: %d\n", L_count((LINK *)iptr));

    if (flt == NULL)
        // default filter is port 80 (www) both sides of the packets...
        FilterPrepare(&fptr, FILTER_SERVER_PORT|FILTER_PACKET_FAMILIAR, 80);
    

    // enumerate all instruction packets
    while (iptr != NULL) {
        //count++;

        // no point in replaying bad checksum packets...
        if (iptr->ok != 0) {
            // make sure it matches our filter (right now hard coded for www)
            if (FilterCheck(flt ? flt : &fptr, iptr)) {
                //fcount++; // filter couont..
            
                //printf("passed pass filter  %d:%d -> %d:%d data %p data size %d %X %X flags\n", src.s_addr, iptr->source_port, dst.s_addr, iptr->destination_port, iptr->data, iptr->data_size, iptr->header_identifier, iptr->flags);

                // a SYN packet with an ACK of 0 should be the first connecting packet
                if (!src_ip && !dst_ip && !src_port && !dst_port) {
                    if ((iptr->flags & TCP_FLAG_SYN) && iptr->ack == 0) {
                        // grab the IP addresses, and ports from packet.. we will use as a reference to find the connection
                        src_ip = iptr->source_ip;
                        dst_ip = iptr->destination_ip;
                        src_port = iptr->source_port;
                        dst_port = iptr->destination_port;
                    }
                }

                // is it the same connection?
                if (((src_port == iptr->source_port) && (dst_port == iptr->destination_port)) ||
                    ((src_port == iptr->destination_port) && (dst_port == iptr->source_port))) {
                        //printf("%d:%d -> %d:%d data %p data size %d\n", src.s_addr, iptr->source_port, dst.s_addr, iptr->destination_port, iptr->data, iptr->data_size);
                        // if its coming from the source IP we found as an initial SYN.. its the client
                        if (iptr->source_port == src_port) {
                            //ccount++;
                            iptr->client = (iptr->source_port == src_port);
                        }

                        // get the next packets pointer..
                        inext = iptr->next;
                        
                        // remove from the list it arrived in.. so we can put into another list which only contains
                        // a single connection
                        if (*instructions == iptr)
                            *instructions = inext;
                        else
                            ilast->next = inext;

                        // we dont want ths packet going to the next one as it arrived..
                        iptr->next = NULL;

                        // put to linked list in order
                        L_link_ordered((LINK **)&packets, (LINK *)iptr);

                        // RST + ACK = last packet.. in the millions of packets it was slow-er without this...
                        // turned this off.. it was leaving 2 more packets.. rewrite

                        // this got messy fast.. rewrite (have another func to look into future packets for the final)
                        if (got_fin_ack == 0) {
                            if ((iptr->flags & TCP_FLAG_FIN) && (iptr->flags & TCP_FLAG_ACK)) {
                                got_fin_ack = 1;
                                //printf("Found last packet.. FIN|ACK\n");
                                //break;
                            }
                        } else if (got_fin_ack == 1) {
                                if ((iptr->flags & TCP_FLAG_ACK)) {
                                    got_fin_ack++;
                                }
                        } else if (got_fin_ack == 2) break;
                            
                        // time to process the next
                        iptr = inext;

                        //ccount++;

                        continue;
                    }
                }
            } /*else {
                printf("Didnt pass filter  %d:%d -> %d:%d data %p data size %d %X\n", src.s_addr, iptr->source_port, dst.s_addr, iptr->destination_port, iptr->data, iptr->data_size, iptr->header_identifier);
            }*/

        // set this packet as the last.. so in future the connections can be unlinked from their original list
        ilast = iptr;

        // time to process the next
        iptr = iptr->next;
    }

    ret = packets;
/*
    printf("-----------------\n");
    printf("done func %d client count %d filter count %d\n", count, ccount, fcount);
    printf("-----------------\n");
*/
    return ret;
}



// information each thread requires to process its information
typedef struct _thread_packet_analysis {
    pthread_t ThreadHandle;
    pthread_mutex_t Mutex;
    FilterInformation *Filter;
    PacketBuildInstructions **incoming_list;
    PacketBuildInstructions *IncomingPtr;
    PacketBuildInstructions **connection_list;
    PacketBuildInstructions *ConnectionPtr;
    int start_ts;
    int incoming_count;
    int outgoing_count;
    int completed;
    AS_attacks *attacks;
    AS_context *ctx;

    // how many times to replay this as an attack?
    int replay_count;
    // how many seconds interval in between?
    int interval;
} ThreadPktAnalysisDetails;

// A function for each thread to loop and find all connections which match a Filter and creating
// attack structures for them... returning the attack structure linked list of them all to get
// merged into the applications list along with each other thread being processed
// *** todo: set these threads as low priority so when together w scripting etc it wont affect
// current attacks
void *thread_packet_analysis(void *arg) {
    int count = 0;
    ThreadPktAnalysisDetails *details = (ThreadPktAnalysisDetails *)arg;
    PacketBuildInstructions *cptr = NULL;
    AS_attacks *aptr = NULL;
    
    pthread_mutex_lock(&details->Mutex);

    details->start_ts = time(0);    

    while (1) {
        if ((cptr = InstructionsFindConnection(details->incoming_list, details->Filter)) == NULL) break;
        if ((aptr = InstructionsToAttack(details->ctx, cptr, details->replay_count, details->interval)) == NULL) break;

        aptr->next = details->attacks;
        details->attacks = aptr;

        count++;
    }

    // how many packets does the connection we found have IF any..
    details->outgoing_count = count;
    details->completed =  1;

    pthread_mutex_unlock(&details->Mutex);

    pthread_exit(NULL);
}


// This should be run whenever you have more than a 100k or so sessions...
PacketBuildInstructions *ThreadedInstructionsFindConnection(AS_context *ctx, PacketBuildInstructions **instructions, FilterInformation *flt, int threads, int replay_count, int interval) {
    ThreadPktAnalysisDetails ThreadAnalysisDetails[MAX_THREAD];
    PacketBuildInstructions *ThreadInstructions[MAX_THREAD];
    PacketBuildInstructions *SplitInstructions[MAX_THREAD];
    int count = 0, split = 0, i = 0, n = 0, in_count = 0;
    PacketBuildInstructions *iptr = NULL;
    PacketBuildInstructions *inext = NULL;
    PacketBuildInstructions *startiptr = NULL;
    PacketBuildInstructions *leftover = NULL;
    PacketBuildInstructions *ret = NULL;

    // if no threads were passed.. lets set for 2
    if (threads <= 0) threads = 2;
    // if its more than the max.. lets set to the max
    if (threads > MAX_THREAD) threads = MAX_THREAD;

    // ensure the stack structures in this local function are all zero'd
    memset((void **)&ThreadInstructions, 0, sizeof(PacketBuildInstructions *) * MAX_THREAD);
    memset((void *)&ThreadAnalysisDetails, 0, sizeof(ThreadPktAnalysisDetails) * MAX_THREAD);
    memset((void **)&SplitInstructions, 0, sizeof(PacketBuildInstructions *) * MAX_THREAD);

    // make sure the calling function passed packets correctly
    if ((count = L_count((LINK *)*instructions)) <= 0) return ret; // NULL right here..

    // how many do we delegate to each thread from the incoming list?
    split = count / threads;

    // prepare pointers for enumeration
    iptr = startiptr = *instructions;

    // loop and create threads separated by 'split' amount
    for (i = 0; i < threads; i++) {
        if (iptr == NULL) break;
        startiptr = iptr;

        // split X items to determine the last packet...
        n = split;
        in_count = 0;
        while (n-- && iptr->next != NULL) {
            in_count++;
            iptr = iptr->next;
        }

        // curptr = where to start on the next iteration
        inext = iptr->next;

        // stop this fromm going to next temporarily so its divided for processing
        iptr->next = NULL;

        // move to next..
        iptr = inext;

        // lets fix up the thread information...
        ThreadAnalysisDetails[i].incoming_count = in_count;
        ThreadAnalysisDetails[i].IncomingPtr = startiptr;
        ThreadAnalysisDetails[i].incoming_list = &ThreadAnalysisDetails[i].IncomingPtr;
        ThreadAnalysisDetails[i].Filter = flt;
        ThreadAnalysisDetails[i].replay_count = replay_count;
        ThreadAnalysisDetails[i].interval = interval;
        ThreadAnalysisDetails[i].ctx = ctx;

        // initializze mutex
        pthread_mutex_init(&ThreadAnalysisDetails[i].Mutex, NULL);  

        // create thread passing it the information required to process its section of packets
        if (pthread_create(&ThreadAnalysisDetails[i].ThreadHandle, NULL, &thread_packet_analysis, (void *)&ThreadAnalysisDetails[i]) != 0) {
            // maybe execute blocking here or .. we can just ignore...
            break;
        }
    }

    // We need to loop a second time waiting for each thread to complete...
    // This COULD be threeaded off itself, and merge into the attack list later..
    // Update this later once scripting is completed.. to allow control from
    // another mechanism
    for (i = 0; i < threads; i++) {        
        // be sure we even started this thread...
        if (!ThreadAnalysisDetails[i].incoming_count) continue;

        // lock means we will wait until that thread completes...
        pthread_mutex_lock(&ThreadAnalysisDetails[i].Mutex);

        // join pthread (in case its required to free resources..)
        pthread_join(ThreadAnalysisDetails[i].ThreadHandle, NULL);

        // did it not get marked as completed? weird..
        if (ThreadAnalysisDetails[i].completed == 1) {
            // Add attacks if any connections were found...
            if (ThreadAnalysisDetails[i].attacks != NULL) {
                L_link_ordered((LINK **)&ctx->attack_list, (LINK *)ThreadAnalysisDetails[i].attacks);
            }
        }

        // Link all leftovers from each thread together...
        L_link_ordered((LINK **)&leftover, (LINK *)ThreadAnalysisDetails[i].IncomingPtr);

    }

    // all connections left over gets moved to this pointer for the calling function
    // we should attempt one last retry here with the non threaded function
    // just in case some session was across multiple packets...
    // maybe keep track of whether or not a session had a SYN -> FIN/RST full session
    ret = leftover;
    
    return ret;
}



// Takes the single connection packet instructions from InstructionsFindConnection() and creates an attack structure
// around it so that it initializes an attack with its parameters
AS_attacks *InstructionsToAttack(AS_context *ctx, PacketBuildInstructions *instructions, int count, int interval) {
    PacketBuildInstructions *iptr = instructions;
    AS_attacks *aptr = NULL;
    AS_attacks *ret = NULL;
    int found_start = 0;
    PacketBuildInstructions *Packets[16];
    PacketBuildInstructions *pptr = NULL;
    int Current_Packet = 0;
    int found_seq = 0;
    int i = 0;

    // ensure that packet array if ZERO for later...
    memset((void *)&Packets, 0, sizeof(PacketBuildInstructions *) * 16);

    // allocate space for this new structure being built
    if ((aptr = (AS_attacks *)calloc(1,sizeof(AS_attacks))) == NULL) goto end;

    // ensure it knows which context it belongs to
    aptr->ctx = ctx;

    // *** find a way to set IDs.. first byte can show where it has come from, etc
    // Attack Identifier (for management)
    aptr->id = rand()%0xFFFFFFFF;

    // initialize and lock mutex for this new attack entry
    pthread_mutex_init(&aptr->pause_mutex, NULL);    
    pthread_mutex_lock(&aptr->pause_mutex);

    // this is used for awaiting GZIP compression attack
    aptr->paused = 1;

    // we can get more specific later..
    // esp when replaying DNS (UDP).. TCP4, ICMP and other protocols all together..
    aptr->type = ATTACK_SESSION;

    // set instructions list inside of the attack structure.. 
    aptr->packet_build_instructions = instructions;

    // we need to find a few things... base server/client seq
    // loop through them if we need something from there..    
    while (iptr != NULL) {
        //printf("iptr data %p size %d\n", iptr->data, iptr->data_size);
        if (!found_start) {
            // if its set as a client from the last function which created these structures, and its a SYN packet..
            // then its the first
            if (iptr->client && (iptr->flags & TCP_FLAG_SYN)) {
                aptr->src = iptr->source_ip;
                aptr->dst = iptr->destination_ip;
                aptr->source_port = iptr->source_port;
                iptr->destination_port = iptr->destination_port;

                aptr->dst = iptr->destination_ip;
                aptr->src = iptr->source_ip;
                
                found_start = 1;
            }
        }

        // maybe rewrite this later... i'd like to process more information about connections
        // but i do beieve this will work for now.
        if (!found_seq) {
            // SYN / ACK are good for finding the base seqs because it only gets incresed by 1
            if ((iptr->flags & TCP_FLAG_ACK) && !(iptr->flags & TCP_FLAG_SYN)) {
                // if this is an ACK but not a SYN.. its accepting the connection..
                // we want to find the other before it!
                pptr = Packets[(Current_Packet - 1) % 16];
                // scan at most prior 16 packets looking for ACK/SEQ
                for (i = 1; i < 15; i++) {
                    pptr = Packets[i % 16];
                    if (pptr != NULL) {
                        // be sure its the same connection
                        if ((pptr->source_ip == iptr->destination_ip))
                            // the packet before (SYN packet) should have an ACK of 0 since its new... and it has SYN flag
                            if ((pptr->ack == 0) && (iptr->flags & TCP_FLAG_SYN) & (iptr->flags & TCP_FLAG_ACK)) {
                                // this is the one where we get the clients base seq
                                aptr->client_base_seq = pptr->seq;

                                // and the current packet that we found (ACK'ing the SYN) is the server's base seq
                                aptr->server_base_seq = iptr->ack;

                                found_seq = 1;
                                break;
                            }
                    }
                }
                
            }

            // future analysis go here.. using Packets array for packets before whichever

            // most temporary we hold is 16.. we just keep rotating using mod
            Packets[Current_Packet++ % 16] = iptr;
        }

        iptr = iptr->next;
    }

    //iptr->ts = time(0); // we dont set time so itll activate immediately..
    aptr->count = count;
    // lets repeat this connection once every 10 seconds
    aptr->repeat_interval = interval;

    // successful...
    ret = aptr;


    // lets initialize our adjustments so its different from the input
    PacketAdjustments(aptr);

    // unpause...
    aptr->paused = 0;
    
    // the calling function can handle putting it into the actual attack list..
    
    end:;

    if (aptr) pthread_mutex_unlock(&aptr->pause_mutex);

    // something happened before we successfully set the return  pointer.. free everything
    // we allocated
    if (!ret && aptr) {
        // this was passed to us.. so dont free it
        aptr->packet_build_instructions = NULL;

        // free any other structures that were created..
        AttackFreeStructures(aptr);

        PtrFree((char **)&aptr);
    }

    return ret;
}


// clean up the structures used to keep information requira ed for building the low level network packets
void PacketBuildInstructionsFree(PacketBuildInstructions **list) {  
    PacketBuildInstructions *iptr = *list, *inext = NULL;

    while (iptr != NULL) {
        PtrFree(&iptr->data);
        iptr->data_size = 0;

        PtrFree(&iptr->packet);
        iptr->packet_size = 0;

        PtrFree(&iptr->options);
        iptr->options_size = 0;

        // what comes after this?
        inext = iptr->next;

        // free this structure..
        free(iptr);

        // move to the next..
        iptr = inext;
    }

    // they were all cleared so we can ensure the linked list is empty.
    *list = NULL;

    return;
}

