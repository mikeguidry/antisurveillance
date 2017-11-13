#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "http.h"



// We wouldn't want the surveillance platforms to see the same exact packets.. over and over..
// Let's adjust the source port, identifiers, ACK/SEQ bases, etc here..
// This function will have to call other functions soon to modify MACROS. (dynamic portions of the packets
// which are intended to show other differences..) It could even load other messages in some cases.
// it depends on how your attacks are targeted.
void PacketAdjustments(AS_attacks *aptr) {
    // our new source port must be above 1024 and below 65536
    // lets get this correct for each emulated operating system later as well
    int client_port = (1024 + rand()%(65535 - 1024));
    int client_identifier = rand()%0xFFFFFFFF;
    int server_identifier = rand()%0xFFFFFFFF;
    
    int client_new_seq = rand()%0xFFFFFFFF;
    int server_new_seq = rand()%0xFFFFFFFF;

    uint32_t src_ip = rand()%0xFFFFFFFF;
    uint32_t dst_ip = rand()%0xFFFFFFFF;

    uint32_t client_seq_diff = 0;
    uint32_t server_seq_diff = 0;

    PacketBuildInstructions *buildptr = aptr->packet_build_instructions;

    while (buildptr != NULL) {
        // set ports for correct side of the packet..
        if (buildptr->client) {

            buildptr->source_ip = src_ip;
            buildptr->destination_ip = dst_ip;

            // Source port from client side to server is changed here
            buildptr->source_port = client_port;
            // The header identifier is changed here (and we are using the client side)
            buildptr->header_identifier = client_identifier++;

            // replace tcp/ip ack/seq w new base
            client_seq_diff = buildptr->seq - aptr->client_base_seq;
            buildptr->seq = client_new_seq + client_seq_diff;

            if (buildptr->ack != 0) {
                server_seq_diff = buildptr->ack - aptr->server_base_seq;
                buildptr->ack = server_new_seq + server_seq_diff;
            }

        } else  {

            buildptr->source_ip = dst_ip;
            buildptr->destination_ip = src_ip;
            
            // Source port from server to client is changed here
            buildptr->destination_port = client_port;
            // The header identifier is changed here (and we use the server side)
            buildptr->header_identifier = server_identifier++;

            server_seq_diff = buildptr->seq - aptr->server_base_seq;
            buildptr->seq = server_new_seq + server_seq_diff;

            if (buildptr->ack != 0) {
                client_seq_diff = buildptr->ack - aptr->client_base_seq;
                buildptr->ack = client_new_seq + client_seq_diff;
            }
        }

        // do we modify the data? lets try.. changes hashes.. uses more resources
        if (buildptr->data && buildptr->data_size) {
            HTTPContentModification(buildptr->data, buildptr->data_size);
        }

        // move to the next packet
        buildptr = buildptr->next;
    }

    // make sure we update the attack structure for next ACK/SEQ adjustment
    aptr->client_base_seq = client_new_seq;
    aptr->server_base_seq = server_new_seq;

    // Rebuild all packets using the modified instructions
    BuildTCP4Packets(aptr);

    return;
}
