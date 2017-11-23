/*
Command line (mainly C only) version will be here...
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "network.h"
#include "antisurveillance.h"
#include "pcap.h"
#include "attacks.h"
#include "packetbuilding.h"
#include "http.h"
#include "utils.h"

// or being controlled by a third party mechanism (script, etc)
int main(int argc, char *argv[]) {
    int i = 0, r = 0;
    int start_ts = time(0);
    char *filename = NULL;
    int loop_count = 0;
    AS_context *ctx = Antisurveillance_Init();

    if (ctx == NULL) {
        printf("Error initializing\n");
        exit(-1);
    }

    if (argc > 2) {
        if (Test_Generate(ctx, argc, argv) != 1)
            exit(-1);
    } else if (argc == 2) {
        filename = argv[1];
    
        if (Test_PCAP(ctx, filename) != 1)
            exit(-1);        
    } else {
        printf("syntax: ....\n");
        exit(-1);
    }

    loop_count = (L_count((LINK *)ctx->attack_list) > 1000) ? 300 : 30;
    printf("Loop count: %d\n", loop_count);
    
    // We loop to call this abunch of times because theres a chance all packets do not get generated
    // on the first call.  It is designed this way to handle a large amount of fabricated sessions 
    // simultaneously... since this is just a test... let's loop a few times just to be sure
    for (i = 0; i < loop_count; i++) {
        r = AS_perform(ctx);
        if (r != 1) printf("AS_perform() = %d\n", r);

        usleep(500);
    }

    i = 0;

    if (1==0)
    while (++i) {
        AS_perform(ctx);
        if ((i % 5)==0) {
            printf("\rCount: %d                      \t", i);
            fflush(stdout);
        }
        usleep(700000);
    }

    // how many packes are queued in the output supposed to go to the internet?
    printf("network queue: %p\n", ctx->network_queue);
    if (ctx->network_queue)
        printf("packet count ready for wire: %d\n", L_count((LINK *)ctx->network_queue));  


    printf("Gzip Count: %d\n", ctx->total_gzip_count);

    // This is probably the amount of time it'd dumping to network since its all happening simultaneously
    printf("Time before dumping packets to disk: %d seconds\n", (int)(time(0) - start_ts));

    PcapSave(ctx, filename ? (char *)"output2.pcap" : (char *)"output.pcap", ctx->network_queue, NULL, 1);
    
    printf("Time to fabricate, and dump packets to disk: %d seconds\n", (int)(time(0) - start_ts));

    exit(0);
}