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


int Test_Generate(AS_context *ctx, int argc, char *argv[]) {
    int server_port, client_port;
    uint32_t server_ip, client_ip;
    int count = 1;
    int repeat_interval = 1;
    int r = 0;
    int loop_count = 0;
    int i = 0;

    if (argc == 1) {
        bad_syntax:;
        printf("%s ipv4_client_ip client_port ipv4_server_ip server_port client_body_file server_body_file repeat_count repeat_interval\n",
            argv[0]);
        exit(-1);
    }
    
    // client information
    client_ip       = inet_addr(argv[1]);
    client_port     = atoi(argv[2]);

    // server information
    server_ip       = inet_addr(argv[3]);
    server_port     = atoi(argv[4]);

    // client request data (in a file)
    ctx->G_client_body   = FileContents(argv[5], &ctx->G_client_body_size);
    // server responsse data (in a file)
    ctx->G_server_body   = FileContents(argv[6], &ctx->G_server_body_size);


    // how maany times to repeat this session on the internet?
    // it will randomize source port, etc for each..
    count           = atoi(argv[7]);
    // how many seconds in between each request?
    // this is because its expecting to handling tens of thousands simul from each machine
    // millions depending on how much of an area the box will cover for disruption of the surveillance platforms
    repeat_interval = atoi(argv[8]);

    if (!client_ip || !server_ip || !client_port || !server_port || !ctx->G_client_body ||
             !ctx->G_server_body || !count || !repeat_interval) goto bad_syntax;

    // Initialize an attack structure regarding passed information
    if ((r = AS_session_queue(ctx, 1, client_ip, server_ip, client_port, server_port, count, repeat_interval, 1,
                 (void *)&HTTP4_Create)) != 1) {
        printf("error adding session\n");
        exit(-1);
    }

    return 1;
}


int Test_PCAP(AS_context *ctx, char *filename) {
    int i = 0;

    printf("Loading data from packet capture for attacks: %s\n", filename);

    i = PCAPtoAttack(ctx, filename, 80, 99999, 1, NULL);

    printf("Total from PCAP(80) : %d\n", L_count((LINK *)ctx->attack_list));

    return 1;
}


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