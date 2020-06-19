/*

this is specifally here  temporarily to continue/dev/test traceroute things
for dsitance etc

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include "network.h"
#include "antisurveillance.h"
#include "pcap.h"
#include "attacks.h"
#include "packetbuilding.h"
#include "http.h"
#include "utils.h"
#include "scripting.h"
#include "research.h"

//https://stackoverflow.com/questions/17766550/ctrl-c-interrupt-event-handling-in-linux
volatile sig_atomic_t flag = 0;
void ctrlc_exit(int sig){ // can be called asynchronously
    flag=1;
    exit(0);
}


int main(int argc, char *argv[]) {
    int i = 0, done = 0;
    int n = 0;
    AS_context *ctx = Antisurveillance_Init();
    // default script is "mgr.py"
    char *script = "mgr";
    AS_scripts *sctx = NULL;    
    TracerouteSpider *sptr = NULL;
    TracerouteQueue *qptr = NULL;
    char *IP = NULL;
    int z = 0;
    int complete = 0;

    // allow ctrl-c to stop script (if can you loop forever)
    signal(SIGINT, ctrlc_exit); 

    if (argc > 1) {
        script = argv[1];
    }

    // find another way to get this later...
    sctx = ctx->scripts;

    //Spider_Load_threaded(ctx, "traceroute");
    Spider_Load(ctx, "traceroute");


    //printf("lets fill em`ptpy responsses\n");
    
    Traceroute_FillAll(ctx);

    //Spider_Save(ctx);

    for (n = 0; n < JTABLE_SIZE; n++) {
        qptr = ctx->traceroute_queue_identifier[n];
        
        while (qptr != NULL) {
            z = 0;
            complete = 0;

            for (i = 0; i < 30; i++) {
                if (qptr->responses[i] != NULL) {
                    if (qptr->responses[i]->hop_ip == qptr->target_ip) {
                        complete = 1;
                    }
                    if ((argc > 1) && qptr->responses[i+1] && qptr->responses[i+2]) z++;
                    else z++;
                    // we wanna check if we have 4 suquential responses AND commpleted..

                    //z++;
                }
            }

            if (1==1 && z && complete) {
                IP = IP_prepare_ascii(qptr->target_ip, NULL);

                if (IP) {
                    printf("Q[%03d]IP: %s [Q %X] ptr %p max ttl %d results %d\n", n, IP, qptr->identifier, qptr, qptr->max_ttl, z);
                    free(IP);
                }

                for (i = 0; i < 30; i++) {
                    if (qptr->responses[i] != NULL) {

                        //printf("qptr response %d: %p\n", i, qptr->responses[i]);
                        IP = IP_prepare_ascii(qptr->responses[i]->hop_ip, NULL);
                        if (IP) {
                            printf("%d. %s\n", qptr->responses[i]->ttl, IP);
                            free(IP);
                        }
                    }
                }
            }
            qptr = qptr->next_identifier;
        }
    }
    exit(0);

    printf("spiders\n");

    sptr = ctx->traceroute_spider;
    while (sptr) {
        IP = IP_prepare_ascii(sptr->hop_ip, NULL);

        if (IP) {
            printf("HOP IP: %s [identifier %X] qptr %p ttl %d\n", IP, sptr->identifier_id, sptr->queue, sptr->ttl);
            free(IP);
        }

        
        sptr = sptr->next;
    }

    exit(0);
}
