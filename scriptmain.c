/*

The version which is based around being controlled by python, and/or executing python queue scripts goes here.

This is proof that some lines of code on the Internet without anyone agreeing can change the world.  Money cannot solve
the issues that allow these attacks.

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

int GenerateIPv6Address(AS_context *ctx, char *country, struct in6_address *address);

extern const char *geoip_countries[];

//https://stackoverflow.com/questions/17766550/ctrl-c-interrupt-event-handling-in-linux
volatile sig_atomic_t flag = 0;
void ctrlc_exit(int sig){ // can be called asynchronously
    flag=1;
    exit(0);
}


int main(int argc, char *argv[]) {
    int i = 0, done = 0;
    AS_context *ctx = Antisurveillance_Init();
    // default script is "mgr.py"
    char *script = "mgr";
    AS_scripts *sctx = NULL;    
    int z = 0;

    // allow ctrl-c to stop script (if can you loop forever)
    signal(SIGINT, ctrlc_exit); 

    if (argc > 1) {
        script = argv[1];
    }

    // find another way to get this later...
    sctx = ctx->scripts;

    // set retry max to 0 since we are loading from file...
    // *** change 
    if (argc > 2) {
        ctx->traceroute_max_retry = 0;

        //Spider_Load_threaded(ctx, "traceroute");
        Spider_Load(ctx, "traceroute");
        
        ctx->traceroute_max_retry = 100;
    }

    //printf("1\n");
    // call the init() function in the script
    PythonLoadScript(sctx, script, "init", NULL);
    //printf("2\n");


    ctx->http_discovery_enabled = 1;
    ctx->http_discovery_max = 50;

    //GenerateIPv6Address(ctx, (char *) "US", NULL);
    while (ctx->script_enable) {
            // call AS_perform() once to iterate all attacks
            AS_perform(ctx);

            // now call the script in case it wants to make any changes.. or disable the system
            Scripting_Perform(ctx);

            if (flag) {
                printf("Caught Ctrl-C...\n");
                break;
            }
/*
            z = 0;
            while (geoip_countries[z]) {
                //printf("Country: %s\n", geoip_countries[z]);
                GenerateIPv6Address(ctx, (char *)geoip_countries[z], NULL);
                z++;
                //if (z == 255) { z= 0; }
                //usleep(10000);
            }
*/
    }

    // completed... finish routines to free all memory, scripting, and other subsystems..
    // this will allow this to be used as a library easier (inn other apps)
    exit(0);
}
