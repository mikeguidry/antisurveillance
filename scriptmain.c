/*

The version which is based around being controlled by python, and/or executing python queue scripts goes here.

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

//https://stackoverflow.com/questions/17766550/ctrl-c-interrupt-event-handling-in-linux
volatile sig_atomic_t flag = 0;
void ctrlc_exit(int sig){ // can be called asynchronously
    flag=1;
}


int main(int argc, char *argv[]) {
    int i = 0, done = 0;
    AS_context *ctx = Antisurveillance_Init();
    // default script is "mgr.py"
    char *script = "mgr";
    AS_scripts *sctx = NULL;    

    signal(SIGINT, ctrlc_exit); 

    if (argc > 1) {
        script = argv[1];
    }

    // find another way to get this later...
    sctx = ctx->scripts;

    // call the init() function in the script
    PythonLoadScript(sctx, script, "init", NULL);

    while (ctx->script_enable) {
            // call AS_perform() once to iterate all attacks
            AS_perform(ctx);

            // now call the script in case it wants to make any changes.. or disable the system
            Scripting_Perform(ctx);

            if (flag) {
                printf("Caught Ctrl-C...\n");
                break;
            }
    }

    // completed... finish routines to free all memory, scripting, and other subsystems..
    // this will allow this to be used as a library easier (inn other apps)
    exit(0);
}
