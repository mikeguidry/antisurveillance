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
#include "network.h"
#include "antisurveillance.h"
#include "pcap.h"
#include "attacks.h"
#include "packetbuilding.h"
#include "http.h"
#include "utils.h"
#include "scripting.h"

int main(int argc, char *argv[]) {
    int i = 0, done = 0;
    AS_context *ctx = Antisurveillance_Init();
    // default script is "mgr.py"
    char *script = "mgr";
    AS_scripts *sctx = NULL;    

    if (argc > 1) {
        script = argv[1];
    }

    // finnd another way to get this later...
    sctx = ctx->scripts;

    while (!done) {
        // Execute the main script
        i = PythonLoadScript(sctx, "mgr", "init", NULL);

        if (!sctx->perform) {
            done = 1;
        } else {
            // execute a scripting loop
            Scripting_Perform(ctx);
        }
    }

    // completed... finish routines to free all memory, scripting, and other subsystems..
    // this will allow this to be used as a library easier (inn other apps)
    exit(0);
}
