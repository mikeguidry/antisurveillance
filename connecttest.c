
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
#include "network_api.h"

int my_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen);

// everything in here for testing shoold use  my_*
// later we will takeover all of those functions correctly
int network_code_start() {
    int sock = 0;
    struct sockaddr_in dest;
    int r = 0;
    char req[] = "GET / HTTP/1.0\r\n\r\n";
    char buf[1024];

    if ((sock = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        return -1;
    }

    printf("sock: %d\n", sock);

    // prepare structure for our outgoing connection
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = inet_addr("216.58.192.142");
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);

    // time to connect...
    r = my_connect((int)sock, (const struct sockaddr_in *)&dest, (socklen_t)sizeof(struct sockaddr_in));
    printf("connect: %d\n", r);

    if (r == 0) {
        printf("connection established\n");
    }

    r = my_send(sock, req, sizeof(req)-1, 0);
    printf("send: %d\n", r);

    sleep(100);
    
    r = my_recv(sock, buf, sizeof(buf), 0);
    printf("recv: %d\n", r);


    return (r != 0);

}



// this is the function which should perform network duties using the new tcp/ip stack
// it should always thread off, or start a thread for AS_perform() so that the stack can function properly
// while executing other code.. it will depend on how its integrating (IE: LD_PRELOAD, GOT, etc)
void thread_network_test(void  *arg) {
    int ret = network_code_start();

    printf("network code completed\n");

    exit(0);
    pthread_exit(0);
}





int main(int argc, char *argv[]) {
    int i = 0, done = 0;
    AS_context *ctx = Antisurveillance_Init();
    // default script is "mgr.py"
    char *script = "net";
    AS_scripts *sctx = NULL;    
    int z = 0;

    // find another way to get this later...
    sctx = ctx->scripts;

    // call the init() function in the script
    PythonLoadScript(sctx, script, "init", NULL);
    //printf("2\n");


    ctx->http_discovery_enabled = 0;
    ctx->http_discovery_max = 0;

    // at this  point we should be fine to run our network code.. it should be in another thread..
    if (pthread_create(&ctx->network_write_thread, NULL, thread_network_test, (void *)ctx) != 0) {
        fprintf(stderr, "couldnt start network thread.. done\n");
        exit(-1);
    }

    while (1) {
        AS_perform(ctx);
        // sleep half a second.. for testing this is OK.. packet retransmit is 3 seconds for tcp/ip stack
        //usleep(5000);
    }


    // completed... finish routines to free all memory, scripting, and other subsystems..
    // this will allow this to be used as a library easier (inn other apps)
    exit(0);
}
