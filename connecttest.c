
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

AS_context *Gctx = NULL;

int my_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen);

// everything in here for testing shoold use  my_*
// later we will takeover all of those functions correctly
int network_code_start(AS_context *ctx, int tid) {
    int sock = 0;
    struct sockaddr_in dest;
    int r = 0;
    char req[] = "GET / HTTP/1.0\r\n\r\n"; // obciousslt adding headers/etc is a must
    char buf[16384];
    int retry = 2;
    int start = 0;
    int ret = 0;
    
    SocketContext *sptr = NULL;
    char ip[16];

    //sleep(1);

    start = time(0);

    // open new socket...
    if ((sock = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) return -1;

    if ((sptr = NetworkAPI_SocketByFD(ctx, sock)) == NULL) return -1;

    if (tid == 174) tid = 173;
    if (tid == 0) tid = 1;

    sprintf(ip, "192.168.72.%d", tid);
    //printf("settinng ip %s\n", ip);
    sptr->our_ipv4 = inet_addr(ip);

    // max wait for recv... (for broken sockets until protocol is up to par with regular OS)
    sptr->max_wait = 3;
    //printf("sock: %d\n", sock);

    // prepare structure for our outgoing connection to google.com port 80
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = inet_addr("192.168.72.174");
    //dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);

    // connect to google.com port 80
    r = my_connect((int)sock, (const struct sockaddr_in *)&dest, (socklen_t)sizeof(struct sockaddr_in));
    // did it work out? whats response..
    //printf("connect: %d\n", r);

    // if it worked  out.. 
    if (r == 0) {
        //printf("connection established\n");

        r = my_send(sock, req, sizeof(req)-1, 0);
        //printf("send: %d\n", r);

        // at this stage.. 83 bytes just received 15,851 bytes in a SINGLE connection
        // w load balancers, and other things in most companies this can easily be expanded
        // IF using some type of passive monitoring, or system whic can control many other IPs
        // then it can be increased substantially

        //sleep(3);

        do {
            memset(buf,0,sizeof(buf)-1);
            //ctx->socket_list->connections->noblock=1;
            r = my_recv(sock, buf, sizeof(buf), 0);
            if (r <= 0) retry--;
            //printf("recv: %d\ndata: \"%s\"\n", r, buf);
            if (strstr(buf, "</html>")) {
                //printf("FULL SUCCESS\n");
                ret = 1;
                break;
            }
            //if (!r) sleep(3);
        } while (r != -1 || !retry);
    }

    // close socket
    

    //printf("%d seconds to execute\n", time(0) - start);

    sleep(3);

    my_close(sock);
    
    //pthread_exit(0);

    return ret;
}



// this is the function which should perform network duties using the new tcp/ip stack
// it should always thread off, or start a thread for AS_perform() so that the stack can function properly
// while executing other code.. it will depend on how its integrating (IE: LD_PRELOAD, GOT, etc)
void thread_network_test(void  *arg) {
    int ret = 0;
    int c = 0;
    int tid = (int)arg;
    
    while (1) {
        ret = network_code_start((AS_context *)Gctx, tid);
        if (ret) {
            printf("tid %d c %d success\n", tid, ++c);
        }
        if (tid == 0) {
            printf("tid 0 ret %d\n", ret);
            break;
        }

        //if (c == 20) exit(0);
    }

    
    printf("network code completed\n");

    sleep(10);

    //exit(0);
    pthread_exit(0);
}





int main(int argc, char *argv[]) {
    int i = 0, done = 0;
    AS_context *ctx = Antisurveillance_Init();
    // default script is "mgr.py"
    char *script = "net";
    AS_scripts *sctx = NULL;    
    int z = 0;
    int count = 10;

    // find another way to get this later...
    sctx = ctx->scripts;

    // call the init() function in the script
    //PythonLoadScript(sctx, script, "init", NULL);
    //printf("2\n");

    Gctx = ctx;


    if (argc == 2) {
        count = atoi(argv[1]);
        printf("Using %d connections\n", count);
    }
    

    ctx->http_discovery_enabled = 0;
    ctx->http_discovery_max = 0;

    for (i = 0; i < count; i++) {
        // at this  point we should be fine to run our network code.. it should be in another thread..
        if (pthread_create(&ctx->network_write_thread, NULL, thread_network_test, (void *)i) != 0) {
            fprintf(stderr, "couldnt start network thread..\n");
        //   exit(-1);
        }
    }

    while (1) {
        AS_perform(ctx);
        // sleep half a second.. for testing this is OK.. packet retransmit is 3 seconds for tcp/ip stack
        usleep(5000);
    }


    // completed... finish routines to free all memory, scripting, and other subsystems..
    // this will allow this to be used as a library easier (inn other apps)
    exit(0);
}
