/*

listen test - listen on ports / allow incomming tcp/connections wiith a customm tcp/ip stack

this is another side of mass surveillance platforms being weaponized...

specific sockets which are listening on specific ports which can be turned on/off at will algorithm wise..
the rest of the IP can function normal to its server..

I planned to use this for automated hacking + worm-ing the world but they .. why not just give it away?

The point is that if you are able to filter specific ports from a 'target IP' then you can redirect to this custom TCP/IP stack
which will allow C&C which has nevver been seen before because .. it functions 100% proper, and normal...
the IPs, and ports can change.. it TRULY is 100% untracable, but also available worldwide... the HOPs, etc
can be manipulated (thats the only new portion of this for the  last two years that i came up with recently),

oh one other new development lately... it can be secured by tcp options, or a few other features that i dont want to discuss yet
any ISP worldwide can prepare this setup, or any passive internet monitoring system... its unstoppable in every way possible

the entire system can and should be controlled by an algorithm.. nobody could ever figure it out woithout inside knowledge
it can allow secure communication, drops, etc which can never be found againn.. and with proper encryption the logs
would be irrelevant... it can take advantage of real live servers (facebook, etc) and nobody would be none the wiser
or ever suspect anything.. well time for the world to see just how dangereous mass surveillance systems are...
BEYOND mass surveillance..


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
#include "network_api.h"

AS_context *Gctx = NULL;

int my_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen);

int connected_thread(int client) {
    char req[] = "xyz";
    char buf[1024];
    int r = 0;

    printf("client fd: %d\n", client);

    do {

        memset(buf,0,sizeof(buf)-1);

        r = my_recv(client, buf, sizeof(buf), 0);

        printf("recv[%d]: %s\n", r, buf);
        if (strstr(buf, "abc")) {
            r = my_send(client, req, sizeof(req)-1, 0);
        }

    } while (r != -1);

    my_close(client);

    pthread_exit(0);
}





// everything in here for testing shoold use  my_*
// later we will takeover all of those functions correctly
int network_code_start(AS_context *ctx) {
    int sock = 0;
    struct sockaddr_in dest;
    int r = 0;
    char buf[16384];
    int retry = 2;
    int start = 0;
    int ret = 0;
    char req[] = "xyz";
    int client = 0;
    SocketContext *sptr = NULL;

    start = time(0);

    // ignore traffic from debugging.. (ssh/x)
    ctx->ignore_flt = (struct _filter_information *)calloc(2, sizeof(FilterInformation));
    FilterPrepare(&ctx->ignore_flt[0], FILTER_PACKET_TCP|FILTER_SERVER_PORT|FILTER_PACKET_FAMILIAR, 22);
    FilterPrepare(&ctx->ignore_flt[1], FILTER_PACKET_TCP|FILTER_SERVER_PORT|FILTER_PACKET_FAMILIAR, 6000);
    ctx->ignore_flt_count = 2;


    // open new socket...
    if ((sock = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) return -1;

    printf("sock: %d\n", sock);

    // prepare structure for our outgoing connection to google.com port 80
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = inet_addr("192.168.1.14");
    //dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_family = AF_INET;
    dest.sin_port = htons(1001);



    // connect to google.com port 80
    r = my_bind((int)sock, (const struct sockaddr_in *)&dest, (socklen_t)sizeof(struct sockaddr_in));
    // did it work out? whats response..
    printf("bind: %d\n", r);



    r = my_listen(sock, 0);
    printf("listen: %d\n", r);

    while (1) {
        printf("waiting for connection\n");
        client = my_accept(sock, NULL, 0);
        if (client) {
            if (pthread_create(&ctx->network_write_thread, NULL, connected_thread, (void *)client) != 0) {
                my_close(client);
            }
        }
    }

    printf("client accepted %d\n", client);

    sleep(2);
/*
    // if it worked  out.. 
    if (client > 0) {
        printf("client fd: %d\n", client);
        do {
            memset(buf,0,sizeof(buf)-1);
            //ctx->socket_list->connections->noblock=1;
            r = my_recv(client, buf, sizeof(buf), 0);
            printf("recv[%d]: %s\n", r, buf);
            if (strstr(buf, "abc")) {
                r = my_send(client, req, sizeof(req)-1, 0);

                //ret = 1;
                //break;
            }

        } while (r != -1);
    }

    // close socket
    sleep(5);

    my_close(client);
    */
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
        ret = network_code_start((AS_context *)Gctx);
        if (ret) {
            printf("tid %d c %d success\n", tid, ++c);
        }
        if (tid == 0) {
            printf("tid 0 ret %d\n", ret);
            break;
        }
    }

    
    printf("network code completed\n");

    sleep(10);

    exit(0);
    pthread_exit(0);
}






int main(int argc, char *argv[]) {
    int i = 0, done = 0;
    AS_context *ctx = Antisurveillance_Init(1);
    // default script is "mgr.py"
    char *script = "net";
    AS_scripts *sctx = NULL;    
    int z = 0;
    int count = 10;

    // find another way to get this later...
    sctx = ctx->scripts;
    Gctx = ctx;

    ctx->http_discovery_enabled = 0;
    ctx->http_discovery_max = 0;

    // at this  point we should be fine to run our network code.. it should be in another thread..
    if (pthread_create(&ctx->network_write_thread, NULL, thread_network_test, (void *)i) != 0) {
        fprintf(stderr, "couldnt start network thread..\n");
    //   exit(-1);
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
