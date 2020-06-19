
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

typedef struct _thread_details {
    AS_context *ctx;
    int start_ts;
    int tid;
} ThreadDetails;

int my_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen);

// everything in here for testing shoold use  my_*
// later we will takeover all of those functions correctly
int network_code_start(AS_context *ctx, int start_ts, int tid) {
    int sock = 0;
    struct sockaddr_in6 dest;
    int r = 0;
    char req_fmt[] = "GET /?%d_%d HTTP/1.0\r\n\r\n"; // obciousslt adding headers/etc is a must
    char req[1024];
    char buf[16384];
    int retry = 2;
    int start = 0;
    int ret = 0;
    
    SocketContext *sptr = NULL;
    char ip[256];

    sprintf(req, req_fmt, start_ts, tid);

    //sleep(1);


    ctx->queue_buffer_size = 1024*1024*10;
    ctx->queue_max_packets = 10000;


    start = time(0);

    // open new socket...
    if ((sock = my_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1) return -1;

    if ((sptr = NetworkAPI_SocketByFD(ctx, sock)) == NULL) return -1;

    tid = tid % 250;
    if (tid == 183) tid = 174;
    if (tid == 0) tid = 1;

    memset(&dest, 0, sizeof(struct sockaddr_in6));
    sprintf(ip, "2600:1004:b158:bdd0:20c:29ff:febc:9fa5");//, tid);
    inet_pton(AF_INET6, ip, &dest.sin6_addr);
    //printf("settinng ip %s\n", ip);
    //sptr->our_ipv4 = inet_addr(ip);
    // prepare binding to a specific, ip and local port

    //dest.sin_addr.s_addr = inet_addr(ip);
    //dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin6_family = AF_INET6;
    dest.sin6_port = rand()%0xFFFFFFFF;

    // bind to the IP we chose, and port for the  outgoing connection we will place
    r = my_bind((int)sock, (const struct sockaddr_in6 *)&dest, (socklen_t)sizeof(struct sockaddr_in6));
    //printf("bind: %d\n", r);


    // max wait for recv... (for broken sockets until protocol is up to par with regular OS)
    sptr->max_wait = 3;
    //printf("sock: %d\n", sock);

    // prepare structure for our outgoing connection to google.com port 80
    memset(&dest, 0, sizeof(struct sockaddr_in6));
    //dest.sin_addr.s_addr = inet_addr("2600:1004:b163:583b:250:56ff:fe33:b63c");
    sprintf(ip, "2600:1004:b158:bdd0:250:56ff:fe33:b63c");
    inet_pton(AF_INET6, ip, &dest.sin6_addr);
    //dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(80);

    // connect to google.com port 80
    r = my_connect((int)sock, (const struct sockaddr_in6 *)&dest, (socklen_t)sizeof(struct sockaddr_in6));
    // did it work out? whats response..
    //printf("connect: %d\n", r);
    r=0;

    sleep(1);

    // if it worked  out.. 
    if (r == 0) {
        //printf("connection established\n");

        r = my_send(sock, req, strlen(req), 0);
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
    

    printf("%d seconds to execute\n", time(0) - start);



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
    ThreadDetails *dptr = (ThreadDetails *)arg;
    int tid = (int)dptr->tid;
    
    while (1) {
        ret = network_code_start((AS_context *)dptr->ctx, dptr->start_ts, tid);
        if (ret) {
            pthread_mutex_lock(&dptr->ctx->socket_list_mutex);
            printf("tid %d c %d success\n", tid, ++c);
            pthread_mutex_unlock(&dptr->ctx->socket_list_mutex);
        }
        if (tid == 0) {
            break;
        }

    }
    
    //sleep(10);

    free(dptr);

    pthread_exit(0);
}


int StartThread(pthread_t *thread_id_ptr, AS_context *ctx, int start_ts, int tid) {
    ThreadDetails *dptr = (ThreadDetails *)calloc(1, sizeof(ThreadDetails));
    if (dptr == NULL) return -1;
    dptr->tid = tid;
    dptr->ctx = ctx;
    dptr->start_ts = start_ts;
    int ret = 0;

    if (pthread_create(&thread_id_ptr, NULL, thread_network_test, (void *)dptr) != 0) {
        fprintf(stderr, "couldnt start network thread..\n");
        free(dptr);
        ret = -1;
    } else ret = 1;

    return ret;
}




int main(int argc, char *argv[]) {
    int i = 0, done = 0;
    AS_context *ctx = Antisurveillance_Init(1);
    // default script is "mgr.py"
    char *script = "net";
    AS_scripts *sctx = NULL;    
    int z = 0;
    int count = 1;
    pthread_t *thread_ids = NULL;
    int start = time(0);

        // ignore traffic from debugging..
    ctx->ignore_flt = (struct _filter_information *)calloc(2, sizeof(FilterInformation));
    FilterPrepare(&ctx->ignore_flt[0], FILTER_PACKET_TCP|FILTER_SERVER_PORT|FILTER_PACKET_FAMILIAR, 22);
    FilterPrepare(&ctx->ignore_flt[1], FILTER_PACKET_TCP|FILTER_SERVER_PORT|FILTER_PACKET_FAMILIAR, 6000);
    ctx->ignore_flt_count = 2;


    // find another way to get this later...
    sctx = ctx->scripts;

    PCAP_OperationAdd(ctx, "incoming.pcap", NULL);

    // call the init() function in the script
    //PythonLoadScript(sctx, script, "init", NULL);
    //printf("2\n");

    if (ctx == NULL) {
        printf("couldnt initialize context\n");
        exit(-1);
    }

    if (argc == 2) {
        count = atoi(argv[1]);
        printf("Using %d connections\n", count);
    }

    thread_ids = (pthread_t *)calloc(count, sizeof(pthread_t));
    if (thread_ids == NULL) {
        printf("error allocating mem for threads\n");
        exit(-1);
    }

    for (i = 0; i < count; i++) {
        z = StartThread(&thread_ids[i], ctx, start, i);
        if (z <= 0)
            printf("Couldnt start thread #%d\n", i);
    }

    while (1) {

        AS_perform(ctx);
        usleep(5000);

        if ((time(0) - start) > 60) {
            break;
        }
        //sleep(10);
     }

    // completed... finish routines to free all memory, scripting, and other subsystems..
    // this will allow this to be used as a library easier (inn other apps)
    exit(0);
}
