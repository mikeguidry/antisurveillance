
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
    int tid;
} ThreadDetails;

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

    if (tid == 183) tid = 174;
    if (tid == 0) tid = 1;

    sprintf(ip, "192.168.72.%d", tid);
    //printf("settinng ip %s\n", ip);
    //sptr->our_ipv4 = inet_addr(ip);
    // prepare binding to a specific, ip and local port
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = inet_addr(ip);
    //dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_family = AF_INET;
    dest.sin_port = rand()%0xFFFFFFFF;

    // bind to the IP we chose, and port for the  outgoing connection we will place
    r = my_bind((int)sock, (const struct sockaddr_in *)&dest, (socklen_t)sizeof(struct sockaddr_in));
    //printf("bind: %d\n", r);


    // max wait for recv... (for broken sockets until protocol is up to par with regular OS)
    sptr->max_wait = 3;
    //printf("sock: %d\n", sock);

    // prepare structure for our outgoing connection to google.com port 80
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = inet_addr("192.168.72.184");
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

    //sleep(3);

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
        ret = network_code_start((AS_context *)dptr->ctx, tid);
        if (ret) {
            pthread_mutex_lock(&dptr->ctx->socket_list_mutex);
            printf("tid %d c %d success\n", tid, ++c);
            pthread_mutex_unlock(&dptr->ctx->socket_list_mutex);
        }
        if (tid == 0) {
            break;
        }

    }
    
    sleep(10);

    free(dptr);

    pthread_exit(0);
}


int StartThread(pthread_t *thread_id_ptr, AS_context *ctx, int tid) {
    ThreadDetails *dptr = (ThreadDetails *)calloc(1, sizeof(ThreadDetails));
    if (dptr == NULL) return -1;
    dptr->tid = tid;
    dptr->ctx = ctx;
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
    int count = 10;
    pthread_t *thread_ids = NULL;

    // find another way to get this later...
    sctx = ctx->scripts;

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

    ctx->http_discovery_enabled = 0;
    ctx->http_discovery_max = 0;


    for (i = 0; i < count; i++) {
        z = StartThread(&thread_ids[i], ctx, i);
        if (z <= 0)
            printf("Couldnt start thread #%d\n", i);
    }

    while (1) {

        AS_perform(ctx);
        usleep(5000);
        //sleep(10);
     }

    // completed... finish routines to free all memory, scripting, and other subsystems..
    // this will allow this to be used as a library easier (inn other apps)
    exit(0);
}
