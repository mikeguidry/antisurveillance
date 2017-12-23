/*

the best webservers to use are ones with decent size, and also use PSH to respoond
this will request "GET /" fromm the web server, and analyze the packets, and size
to help you pick webservers out of a range for attacking

later it can all be put together into a fully automated system

in my test without PSH i was only getting 50% accuracy.. its possible to retrieve the webpages one time
and automatically generate all ACKs for alll data ahead, and send it immediately.. or in delay
this would increae this number substantially without requiring processing of all packets
its not a game.

steps:
1) load ip addresses from a file into an ip list structure
2) connect to each ip address port 80 web server, and request GET / HTTP/1.0 (simple, no hostname...)
3) count the time it takes to retrieve the file, and take note of the size.. also monitor whether the  host used PSH TCP/IP.. which means it will send the entire file
before requiring ACK it means that these 'beefed up.. optimizzed tcp/ip webhosts' are just going to be better helpers for our massive attacks
4) we need to dump all information to an output ip list (lets take the top 60% and dump the  bottomm 40%) by size, and def psh is always #1

this should be handled from a certain side of the tap... if you have access to a single ISP ips then you will want to use it on those IPs
if you have access to abunch of IPs that you wish to request from instead of use as a webserver.. thenn you need to perform it on that side
it really depends on how you will perform the attack


// alternatively.. a pcap version (which could either be done on live traffic ussing the http discovery, or load pcap from others) to find http and perform
all same checks
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


char *tag[] = { "A1", "00", NULL };


typedef struct _results {
    struct _results *next;
    uint32_t ip;
    int size;
    int found_psh;
} Results;

typedef struct _thread_details {
    AS_context *ctx;
    int tid;
} ThreadDetails;


int AddResult(AS_context *ctx, uint32_t ip, int size, int found_psh) {
    Results *rptr = NULL;

    if ((rptr = (Results *)calloc(1,sizeof(Results))) == NULL) return -1;
    rptr->size = size;
    rptr->ip = ip;
    rptr->found_psh = found_psh;

    pthread_mutex_lock(&ctx->custom_mutex);

    rptr->next = (Results *)ctx->custom;
    ctx->custom = (char *)rptr;

    pthread_mutex_unlock(&ctx->custom_mutex);
    
    return 1;
}

int my_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen);

// everything in here for testing shoold use  my_*
// later we will takeover all of those functions correctly
int network_code_start(AS_context *ctx, int tid, uint32_t src_ip, int src_port, uint32_t dest_ip, int dest_port) {
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
    int found_psh = 0;
    IOBuf *ioptr = NULL;
    int total_size = 0;

    start = time(0);

    // open new socket...
    if ((sock = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) return -1;

    if ((sptr = NetworkAPI_SocketByFD(ctx, sock)) == NULL) return -1;

    // or emulated like regular apps... i chose to use this for now
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = src_ip;
    //dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_family = AF_INET;
    dest.sin_port = htons(src_port);

    // bind to the IP we chose, and port for the  outgoing connection we will place
    r = my_bind((int)sock, (const struct sockaddr_in *)&dest, (socklen_t)sizeof(struct sockaddr_in));

    // max wait for recv... (for broken sockets until protocol is up to par with regular OS)
    sptr->max_wait = 3;

    // prepare structure for our outgoing connection to google.com port 80
    memset(&dest, 0, sizeof(struct sockaddr_in));
    dest.sin_addr.s_addr = dest_ip;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);

    // connect to google.com port 80
    r = my_connect((int)sock, (const struct sockaddr_in *)&dest, (socklen_t)sizeof(struct sockaddr_in));

    // if it worked  out.. 
    if (r == 0) {
     
        r = my_send(sock, req, sizeof(req)-1, 0);
     
        do {
            memset(buf,0,sizeof(buf)-1);

            // we are threaded.. fuck no blocking.. (i havent wrote select() yet)
            //ctx->socket_list->connections->noblock=1;
            r = my_recv(sock, buf, sizeof(buf), 0);
            if (r <= 0) retry--;

            if (strstr(buf, "</html>")) {
                ret = 1;
                break;
            }
            total_size += r;

        } while (r != -1 || !retry);
    }

    // the sockets packet information  (each packet individually, minus the data) is still there until close
    // get a pointer to the socket itself
    if (total_size && (sptr = NetworkAPI_SocketByFD(ctx, sock)) != NULL) {
        // lock the mutex..
        pthread_mutex_lock(&sptr->mutex);

        // enumerate through all incoming buffer pointers
        ioptr = sptr->in_buf;
        while (ioptr != NULL) {
            // check if the original packet details as it was read from the wire and put into our instructions was duplicated properly
            if (ioptr->iptr != NULL) {
                // check for TCP FLAG PSH
                if (ioptr->iptr->flags & TCP_FLAG_PSH) {
                    // if we foundd it then we are good
                    found_psh = 1;
                    break;
                }

            }
            ioptr = ioptr->next;
        }

        pthread_mutex_unlock(&sptr->mutex);
    } else {
        // we ignore errors..
    }

    my_close(sock);
    
    // log to disk.. size and if psh was found...
    // we have found_psh integer, and total_size integer
    //int AddResult(AS_context *ctx, uint32_t ip, int size, int found_psh) {
    AddResult(ctx, ip, total_size, found_psh);

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
    uint32_t src_ip = 0, dest_ip = 0;
    int src_port = 0, dest_port = 0;
    
    src_ip = get_source_ipv4();
    src_port = rand()%0xffffffff;
    dest_port = 80;
    
    while (1) {
        dest_ip = IPv4SetRandom(dptr->ctx, tag[0], 1);
        if (!dest_ip) break;

        ret = network_code_start((AS_context *)dptr->ctx, tid, src_ip, src_port, dest_ip, dest_port);
    }
    
    sleep(10);

    free(dptr);

    pthread_exit(0);
}


int StartThread(pthread_t *thread_id_ptr, AS_context *ctx, int tid) {
    int ret = 0;
    ThreadDetails *dptr = NULL;

    if ((dptr = (ThreadDetails *)calloc(1, sizeof(ThreadDetails))) == NULL) return -1;
    dptr->tid = tid;
    dptr->ctx = ctx;

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
    int z = 0;
    int count = 10;
    pthread_t *thread_ids = NULL;
    void *thread_ret = NULL;
    Results *rptr = NULL;

    if (argc == 2) {
        count = atoi(argv[1]);
        printf("Using %d connections\n", count);
    }
    
    thread_ids = (pthread_t *)calloc(count, sizeof(pthread_t));
    if (thread_ids == NULL) {
        printf("error allocating mem for threads\n");
        exit(-1);
    }

    // fill IPAddresses structure from a file
    if (!file_to_iplist(ctx, "psh_input_ip", tag[0])) {
        fprintf(stderr, "couldnt open input file or load IP addresses properly\n");
        exit(-1);
    }


    for (i = 0; i < count; i++) {
        z = StartThread(&thread_ids[i], ctx, i);
        if (z <= 0)
            printf("Couldnt start thread #%d\n", i);
    }


    // loop performing subsystems loops/events until all threads are completed with their ips
    while (1) {
        // calll all subsytem loops
        AS_perform(ctx);
        // small sleep..
        usleep(5000);

        // try to join (close) all threads...
        for (i = z = 0; i < count; i++) {
            if (thread_ids[i] != NULL) {
                if (pthread_tryjoin_np(thread_ids[i], &thread_ret) == 0) {
                    thread_ids[i] = NULL;
                } else z++;
            }
        }
        // all threads completed
        if (z == 0) break;
     }

    // now to check results..
    // no need to lock but in case i copy paste later..
    pthread_mutex_lock(&ctx->custom_mutex);
    rptr = (Results *)ctx->custom;
    while (rptr != NULL) {

        // sort? write to file?? hmm.. need to think the night on it

        rptr = rptr->next;
    }

    pthread_mutex_unlock(&ctx->custom_mutex);


    // completed... finish routines to free all memory, scripting, and other subsystems..
    // this will allow this to be used as a library easier (inn other apps)
    exit(0);
}
