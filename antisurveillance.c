#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <resolv.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <zlib.h>
#include <pthread.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/if_ether.h>

#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "antisurveillance.h"
#include "pcap.h"
#include "network.h"
#include "attacks.h"
#include "packetbuilding.h"
#include "http.h"
#include "utils.h"



#define TEST

AS_attacks *attack_list;

char *G_client_body = NULL;
char *G_server_body = NULL;
int G_client_body_size = 0;
int G_server_body_size = 0;
    
// for debugging to test various gzip parameters
extern int total_gzip_count;

// Global variable holding the GZIP caching at the moment...
extern char *gzip_cache;
extern int gzip_cache_size;
extern int gzip_cache_count;
extern int gzip_initialized;
extern pthread_mutex_t gzip_cache_mutex;


// The outgoing queue which gets wrote directly to the Internet wire.
extern AttackOutgoingQueue *network_queue;
extern AttackOutgoingQueue *network_queue_last;
extern pthread_mutex_t network_queue_mutex;
extern pthread_t network_thread;




/*
notes for using pcaps, etc....

someone can start wireshark, and browse a site that they want to add to the attack
if they used macros such as fabricated name, address.. orr other informatin
that could be automatically found, and modified then it would be the simplest
way to append more sessions for attacking

if put into a database.. it could have a list of sites
w management (IE: perform some basic actions using a browser addon
such as clearing things (cookies, etc, ,etc)) and then it can
prepare to spoof somme other useragents...

it would allow people who dont undertand technology to easily inisert 
new sites to fabricate transmissions towards

be sure to save as PCAP not PCAPNG
*/



/*
typedef struct _points { int x; int y; int n} MPoints;
CPoints[] = {
    {00,11,1},{01,22,2},{21,31,3},{31,42,4},{41,53,5},{55,54,6},{54,53,7},{05,15,8},{14,22,9},{03,15,10},{24,35,11},{00,00,00}
};

int pdiff(int x, int y) {
    int ret = 0;
    int i = 0, a = 0, z = 0;
    MPoints points[16];

    while (CPoints[i].n != 0) {
        points[i].x = CPoints[i].x - x;
        if (points[i].x < 0) points[i].x ~= points[i].x;
        points[i].y = CPoints[i].y - y;
        if (points[i].y < 0) points[i].y ~= points[i].y; 

        i++;
    }

    for (a = 0; CPoints[a].id != 0; a++) {

    }

    return ret;
}

[00,11],[01,22],[21,31],[31,42],[41,53],[55,54],[54,53],[05,15],[14,22],[03,15],[24,35],[00,00]

0                       1                                  2                         3                          4                              5







1                     11                                  21                        31                         41                              51







2                      12                                  22                        32                         42                            52






3                     13                                   23                         33                         43                           53





4                      14                                  24                       34                            44                           54



5                     15                                25                            35                            45                          55



*/





// Perform one iteration of each attack structure that was queued
int AS_perform() {
    AS_attacks *aptr = attack_list;
    attack_func func;
    int r = 0;
    
    while (aptr != NULL) {
        // try to lock this mutex
        if (pthread_mutex_trylock(&aptr->pause_mutex) == 0) {  
            
            // if we need to join this thread (just in case pthread will leak otherwise)
            if (aptr->join) {
                pthread_join(aptr->thread, NULL);
                aptr->join = 0;
            }
            
            //printf("aptr %p next %p\n", aptr, aptr->next);
            if (aptr->paused == 0 && aptr->completed == 0) {
                r = 0;
                // if we dont have any prepared packets.. lets run the function for this attack
                if (aptr->packets == NULL) {
                    // call the correct function for performing this attack to build packets.. it could be the first, or some adoption function decided to clear the packets
                    // to call the function again
                    func = (attack_func)aptr->function;
                    if (func != NULL) {
                        // r = 1 if we created a new thread
                        r = ((*func)(aptr) == NULL) ? 0 : 1;
                    }
                }

                if (!r && !aptr->paused) {
                    // If those function were successful then we would have some packets here to queue..
                    if ((aptr->current_packet != NULL) || (aptr->packets != NULL)) {
                        PacketQueue(aptr);
                    } else {
                        // otherwise we mark as completed to just free the structure
                        aptr->completed = 1;
                    }
                }
            }

            pthread_mutex_unlock(&aptr->pause_mutex);
        }

        // go to the next
        aptr = aptr->next;
    }

    // every loop lets remove completed sessions... we could choose to perform this every X iterations, or seconds
    // to increase speed at times.. depending on queue, etc
    AS_remove_completed();

#ifndef TEST
    // flush network packets queued to wire
    FlushAttackOutgoingQueueToNetwork();
#endif

    return 1;
}



// If a session has been deemed completed, then this function will remove it and fix up the linked lists
void AS_remove_completed() {
    AS_attacks *aptr = attack_list, *anext = NULL, *alast = NULL;

    while (aptr != NULL) {
        if (pthread_mutex_trylock(&aptr->pause_mutex) == 0) {

            if (aptr->completed == 1) {
                // try to lock this mutex
                
                    // we arent using a normal for loop because
                    // it'd have an issue with ->next after free
                    anext = aptr->next;

                    // free all packets from this attack structure..
                    AttackFreeStructures(aptr);

                    if (attack_list == aptr)
                        attack_list = anext;
                    else {
                        alast->next = anext;
                    }

                    pthread_mutex_unlock(&aptr->pause_mutex);
                    
                    // free the structure itself
                    free(aptr);

                    aptr = anext;

                    continue;
                }

                pthread_mutex_unlock(&aptr->pause_mutex);
            }

        alast = aptr;

        aptr = aptr->next;
    }

    return;
}



// This was created to test this code standalone.  The final should integrate easily into other applications.
int main(int argc, char *argv[]) {
    int server_port, client_port;
    uint32_t server_ip, client_ip;
    int count = 1;
    int repeat_interval = 1;
    int i = 0, r = 0;
    int start_ts = time(0);
    char *filename = NULL;
#ifdef BIG_TEST
    int repeat = 1000000;
#endif
    if (argc == 1) {
        bad_syntax:;
        printf("%s ipv4_client_ip client_port ipv4_server_ip server_port client_body_file server_body_file repeat_count repeat_interval\n",
            argv[0]);
        exit(-1);
    } else if (argc == 2) {
        filename = argv[1];
        printf("Will load attacks from pcap %s\n", filename);
        
    }

    srand(time(0));

    // initialize a few things for gzip threading
    gzip_init();

    // initialize mutex for network queue...
    //pthread_mutex_init(&network_queue_mutex, NULL);

    // start network queue thread
    /*if (pthread_create(&network_thread, NULL, thread_network_flush, (void *)NULL) != 0) {
        printf("couldnt start network thread\n");
    }*/

    if (filename == NULL) {
    // client information
    client_ip       = inet_addr(argv[1]);
    client_port     = atoi(argv[2]);

    // server information
    server_ip       = inet_addr(argv[3]);
    server_port     = atoi(argv[4]);

    // client request data (in a file)
    G_client_body   = FileContents(argv[5], &G_client_body_size);
    // server responsse data (in a file)
    G_server_body   = FileContents(argv[6], &G_server_body_size);
    
#ifdef GZIPTEST
    // lets test gzip
    GZipAttack(0,&G_server_body_size, &G_server_body, 1024*1024*100, 50);

    // lets write to output...
    fd = fopen("test.gz","wb");
    if (fd == NULL) {
        printf("couldnt open output file.. maybe some other problem witth gzip\n");
        exit(-1);
    }
    fwrite((void *)G_server_body, 1, G_server_body_size, fd);
    fclose(fd);
    
    printf("wrote gzip attack file.. done\n");
    exit(-1);
#endif

    // how maany times to repeat this session on the internet?
    // it will randomize source port, etc for each..
    count           = atoi(argv[7]);
    // how many seconds in between each request?
    // this is because its expecting to handling tens of thousands simul from each machine
    // millions depending on how much of an area the box will cover for disruption of the surveillance platforms
    repeat_interval = atoi(argv[8]);

    if (!client_ip || !server_ip || !client_port || !server_port || !G_client_body ||
             !G_server_body || !count || !repeat_interval) goto bad_syntax;
    } else {
        //AS_attacks *PCAPtoAttack(char *filename, int dest_port, int count, int interval);
        //aptr = 
        i = PCAPtoAttack(filename, 80, 999999, 10);
        printf("Total from PCAP(80) : %d\n", i);
        //i = PCAPtoAttack(filename, 443, 999999, 10); printf("Total from PCAP(443): %d\n", i);
    }


#ifdef BIG_TEST
    while (repeat--) {
        server_ip = rand()%0xFFFFFFFF;
        client_ip = rand()%0xFFFFFFFF;
#endif
        if (!filename)
        // Initialize an attack structure regarding passed information
        if ((r = AS_session_queue(1, client_ip, server_ip, client_port, server_port, count, repeat_interval, 1,
                     (void *)&HTTP4_Create)) != 1) {
            printf("error adding session\n");
            exit(-1);
        }
        
#ifndef BIG_TEST
        if (!filename)
         printf("AS_session_queue() = %d\n", r);
#else
       // This is the main function to use which will loop, and handle things for the attacks
       r = AS_perform();

        if (repeat % 1000) {
            printf("\rCount: %05d\t\t", repeat);
             fflush(stdout);
        }
    }
    
    printf("\rDone                      \t\t\n");
#endif

#ifndef BIG_TEST
    // We loop to call this abunch of times because theres a chance all packets do not get generated
    // on the first call.  It is designed this way to handle a large amount of fabricated sessions 
    // simultaneously... since this is just a test... let's loop a few times just to be sure.
    for (i = 0; i < 3000; i++) {
        r = AS_perform();
        if (r != 1) printf("AS_perform() = %d\n", r);

        usleep(5000);
    }
#endif

    
    // how many packes are queued in the output supposed to go to the internet?
    printf("network queue: %p\n", network_queue);
    if (network_queue)
        printf("packet count ready for wire: %d\n", L_count((LINK *)network_queue));  


    printf("Gzip Count: %d\n", total_gzip_count);

    // This is probably the amount of time it'd dumping to network since its all happening simultaneously
    printf("Time before dumping packets to disk: %d seconds\n", (int)(time(0) - start_ts));

    if (!filename)
        // now lets write to pcap file.. all of those packets.. open up wireshark.
        PcapSave((char *)"output.pcap", network_queue);
    else
        PcapSave((char *)"output2.pcap", network_queue);

    printf("Time to fabricate, and dump packets to disk: %d seconds\n", (int)(time(0) - start_ts));

    //printf("sleeping.. check ram usage\n");
    //sleep(300);

    exit(0);
}

