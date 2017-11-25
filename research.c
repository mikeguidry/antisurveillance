#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "research.h"

/*

Research is everything related to strategy choices.  For example, which sites do we wish to spend the majority
of our bandwidth falsifying connections towards?  It will perform DNS lookups, traceroutes, and BGP analysis to
determine the best IP 4/6 addresses to use for attacks.

For local attacks: NIDs, etc.. It will take the local IP addresses, and find the best ways of attacking
the platform to either hide in other packets, or attempt to force other issues such as Admin believing hacks
are taking place elsewhere.. etc

I'll try to require as little hard coded information as possible.  I'd like everything to work without requiring any updates -- ever.
*/




// traceroutes are necessary to ensure a single nonde running this code can affect all mass surveillance programs worldwide
// it allows us to ensure we cover all places we expect them to be.. in the world today: if we expect it to be there.. then it
// probably is (for mass surveillance programs)
//https://www.information.dk/udland/2014/06/nsa-third-party-partners-tap-the-internet-backbone-in-global-surveillance-program
// we want to go through asa many routes as possible which means we are innjecting information into each surveillance tap along the way
// the other strategy will be using two nodes running this code which will be on diff parts of the world so we ca ensure eah side of the packets
// get processed correctly.. in the begininng (before they modify) it wont matter.. later once they attempt to filter out, and procecss
// it might matter but it'll make the entire job/technology that much more difficult
int Traceroute_Compare(TracerouteQueue *first, TracerouteQueue *second) {
    int ret = 0;

    // if there arent enough responses to compare.. then we are finished..
    // its not an error since it might just be queued with thousands of other sites/nodes
    //if (!first->traceroute_responses_count_v4 || !second->traceroute_responses_count_v4)
        //return ret;


    // we need to verify how close two nodes are in the world..
    // and if they go through the same fiber routers..
    // this will ensure that the taps get both sides of the connection
    // so we can be sure the attack is successful

    // need to know how many match, annd how close they are to the nodes themselves
    // if they are both within 1-2 of the nondes then we can assume same area, or DC

    // if they go through the same fiber taps in the middle its fine as well


    // we have other information such as leaks which will help us propagate the initial strategy

    // first we verify if any routes are the same
    // then we count the distance between them (first from the highest TTL)
    // we need to know if they are more than likely in the same region
    // then we can cross that information with other traceroutes which share some of the same routes
    // the point is to keep in memory all traceroutes to ensure we can reuse them..
    // for generatinng IPs it will be  important to attack particular countries, etc
    // especially when identities get involded (which would be better to keep particular to the region)..
    // especially chinese characters etc

    end:;

    return ret;
}



/*

traceroute spider

strategy: first go by how many hops are equal...
          then go by the distance between the hops (fromm either highest, or lowest ttl) 
          if the match is on the far side (by dividing the amount of hops)
          then it means its close on one side or the other (thus it shares fiber taps/surveillance nodes)

          its plausable sites are in located in the 'middle' of the traceroute in comparison to another.. because
          its data center is next to some major backbone

          this means other tactics need to take place such as geoip(prob nt reliable), or just coordination with other
          traceroutes
          to find closer, and closer routes to get a better accuracy

          so generally if its within 1-2 hops it can be considered a similar side although geoip on other IPs themselves (not
        the hops or routers) would help determine the location of these routes...

        so to find euro and USA routes.. we can geoip abunch of IP addresses in those countries (even go as far as states/cities) but
        that would require a bigger data file initially

        when we traceroute all the IPs and throw them into the traceroute spider it would help us determine by actual reports
        where each router more than likely is located
        anything going from country to country should be xpected to have a surveillance tap 
        especially USA -> Euro
        USA ->  China
        pretty much any country to another border


        i built a simple way to initialize the dataset without using extreme space, or other companies code
        ill include it for helping manipulate curreent mass surveillance platforms in a simple small compact manner
        even if its 10-20% wrong who cares.

        geoip = 6mb.. vs .. 1k? if that


        linking is simple.. 

        all hops need to be cross referenced

        for future: a network of p2p traceroutes could perform some pretty advanced research... i cant do everything from a single side
        but enough to handle this problem.. it would require constant updates though thus have to stay active

*/


// lets see if we have a hop already in the spider.. then we just add this as a branch of it
TracerouteSpider *Spider_Find(AS_context *ctx, uint32_t hop, struct in6_addr *hopv6) {
    TracerouteSpider *sptr = ctx->traceroute_spider;

    // enumerate through spider list tryinig to find a hop match...
    // next we may want to add looking for targets.. but in general
    // we will wanna analyze more hop informatin about a target ip
    // as its hops come back.. so im not sure if its required yet
    while (sptr != NULL) {
        if (hop != 0) {
            if (sptr->hop == hop)
                break;
        } else {
            if (CompareIPv6Addresses(&sptr->hopv6, hopv6)) 
                break;
        }

        sptr = sptr->next;
    }

    return sptr;
}


// Analyze a traceroute response against the current queue and build the spider web of traceroutes
// for further strategies
int TracerouteAnalyzeSingleResponse(AS_context *ctx, TracerouteResponse *rptr) {
    int ret = 0;
    TracerouteQueue *qptr = ctx->traceroute_queue;
    TracerouteSpider *sptr = NULL, *snew = NULL;

    printf("Traceroute Analyze Single responsse %p\n", rptr);

    // if the pointer was NULL.. lets just return with 0 (no error...)
    if (rptr == NULL) return ret;

    while (qptr != NULL) {
        // found a match since we are more than likely doing mass amounts of traceroutes...
        if (qptr->identifier == rptr->identifier) {
            printf("FOUND queue for this response! qptr  %p\n", qptr);
            break;
        }

        qptr = qptr->next;
    }

    // we had a match.. lets link it in the spider web
    if (qptr != NULL) {

        // if this hop responding matches an actual target in the queue... then that traceroute is completed
        if ((rptr->hop && rptr->hop == qptr->target) ||
            (!rptr->hop && !qptr->target && CompareIPv6Addresses(&rptr->hopv6, &qptr->targetv6))) {
                printf("Traceroute completed %p\n", qptr);
                qptr->completed = 1;
        }


        // allocate space for us to append this response to our interal spider web for analysis
        if ((snew = (TracerouteSpider *)calloc(1, sizeof(TracerouteSpider))) != NULL) {
            // we need to know which TTL later (for spider web analysis)
            snew->ttl = rptr->ttl;

            // take note of the hops address (whether its ipv4, or 6)
            snew->hop = rptr->hop;
            CopyIPv6Address(&snew->hopv6, &rptr->hopv6);

            // take noote of the target ip address
            snew->target_ip = qptr->target;
            CopyIPv6Address(&qptr->targetv6, &rptr->targetv6);
        }

        // determine if we have already started a structure for this hop in the spider web
        if ((sptr = Spider_Find(ctx, rptr->hop, &rptr->hopv6)) != NULL) {
            printf("couldnt find spider\n");
            // we found it as a spider.. so we can add it to a branch
            snew->branches = sptr->branches;
            sptr->branches = snew;
        } else {
            printf("found spider linked as a branch\n");
            // lets link directly to main list .. first time seeing this hop
            snew->next = ctx->traceroute_spider;
            ctx->traceroute_spider = snew;
        }

        ret = 1;
    }

    end:;
    return ret;
}

/*
maybe move commands instead of taking ipv4, and ipv6 separately... we can union.. and check 
if all other ipv6 bytes (that wouldnt get set fromm ipv4 due to small size) is 00s
typedef union {
    uint32_t target;
    struct in6_addr targetv6;
} target_ip;
*/

int Traceroute_Queue(AS_context *ctx, uint32_t target, struct in6_addr *targetv6) {
    TracerouteQueue *tptr = NULL;
    int ret = -1;

    printf("Traceroute Queue %d %d\n", target, *(int *)(targetv6));

    // allocate memory for this new traceroute target we wish to add into the system
    if ((tptr = (TracerouteQueue *)calloc(1, sizeof(TracerouteQueue))) == NULL) goto end;

    // which IP are we performing traceroutes on
    tptr->target = target;
    // if its an ipv6 addres pasased.. lets copy it (this function will verify its not NULL)
    CopyIPv6Address(&tptr->targetv6, targetv6);

    // we start at ttl 1.. itll inncrement to that when processing
    tptr->current_ttl = 0;

    // create a random identifier to find this packet when it comes from many hops
    tptr->identifier = rand()%0xFFFFFFFF;

    // later we wish to allow this to be set by scripting, or this function
    // for example: if we wish to find close routes later to share... we can set to max = 5-6
    // and share with p2p nodes when mixing/matching sides of the taps (when they decide to secure them more)
    tptr->max_ttl = MAX_TTL;

    // current timestamp stating it was added at this time
    tptr->ts = time(0);

    // add to traceroute queue...
    tptr->next = ctx->traceroute_queue;
    ctx->traceroute_queue = tptr;

    end:;
    return ret;
}


// if we have active traceroutes, then this function should take the incoming packet
// analyze it,  and determine if it relates to any active traceroute missions
// It should handle all types of packets... id say UDP/ICMP... 
// its a good thing since it wont have to analyze ALL tcp connections ;)
int Traceroute_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = -1;
    //PacketBuildInstructions *iptr = NULL;
    //PacketInfo *pnext = NULL;
    TracerouteResponse *rptr = NULL;
    TraceroutePacketData *pdata = NULL;

    // when we extract the identifier from the packet.. put it here..
    uint32_t identifier = 0;
    // ttl has to be extracted as well (possibly from the identifier)
    int ttl = 0;

    //printf("Got packet from network! data size %d\n", iptr->data_size);

    // data isnt big enough to contain the identifier
    if (iptr->data_size < sizeof(TraceroutePacketData)) goto end;

    pdata = (TraceroutePacketData *)iptr->data;
    // extract identifier+ttl here fromm the packet characteristics, or its data.. if its not a traceroute, just goto end
    //identifier = *(uint32_t *)(iptr->data);

    // ttl = right 16 bits
    //ttl = (identifier & 0x0000FFFF);

    // identifier = left 16 bits
    //identifier = (identifier & 0xFFFF0000) >> 16;
    ttl = pdata->ttl;
    identifier = pdata->identifier;

    //printf("incoming icmp ttl %d identifier %X\n", ttl, identifier);

    // allocate a new structure for traceroute analysis functions to deal with it later
    if ((rptr = (TracerouteResponse *)calloc(1, sizeof(TracerouteResponse))) == NULL) goto end;
    rptr->identifier = identifier;
    rptr->ttl = ttl;
    
    // copy over IP parameters
    rptr->hop = iptr->source_ip;
    CopyIPv6Address(&rptr->hopv6, &iptr->source_ipv6);

    // maybe lock a mutex here (have 2... one for incoming from socket, then moving from that list here)
    rptr->next = ctx->traceroute_responses;
    ctx->traceroute_responses = rptr;

    //printf("Created a TRACEROUTE response structure for this one\n");

    // thats about it for the other function to determine the original target, and throw it into the spider web
    ret = 1;

    end:;

    // free this since we wont need it anymore later
    //PacketBuildInstructionsFree(&iptr);

    // put this pointer back if it was there.. means the packet is in a chain linked w othters -- dont ruin that
    //if (pnext) pptr->next = pnext;

    return ret;
}




// iterate through all current queued traceroutes handling whatever circumstances have surfaced for them individually
int Traceroute_Perform(AS_context *ctx) {
    TracerouteQueue *tptr = ctx->traceroute_queue;
    TracerouteResponse *rptr = ctx->traceroute_responses, *rnext = NULL;
    uint32_t packet_data = 0;
    struct icmphdr icmp;
    PacketBuildInstructions *iptr = NULL;
    AttackOutgoingQueue *optr = NULL;
    int i = 0;
    TraceroutePacketData *pdata = NULL;

    memset(&icmp, 0, sizeof(struct icmphdr));

    int ret = 0;
    // timestamp required for various states of traceroute functionality
    int ts = time(0);

    // if the list is empty.. then we are done here
    if (tptr == NULL) goto end;

    // loop until we run out of elements
    while (tptr != NULL) {
        // if we have reached max ttl then mark this as completed.. otherwise it could be marked completed if we saw a hop which equals the target
        if (tptr->current_ttl >= MAX_TTL) {
            printf("traceroute completed\n");
            tptr->completed = 1;
        }

        if (!tptr->completed) {
            // lets increase TTL every 10 seconds.. id like to perform thousands of these at all times.. so 10 seconds isnt a big deal...
            // thats 5 minutes till MAX ttl (30)
            if ((ts - tptr->ts_activity) > 1) {

                //tptr->ts_activity = time(0);

                printf("traceroute activity timer.. increasing ttl %d\n", tptr->current_ttl);
                tptr->current_ttl++;

                // lets merge these two variables nicely into a 32bit variable for the ICMP packet  (to know which request when it comes back)
                // using it like this allows us to perform mass scans using a small amount of space
                // it ensures we can keep a consistent queue of active traceroutes
                packet_data = (((tptr->identifier << 16) & 0xFFFF0000) | (tptr->current_ttl & 0x0000FFFF));

                icmp.type = ICMP_ECHO;
                icmp.code = 0;
                // i forgot about these.. might be able to use them as identifer/ttl
                icmp.un.echo.sequence = tptr->identifier;
                icmp.un.echo.id = tptr->current_ttl;

                // make packet, or call funnction to handle that..
                // mark some identifier in tptr for Traceroute_Incoming()

                if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
                    if (tptr->target != 0) {
                        iptr->type = PACKET_TYPE_ICMP_4;
                        iptr->destination_ip = tptr->target;
                        iptr->source_ip = get_local_ipv4();
                    } else {
                        iptr->type = PACKET_TYPE_ICMP_6;
                        CopyIPv6Address(&iptr->destination_ipv6, &tptr->targetv6);
                        get_local_ipv6(&iptr->source_ipv6);
                    }

                    // copy ICMP parameters into this instruction packet
                    memcpy(&iptr->icmp, &icmp, sizeof(struct icmphdr));

                    

                    iptr->data_size = sizeof(TraceroutePacketData);
                    iptr->data = (char *)calloc(1, iptr->data_size);
                    if (iptr->data != NULL) {
                        pdata = (TraceroutePacketData *)iptr->data;
                        pdata->identifier = tptr->identifier;
                        pdata->ttl = tptr->current_ttl;
                        printf("%d %X\n", pdata->ttl, pdata->identifier);   
                    }

                    

                    // ok so we need a way to queue an outgoing instruction without an attack structure....
                    // lets build a packet from the instructions we just designed
                    // lets build whichever type this is by calling the function directly from packetbuilding.c
                    // for either ipv4, or ipv6
                    if (iptr->type & PACKET_TYPE_ICMP_6)
                        i = BuildSingleICMP6Packet(iptr);
                    else if (iptr->type & PACKET_TYPE_ICMP_4)
                        i = BuildSingleICMP4Packet(iptr);

                    if (i == 1) {
                        if ((optr = (AttackOutgoingQueue *)calloc(1, sizeof(AttackOutgoingQueue))) != NULL) {
                            optr->buf = iptr->packet;
                            optr->type = iptr->type;
                            optr->size = iptr->packet_size;

                            iptr->packet = NULL;
                            iptr->packet_size = 0;

                            // if we try to lock mutex to add the newest queue.. and it fails.. lets try to pthread off..
                            if (AttackQueueAdd(ctx, optr, 1) == 0) {
                                // create a thread to add it to the network outgoing queue.. (brings it from 4minutes to 1minute) using a pthreaded outgoing flusher
                                if (pthread_create(&optr->thread, NULL, AS_queue_threaded, (void *)optr) != 0) {
                                    // if we for some reason cannot pthread (prob memory).. lets do it blocking
                                    AttackQueueAdd(ctx, optr, 0);
                                }
                            }
                        }
                    }

                    // dont need this anymore..
                    PacketBuildInstructionsFree(&iptr);


                } else {
                    // maybe issue w memory? lets roll back and let the next round try
                    tptr->current_ttl--;
                    break;
                }
            }
        }

        tptr = tptr->next;
    }


    // now process all queued responses we have
    rptr = ctx->traceroute_responses;

    // loop until all responsses have been analyzed
    while (rptr != NULL) {
        // call this function which will take care of the response, and build the traceroute spider for strategies
        TracerouteAnalyzeSingleResponse(ctx, rptr);

        // get pointer to next so we have it after freeing
        rnext = rptr->next;

        // free this response structure..
        free(rptr);

        // move to next
        rptr = rnext;
    }

    ctx->traceroute_responses = NULL;


    end:;
    return ret;
}


//http://www.binarytides.com/get-local-ip-c-linux/
uint32_t get_local_ipv4() {
    const char* google_dns_server = "8.8.8.8";
    int dns_port = 53;
    uint32_t ret = 0;
     
    struct sockaddr_in serv;
     
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);
     if (sock < 0) return 0;
     
    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr( google_dns_server );
    serv.sin_port = htons( dns_port );
 
    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
     
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
         
    ret = name.sin_addr.s_addr;

    close(sock);
     
    return ret;
}

// fromm //http://www.binarytides.com/get-local-ip-c-linux/ as above..
// but modified for ipv6
void get_local_ipv6(struct in6_addr *dst) {
    const char* google_dns_server = "2001:4860:4860::8888";
    int dns_port = 53;
    uint32_t ret = 0;

    struct sockaddr_in6 serv;

    int sock = socket ( AF_INET6, SOCK_DGRAM, 0);
     if (sock < 0) return 0;

    memset( &serv, 0, sizeof(serv) );
    serv.sin6_family = AF_INET6;
    inet_pton(AF_INET6, google_dns_server, &serv.sin6_addr);
    serv.sin6_port = htons( dns_port );

    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

    struct sockaddr_in6 name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);

    memcpy(dst, &name.sin6_addr, sizeof(struct in6_addr));

    close(sock);

}


// initialize traceroute research subsystem
// this has to prepare the incoming packet filter, and structure so we get iniformation from the wire
int Traceroute_Init(AS_context *ctx) {
    NetworkAnalysisFunctions *nptr = NULL;
    FilterInformation *flt = NULL;
    int ret = -1;

    flt = (FilterInformation *)calloc(1, sizeof(FilterInformation));
    nptr = (NetworkAnalysisFunctions *)calloc(1, sizeof(NetworkAnalysisFunctions));

    if (!flt || !nptr) goto end;

    // lets just ensure we obtain all ICMP packet information since we'll have consistent ipv4/ipv6 requests happening
    FilterPrepare(flt, FILTER_PACKET_ICMP, 0);

    // prepare structure used by the network engine to ensure w get the packets we are looking for
    nptr->incoming_function = &Traceroute_Incoming;
    nptr->flt = flt;

    // insert so the network functionality will begin calling our function for these paackets
    nptr->next = ctx->IncomingPacketFunctions;
    ctx->IncomingPacketFunctions = nptr;

    ret = 1;

    end:;

    // free structures if they were not used for whatever reasons
    if (ret != 1) {
        PtrFree(&flt);
        PtrFree(&nptr);
    }

    return ret;
}
