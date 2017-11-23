#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
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

//cpoints is a basic map of the globe.. with somme countries and their general regions marked...
//it is a extremely small way to pick regions of importance for analysis without containing a ton of information

[00,11],[01,22],[21,31],[31,42],[41,53],[55,54],[54,53],[05,15],[14,22],[03,15],[24,35],[00,00]

0                       1                                  2                         3                          4                              5







1                     11                                  21                        31                         41                              51







2                      12                                  22                        32                         42                            52






3                     13                                   23                         33                         43                           53





4                      14                                  24                       34                            44                           54



5                     15                                25                            35                            45                          55



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

typedef struct _traceroute_spider {
    //routine linked list management..
    struct _traceroute_spider *next;

    // branches is like next but for all branches (this hop matches anothers)
    struct _traceroute_spider *branches;

    // the queue which linked into this tree
    // it wiill get removed fromm the active list to speed up the process
    // of analyzing responses... but itll stay linked here for the original
    // information for the strategies for picking targets for blackholing and sureillance attacks
    TracerouteQueue *queue;

    // time this entry was created
    int ts;

    // quick reference of IP (of the router.. / hop / gateway)
    uint32_t hop;
    struct in6_addr hopv6;

    // what was being tracerouted to conclude this entry
    uint32_t target_ip;

    // TTL (hops) in which it was found
    int ttl;

    // determined country code
    int country_code;

    // we may want ASN information to take the fourteen eyes list, and assume
    // all internet providers which are worldwide, and located in other countries
    // fromm those countries are going to also have their own pllatforms in those
    // other locations
    // so we will do ASN -> companies (as an identifer)
    // future: all of these strategies can get incorporated into future automated, and mass hacking campaigns
    int asn;
} TracerouteSpider;


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


// when reading the traceroute responses from the raw socket.. it should get added into this list immediately
// further information could be handled from another thread, or queue... this ensures less packet loss than
// dealing with anything inline as it comes in.. and also allows dumping the data to a save file
// for the spider in the future to pick & choose mass surveillance platforms
typedef struct _traceroute_response {
    struct _traceroute_response *next;

    // to know where the packet relates to
    uint32_t identifier;

    int ttl;

    // the hop which responded
    uint32_t hop;
    // or its ipv6
    struct in6_addr hopv6;

    // if we correlated the identifier with the target
    uint32_t target;
    struct in6_addr targetv6;
} TracerouteResponse;


// Analyze a traceroute response against the current queue and build the spider web of traceroutes
// for further strategies
int TracerouteAnalyzeSingleResponse(AS_context *ctx, TracerouteResponse *rptr) {
    int ret = 0;
    TracerouteQueue *qptr = ctx->traceroute_queue;
    TracerouteSpider *sptr = NULL, *snew = NULL;

    // if the pointer was NULL.. lets just return with 0 (no error...)
    if (rptr == NULL) return ret;

    while (qptr != NULL) {
        // found a match since we are more than likely doing mass amounts of traceroutes...
        if (qptr->identifier == rptr->identifier) {
            break;
        }

        qptr = qptr->next;
    }

    // we had a match.. lets link it in the spider web
    if (qptr != NULL) {
        if ((snew = (TracerouteSpider *)calloc(1, sizeof(TracerouteSpider))) != NULL) {
            snew->hop = rptr->hop;
            snew->ttl = rptr->ttl;
            CopyIPv6Address(&snew->hopv6, &rptr->hopv6);
            snew->target_ip = qptr->target;
            CopyIPv6Address(&qptr->targetv6, &rptr->targetv6);
        }

        if ((sptr = Spider_Find(ctx, rptr->hop, &rptr->hopv6)) != NULL) {
            // we found it as a spider.. so we can add it to a branch
            snew->branches = sptr->branches;
            sptr->branches = snew;
        } else {
            // lets link directly to main list .. first time seeing this hop
            snew->next = ctx->traceroute_spider;
            ctx->traceroute_spider = snew;
        }

        ret = 1;
    }

    end:;
    return ret;
}




// OK ICMP/UDP is finished.. time for the real fun.. this will def catch some eyes once people realize how you can programmatically
// target mass surveillance platforms ... without that much effort really.
// while coding this im using ipv4 .. will change later.... still need to add ipv6 anyways
int Traceroute_Queue(AS_context *ctx, uint32_t target, struct in6_addr *targetv6) {
    TracerouteQueue *tptr = NULL;
    int ret = -1;

    // allocate memory for this new traceroute target we wish to add into the system
    if ((tptr = (TracerouteQueue *)calloc(1, sizeof(TracerouteQueue))) == NULL) goto end;

    // which IP are we performing traceroutes on
    tptr->target = target;
    // if its an ipv6 addres pasased.. lets copy it (this function will verify its not NULL)
    CopyIPv6Address(&tptr->targetv6, targetv6);

    // we start at ttl 1.. itll inncrement to that when processing
    tptr->current_ttl = 0;

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
int Traceroute_Incoming(AS_context *ctx, PacketInfo *pptr) {
    int ret = -1;
    PacketBuildInstructions *iptr = NULL;
    PacketInfo *pnext = NULL;
    TracerouteResponse *rptr = NULL;

    // when we extract the identifier from the packet.. put it here..
    uint32_t identifier = 0;
    // ttl has to be extracted as well (possibly from the identifier)
    int ttl = 0;

    // analyze the packet to ensure it IS one of our traceroutes.. just inn casae a filter, or other way let it through
    // im not rewriting code here when ive already designed all of the analysis for other parts..
    // if its linked to something, lets unlink.. turn into PacketBuildInstructions type
    // so we can easily have access to all parameters of this packet..
    pnext = pptr->next;
    pptr->next = NULL;

    // if we cant analyze it, then we are done here
    if ((iptr = PacketsToInstructions(pptr)) == NULL) goto end;

    // data isnt big enough to contain the identifier
    if (iptr->data_size < sizeof(uint32_t)) goto end;

    // extract identifier+ttl here fromm the packet characteristics, or its data.. if its not a traceroute, just goto end
    identifier = *(uint32_t *)(iptr->data);

    // ttl = right 16 bits
    ttl = (identifier & 0x0000FFFF);

    // identifier = left 16 bits
    identifier = (identifier & 0xFFFF0000) >> 16;

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

    // thats about it for the other function to determine the original target, and throw it into the spider web
    ret = 1;

    end:;

    // free this since we wont need it anymore later
    PacketBuildInstructionsFree(&iptr);

    // put this pointer back if it was there.. means the packet is in a chain linked w othters -- dont ruin that
    if (pnext) pptr->next = pnext;

    return ret;
}




// iterate through all current queued traceroutes handling whatever circumstances have surfaced for them individually
int Traceroute_Perform(AS_context *ctx) {
    TracerouteQueue *tptr = ctx->traceroute_queue;
    TracerouteResponse *rptr = ctx->traceroute_responses;
    uint32_t packet_data = 0;
    struct icmphdr icmp;
    PacketBuildInstructions *iptr = NULL;
    AttackOutgoingQueue *optr = NULL;

    int ret = 0;
    // timestamp required for various states of traceroute functionality
    int ts = time(0);

    // if the list is empty.. then we are done here
    if (tptr == NULL) goto end;

    // loop until we run out of elements
    while (tptr != NULL) {

        // lets increase TTL every 5 seconds
        if ((ts - tptr->ts_activity) > 5) {
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
                    // we need source ip here!
                } else {
                    iptr->type = PACKET_TYPE_ICMP_6;
                    CopyIPv6Address(&iptr->destination_ipv6, &tptr->targetv6);
                    // we need source ip here!
                }

                /*

                iptr->data_size = sizeof(uint32_t);
                iptr->data = (char *)calloc(1, iptr->data_size);
                if (iptr->data != NULL) *(uint32_t *)(iptr->data) = packet_data;

                */

                // ok so we need a way to queue an outgoing instruction without an attack structure....
                if ((optr = (AttackOutgoingQueue *)calloc(1, sizeof(AttackOutgoingQueue))) != NULL) {
                    optr->buf = iptr->packet;
                    optr->type = iptr->type;
                    optr->size = iptr->packet_size;

                    iptr->packet = NULL;
                    iptr->packet_size = 0;

                    // *** this is blocking... maybe change later 
                    AttackQueueAdd(ctx, optr, 0);
                }

                // dont need this anymore..
                PacketBuildInstructionsFree(&iptr);


            } else {
                // maybe issue w memory? lets roll back and let the next round try
                tptr->current_ttl--;
                break;
            }
        }

        tptr = tptr->next;
    }


    end:;
    return ret;
}
