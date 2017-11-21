#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "network.h"
#include "antisurveillance.h"
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
    if (!first->traceroute_responses_count_v4 || !second->traceroute_responses_count_v4)
        return ret;


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
        ill include it for helpinng detect curreent mass surveillance platforms in a simple small compact manner
        even if its 10-20% wrong who cares.

        geoip = 6mb.. vs .. 1k? if that
*/
typedef struct _traceroute_spider {
    //routine linked list management..
    struct _traceroute_spider *next;

    // branches is like next but for all branches (this hop matches anothers)
    struct _traceroute_spider *branches;

    // the queue which linked into this tree
    TracerouteQueue *queue;

    // quick reference of IP
    uint32_t IP;

    // determined country code
    int country_code;

} TracerouteSpider;



// OK ICMP/UDP is finished.. time for the real fun.. this will def catch some eyes once people realize how you can programmatically
// target mass surveillance platforms ... without that much effort really.
// while coding this im using ipv4 .. will change later.... still need to add ipv6 anyways
int Traceroute_Queue(AS_context *ctx, uint32_t target_node) {
    TracerouteQueue *tptr = NULL;
    int ret = -1;

    // allocate memory for this new traceroute target we wish to add into the system
    if ((tptr = (TracerouteQueue *)calloc(1, sizeof(TracerouteQueue))) == NULL) goto end;

    // which IP are we performing traceroutes on
    tptr->ipv4 = target_node;

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
    int ret = 0;

    end:;
    return ret;
}


// iterate through all current queued traceroutes handling whatever circumstances have surfaced for them individually
int Traceroute_Perform(AS_context *ctx) {
    TracerouteQueue *tptr = ctx->traceroute_queue;
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
            // make packet, or call funnction to handle that..
            // mark some identifier in tptr for Traceroute_Incoming()
        }

        tptr = tptr->next;
    }


    end:;
    return ret;
}