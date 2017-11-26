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
#include <stddef.h> /* For offsetof */
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "research.h"
#include "utils.h"


#ifndef offsetof
#define offsetof(type, member) ( (int) & ((type*)0) -> member )
#endif



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

inf recursion was happening because all nodes are linked several ways...
now what to do: we first  find the node in the main list (both of them)
then we only search branches from there (one at a time fromm each node)

and we can prob do this inside of the samee function rather than recursion whic will allow
keepng context infromationw ithout a structure, or passing variables around

1st ver w infinite: it was scanning the entire list, and then branching into it recursively whene it found one..
which was scanning branches.. which means each might get hit a lot of times, and regardless.. the calll itself was taking a lot of
resource, even after using 'search_contex'


*/

// this can be handeled recursively because we have max TTL of 30.. its not so bad
int Traceroute_Search(TracerouteSpider *start, TracerouteSpider *looking_for, int distance) {
    TracerouteSpider *search = NULL;
    TracerouteSpider *search_branch = NULL;
    int cur_distance = distance;
    int ret = 0;
    int ttl_diff = 0;

    // if distance is moore than max ttl.. lets return
    if (distance >= MAX_TTL) return 0;

    // if pointers are NULL for some reason
    if (!start || !looking_for) return 0;

    // ensure we dont go in infinite loop
    if (start->search_context.second == looking_for) return 0;
    start->search_context.second = looking_for;

    // dbg msg
    printf("Traceroute_Search: start %p [%u] looking for %p [%u] distance: %d\n",  start, start->hop_ip, looking_for, looking_for->hop_ip, distance);
    
    // use context here and use the next list..
    search = start;
    
    // first we search all branches, and perform it recursively as well...
    while (search != NULL) {

        if (search->branches) {
            // increase distance since we are accessing a branch
            cur_distance++;

            // get the first element
            search_branch = search->branches;
        
            // we will loop until its NULL
            while (search_branch != NULL) {
/*

we should start looking for TARGETs .. not necessarily hops..
hops are just used to connect the various nodes... although if a target is not found we must traceroute it, and hope it matches
and if it doesnt match we need enough IPs in various locations to attempt to fill in the blank
(there should be a way to queue for IP investigations, or modify the IP to adjust as close as possible)
just to ensure we go through the fiber taps which we were targeting
also we need to modify for other reasons thatll be clear soon to pull all 3 types of attacks together :)


192.168.0.1         192.168.0.1         
cox nola            cox nola            
cox houston                         cox houston                 cox houston
                                                                                        cox L

Traceroute_FindByHop
Traceroute_FindByTarget
Traceroute_FindByIdentifier

when target -> identifier -> hop 

hop -> branch (doesnt count as increment in distance.. its the same.. but once it leaves that structure
to spider another identifier (diff ttl hop in same identifier/query) then it increments

branch -> branch doesnt increment

target -> hop increments
hop -> target increments




*/
                // if the IPv4 address matches.. we found it.. now we have to walk all paths until we literally reach it
                // not just a pointer in the linked list... we have to see how many steps to arrive
                if (search_branch->hop_ip == looking_for->hop_ip) {





                    
                }

                // if not.. then we wanna recursively search this branch.. so increase distance, and  hit this function with this pointer
                //ret = Traceroute_Search(search_branch, looking_for, cur_distance + 1);

                // if it was found..return the distance
                //if (ret) return ret;

                // move to the next branch in this list
                search_branch = search_branch->branches;
            }

            // we decrement hte distance since it wasn't used...
            cur_distance--;
        }

        // movve to the next traceroute response in our main list
        search = search->next;
    }

    return ret;
    // disabling anything under here .. dev'ing maybe rewrite
    /*
    // next we wanna search fromm the  identifiers list (it could be 2 routers away) so distance of 2..
    search = start->identifiers;

    // increase distance so that it is calculated correctly if it finds the needle in this haystack
    cur_distance++;
    // loop until the identifier list is completed..
    while (search != NULL) {

        // does the IPv4 address match?
        if (start->hop_ip == looking_for->hop_ip) {
            // calculate the TTL difference (which tells how many hops away.. which is pretty mcuh the same as branches)
            ttl_diff = start->ttl - looking_for->ttl;

            // if its <0 it means the start->ttl was alrady lower.. lets just get the absolute integer( turn negative to positive)
            if (ttl_diff < 0) ttl_diff = abs(ttl_diff);

            // if we have a value then add the current distance to it
            if (ttl_diff) {
                // set ret so that it returns it to the calling function
                ret = ttl_diff + cur_distance;
                break;
            }

            // otherwise we wanna go into this identifiers branch

            // *** this was recursively doing an inf loop.. will fix soon
            search_branch = NULL; // search->branches;

            // we will loop until all the branches have been checked
            while (search_branch != NULL) {
                // we wanna check branches of that traceroute (identifier) we are checking    

                // increase the distance, and call this function again to recursively use the same algorithm
                ret = Traceroute_Search(search_branch, looking_for, cur_distance+1);

                    // if it was found..
                if (ret) return ret;

                // move to the  next branch in this identifier list
                search_branch = search_branch->branches;
            }
        }

        // move to the next hop in this traceroute (identifier) list
        search = search->identifiers;
    }

    // decrement the distance (just to keep things clean)
    cur_distance--;

    return ret;*/
}

// traceroutes are necessary to ensure a single nonde running this code can affect all mass surveillance programs worldwide
// it allows us to ensure we cover all places we expect them to be.. in the world today: if we expect it to be there.. then it
// probably is (for mass surveillance programs)
//https://www.information.dk/udland/2014/06/nsa-third-party-partners-tap-the-internet-backbone-in-global-surveillance-program
// we want to go through asa many routes as possible which means we are innjecting information into each surveillance tap along the way
// the other strategy will be using two nodes running this code which will be on diff parts of the world so we ca ensure eah side of the packets
// get processed correctly.. in the begininng (before they modify) it wont matter.. later once they attempt to filter out, and procecss
// it might matter but it'll make the entire job/technology that much more difficult
int Traceroute_Compare(AS_context *ctx, TracerouteSpider *first, TracerouteSpider *second) {
    int ret = 0;
    TracerouteSpider *srch_main = NULL;
    TracerouteSpider *srch_branch = NULL;
    int distance = 0;

    // make sure both were passed correctly
    if (!first || !second) return -1;

    // if they are the same..
    if (first->hop_ip == second->hop_ip) return 1;

    // we wanna call this function Traceroute_Search to find the distance  of the two spider parameters passed
    distance = Traceroute_Search(first, second, 0);

    // print distance to screen
    printf("distance: %d\n", distance);

    // prepare to return it..
    ret = distance;


// There will be more code going into here....it needs to update other context automatically after things have been investigated..
// we want a list of probable surveillance platforms worldwide, and their countries... IP addresses of clientts, and servers

// we also want a list of KNOWN platforms (from leaks, or other information) and the information here
// to possibly search near those to get more servers/cleints for attacks


    // so we need to determine the distance between two nodes using our research information
    // its possible these nodes are in branches so we must check both.. 
    // the further from US the two nodes are means they will go through  several routers, and
    // if they are near each other (same country) then it means that if we send packets from
    // where we are, then both sides of the connection will go through many routers.. thus
    // injecting  information into these platforms

    // 1) sort by hops descending...
    // 2) find things with high amounts of hops from us
    // but in the spider web we see they both go through some router and are a low amount of hops between each other
    // if that hop/router is used for a lot of sites then we can assume its a backbone, and probably tapped
    // remember: the packets wont really harm much except some bandwidth (which isnt a huge deal these days)
    // but these platforms will log the information, and process it.. therefore a small price to pay for
    // the resource wastes of these platforms

    // 3) if we cannot find matches for things we are sure are behind backbones, then we can generate Ips
    // for a country which is on the other side (by taking all things on the other side (high hops)) and geoip it
    // then finding ones with none, or small amount.. then we generate geo IP fromm that region, and append them
    // into the traceroute queue

    // this means in the future the analysis system will have information for continuinng the process
    // with those nodes

    // also can find missing TTL from search, and resend those packets once, and then mark it as no more retry


    // find similar hops (if exist) .. if so
    //    find all similars identifiers.. and count distance..
    //    keep track of similar/close distances so we can check if there are alternatives






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
// *** verify IPv6 (change arguments.. use IP_prepare)
TracerouteSpider *Spider_Find(AS_context *ctx, uint32_t hop, struct in6_addr *hopv6) {
    TracerouteSpider *sptr = ctx->traceroute_spider_hops;

    // enumerate through spider list tryinig to find a hop match...
    // next we may want to add looking for targets.. but in general
    // we will wanna analyze more hop informatin about a target ip
    // as its hops come back.. so im not sure if its required yet
    while (sptr != NULL) {
        //printf("hop %u sptr %u\n", hop, sptr->hop);
        if (hop && sptr->hop_ip == hop) {
                break;
        } else {
            //if (!hop && CompareIPv6Addresses(&sptr->hopv6, hopv6))  break;
        }

        sptr = sptr->hops_list;
    }

    return sptr;
}





// count the branches in a spider's structure.. i needed this quick.. maybe redesign for other variables w options to choose
int branch_count(TracerouteSpider *sptr) {
    int ret = 0;
    while (sptr != NULL) {
        ret++;
        sptr = sptr->branches;
    }
    return ret;
}


// link with other traceroute structures of the same queue (same target/scan)
int Spider_IdentifyTogether(AS_context *ctx, TracerouteSpider *sptr) {
    TracerouteSpider *srch = ctx->traceroute_spider;
    int ret = 0;

    // we wanna enumerate all and find the first
    while (srch != NULL) {

        // if it matches the same ID
        if (srch->identifier_id == sptr->identifier_id) {

            // link using the multidimensional (which requires offset of its 'next')
            L_link_ordered_offset((LINK **)&srch->identifiers, (LINK *)sptr, offsetof(TracerouteSpider, identifiers));

            ret = 1;
            break;
        }

        // mvoe to the next one
        srch = srch->next;
    }

    return ret;
}


// Analyze a traceroute response again  st the current queue and build the spider web of traceroutes
// for further strategies
int TracerouteAnalyzeSingleResponse(AS_context *ctx, TracerouteResponse *rptr) {
    int ret = 0;
    TracerouteQueue *qptr = ctx->traceroute_queue;
    TracerouteSpider *sptr = NULL, *snew = NULL;
    TracerouteSpider *hopptr = NULL;
    struct in_addr src;
    int i = 0;
    int left = 0;

    //printf("Traceroute Analyze Single responsse %p\n", rptr);

    // if the pointer was NULL.. lets just return with 0 (no error...)
    if (rptr == NULL) return ret;

    // enumerate all currently queued traceroutes looking for the identifier from the packet
    while (qptr != NULL) {
        //printf("qptr ident: %X  rptr ident %X\n", qptr->identifier, rptr->identifier);
        // found a match since we are more than likely doing mass amounts of traceroutes...
        if (qptr->identifier == rptr->identifier) {
            //printf("FOUND queue for this response! qptr  %p\n", qptr);
            //exit(0);
            break;
        }

        qptr = qptr->next;
    }

    //src.s_addr = rptr->hop;
    //printf("Response IP: %s\n", inet_ntoa(src));
    
    // we had a match.. lets link it in the spider web
    if (qptr != NULL) {
        // if this hop responding matches an actual target in the queue... then that traceroute is completed
        if ((rptr->hop_ip && rptr->hop_ip == qptr->target_ip) ||
            (!rptr->hop_ip && !qptr->target_ip && CompareIPv6Addresses(&rptr->hop_ipv6, &qptr->target_ipv6))) {

                //printf("------------------\nTraceroute completed %p [%u %u]\n-------------------\n", qptr, rptr->hop, qptr->target);
                // normal non randomized traceroute TTLs we just mark it as completed
                //qptr->completed = 1;

                //  If we are doing TTLs in random order rather than incremental.. then lets enumerate over all of the ttls for this queue
                for (i = 0; i < MAX_TTL; i++) {
                    // if a TTL is higher than the current then it should be disqualified..
                    if (qptr->ttl_list[i] >= rptr->ttl) qptr->ttl_list[i] = 0;
                    // and while we are at it.. lets count how  many is left.. (TTLs to send packets for)
                    if (qptr->ttl_list[i] != 0) left++;
                }

                // if all TTLs were already used.. then its completed
                if (!left) qptr->completed = 1;
        }

        // allocate space for us to append this response to our interal spider web for analysis
        if ((snew = (TracerouteSpider *)calloc(1, sizeof(TracerouteSpider))) != NULL) {
            // we need to know which TTL later (for spider web analysis)
            snew->ttl = rptr->ttl;

            // ensure we log identifier so we can connect all for target easily
            snew->identifier_id = qptr->identifier;

            // take note of the hops address (whether its ipv4, or 6)
            snew->hop_ip = rptr->hop_ip;
            CopyIPv6Address(&snew->hop_ipv6, &rptr->hop_ipv6);

            // take note of the target ip address
            snew->target_ip = qptr->target_ip;
            CopyIPv6Address(&qptr->target_ipv6, &rptr->target_ipv6);

            // in case later we wanna access the original queue which created the entry
            snew->queue = qptr;
            
            // link into list containing all..
            L_link_ordered_offset((LINK **)&ctx->traceroute_spider, (LINK *)snew, offsetof(TracerouteSpider, next));

            // now lets link into 'hops' list.. all these variations are required for final strategy
            if ((sptr = Spider_Find(ctx, snew->hop_ip, &snew->hop_ipv6)) != NULL) {
                //printf("--------------\nFound Spider %p [%u] branches %d\n", sptr->hop, snew->hop, branch_count(sptr->branches));

                // we found it as a spider.. so we can add it as a BRANCH to a hop (the router which responded is already listed)
                L_link_ordered_offset((LINK **)&sptr->branches, (LINK *)snew, offsetof(TracerouteSpider, branches));
            } else {
                // we couldnt find this hop/router so we add it as new
                L_link_ordered_offset((LINK **)&ctx->traceroute_spider_hops, (LINK *)snew, offsetof(TracerouteSpider, hops_list));
            }

            // link with other from same traceroute queue (by its identifier ID)...
            // this is another dimension of the strategy.. required .. branches of a single hop wasnt enough
            Spider_IdentifyTogether(ctx, snew);

            ret = 1;
        }
    }

    end:;
    return ret;
}


// Queue an address for traceroute analysis/research
int Traceroute_Queue(AS_context *ctx, uint32_t target, struct in6_addr *targetv6) {
    TracerouteQueue *tptr = NULL;
    int ret = -1;
    int i = 0;
    int n = 0;
    int ttl = 0;
    struct in_addr addr;

    addr.s_addr = target;
    //printf("\nTraceroute Queue %u: %s\n", target, inet_ntoa(addr));

    // allocate memory for this new traceroute target we wish to add into the system
    if ((tptr = (TracerouteQueue *)calloc(1, sizeof(TracerouteQueue))) == NULL) goto end;

    // which IP are we performing traceroutes on
    tptr->target_ip = target;


    // if its an ipv6 addres pasased.. lets copy it (this function will verify its not NULL)
    CopyIPv6Address(&tptr->target_ipv6, targetv6);

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
    L_link_ordered_offset((LINK **)&ctx->traceroute_queue, (LINK *)tptr, offsetof(TracerouteQueue, next));

    i = 0;
    // lets randomize TTLs to bypass some filters..
    while (i < MAX_TTL) {
        // first set each to the proper ttl..
        tptr->ttl_list[i] = i;

        i++;
    }

    // this randomizes ttls so routes that get a lot of packets wont get them all at once
    
    i = 0;
    // now we must randomize the TTLs.. lets do the first 15 hops.. since thats where the MAJORITY will be
    // this means we wont send too many hosts several ICMP packets
    // example: if it respoonds at 26.. we disqualify 27-30
    //          but we may send it 25,24,23 like this... but if randomize 0-15.. 
    //          we will probably get the majority low.. and we can go fromm 0-30 at 15+
    //          i was mainly worried about too many packets going to the 0-3 (internal near the commputer sending)
    // I believe this will allow us to perform more traceroutes overall.. since we are not going in a consistent pack
    //   of 50 to each route everytime

    // its even quite possible this could decrease the amount of packets required.. by disqualifying higher ttls
    // earlier... ill try to incorporate further strategies later...


    // randomize TTLs between 0 and 15 (so each hop doesnt get all 50 at once.. higher chance of scanning  probability of success)    
    for (i = 0; i < 15; i++) {
        // array randomization
        // pick which 0-15 we will exchange the current one with
        n = rand()%15;
        // use 'ttl' as temp variable to hold that TTL we want to swap
        ttl = tptr->ttl_list[n];

        // swap it with this current enumeration by the i for loop
        tptr->ttl_list[n] = tptr->ttl_list[i];

        // move from swapped variable to complete the exchange
        tptr->ttl_list[i] = ttl;
    }

    // same as above just for 20-30..
    for (i = 20; i <MAX_TTL; i++) {
        n = i + (rand()%(MAX_TTL - i));
        ttl = tptr->ttl_list[n];
        tptr->ttl_list[n] = tptr->ttl_list[i];
        tptr->ttl_list[i] = ttl;
    }


    end:;
    return ret;
}


// When we initialize using Traceroute_Init() it added a filter for ICMP, and set this function
// as the receiver for any packets seen on the wire thats ICMP
int Traceroute_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = -1;
    struct in_addr cnv;
    TracerouteResponse *rptr = NULL;
    TraceroutePacketData *pdata = NULL;

    // when we extract the identifier from the packet.. put it here..
    uint32_t identifier = 0;
    // ttl has to be extracted as well (possibly from the identifier)
    int ttl = 0;

    //printf("incoming\n");

    if (iptr->source_ip && (iptr->source_ip == ctx->my_addr_ipv4)) {
        //printf("ipv4 Getting our own packets.. probably loopback\n");
        return 0;
    }

    if (!iptr->source_ip && CompareIPv6Addresses(&ctx->my_addr_ipv6, &iptr->source_ipv6)) {
        //printf("ipv6 Getting our own packets.. probably loopback\n");
        return 0;
    }
        
    // data isnt big enough to contain the identifier
    if (iptr->data_size < sizeof(TraceroutePacketData)) goto end;

    // the responding hops may have encapsulated the original ICMP within its own.. i'll turn the 28 into a sizeof() calculation
    // ***
    if (iptr->data_size > sizeof(TraceroutePacketData) && ((iptr->data_size >= sizeof(TraceroutePacketData) + 28)))
        pdata = (TraceroutePacketData *)(iptr->data + 28);//(sizeof(struct iphdr) + sizeof(struct icmphdr)));
    else
        pdata = (TraceroutePacketData *)iptr->data;

    /*
    printf("Got packet from network! data size %d\n", iptr->data_size);
    //printf("\n\n---------------------------\nTraceroute Incoming\n");

    cnv.s_addr = iptr->source_ip;
    printf("SRC: %s %u\n", inet_ntoa(cnv), iptr->source_ip);

    cnv.s_addr = iptr->destination_ip;
    printf("DST: %s %u\n", inet_ntoa(cnv), iptr->destination_ip);
    */

    // the packet has the TTL, and the identifier (to find the original target information)
    ttl = pdata->ttl;
    identifier = pdata->identifier;

    // this function is mainly to process quickly.. so we will fill another structure so that it can get processed
    // later again with calculations directly regarding its query

    // allocate a new structure for traceroute analysis functions to deal with it later
    if ((rptr = (TracerouteResponse *)calloc(1, sizeof(TracerouteResponse))) == NULL) goto end;
    rptr->identifier = identifier;
    rptr->ttl = ttl;
    
    // copy over IP parameters
    rptr->hop_ip = iptr->source_ip;
    CopyIPv6Address(&rptr->hop_ipv6, &iptr->source_ipv6);

    // maybe lock a mutex here (have 2... one for incoming from socket, then moving from that list here)
    L_link_ordered_offset((LINK **)&ctx->traceroute_responses, (LINK *)rptr, offsetof(TracerouteResponse, next));

    // thats about it for the other function to determine the original target, and throw it into the spider web
    ret = 1;

    end:;

    // iptr gets freed in the calling function
    return ret;
}


static int ccount = 0;


// iterate through all current queued traceroutes handling whatever circumstances have surfaced for them individually
int Traceroute_Perform(AS_context *ctx) {
    TracerouteQueue *tptr = ctx->traceroute_queue;
    TracerouteResponse *rptr = ctx->traceroute_responses, *rnext = NULL;
    struct icmphdr icmp;
    PacketBuildInstructions *iptr = NULL;
    AttackOutgoingQueue *optr = NULL;
    int i = 0;
    TraceroutePacketData *pdata = NULL;
    TracerouteSpider *sptr = NULL;
    int tcount  = 0;
    int ret = 0;
    // timestamp required for various states of traceroute functionality
    int ts = time(0);


    // if the list is empty.. then we are done here
    if (tptr == NULL) goto end;

    // zero icmp header since its in the stack
    memset(&icmp, 0, sizeof(struct icmphdr));


    printf("Traceroute_Perform: Queue %d [completed %d]\n", L_count((LINK *)tptr), Traceroute_Count(ctx, 1));

    // loop until we run out of elements
    while (tptr != NULL) {        
        // if we have reached max ttl then mark this as completed.. otherwise it could be marked completed if we saw a hop which equals the target
        if (tptr->current_ttl >= MAX_TTL) {
            tptr->completed = 1;
        }

        if (!tptr->completed && tptr->enabled) {
            // lets increase the TTL by this number (every 1 second right now)
            if ((ts - tptr->ts_activity) > 1) {
                tptr->ts_activity = time(0);

                // increase TTL in case this one is rate limiting ICMP, firewalled, or whatever.. move to the next
                tptr->current_ttl++;

                // in case we have more in a row for this queue that are 0 (because it responded fromm a higher ttl already)
                // and we just need its lower hops...
                // this is mainly when we are randomizing the TTL so our closer routes arent getting all 50 at once..                
                while ((tptr->current_ttl < MAX_TTL) && tptr->ttl_list[tptr->current_ttl] == 0)
                    tptr->current_ttl++;

                // if the current TTL isnt disqualified already
                if (tptr->ttl_list[tptr->current_ttl] != 0) {
                    // prepare the ICMP header for the traceroute
                    icmp.type = ICMP_ECHO;
                    icmp.code = 0;
                    icmp.un.echo.sequence = tptr->identifier;
                    icmp.un.echo.id = tptr->identifier + tptr->ttl_list[tptr->current_ttl];

                    // create instruction packet for the ICMP(4/6) packet building functions
                    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {

                        // this is the current TTL for this target
                        iptr->ttl = tptr->ttl_list[tptr->current_ttl];
                        
                        // determine if this is an IPv4/6 so it uses the correct packet building function
                        if (tptr->target_ip != 0) {
                            iptr->type = PACKET_TYPE_ICMP_4;
                            iptr->destination_ip = tptr->target_ip;
                            iptr->source_ip = ctx->my_addr_ipv4;
                        } else {
                            iptr->type = PACKET_TYPE_ICMP_6;
                            // destination is the target
                            CopyIPv6Address(&iptr->destination_ipv6, &tptr->target_ipv6);
                            // source is our ip address
                            CopyIPv6Address(&iptr->source_ipv6, &ctx->my_addr_ipv6);
                        }

                        // copy ICMP parameters into this instruction packet as a complete structure
                        memcpy(&iptr->icmp, &icmp, sizeof(struct icmphdr));

                        // set size to the traceroute packet data structure's size...
                        iptr->data_size = sizeof(TraceroutePacketData);

                        if ((iptr->data = (char *)calloc(1, iptr->data_size)) != NULL) {
                            pdata = (TraceroutePacketData *)iptr->data;

                            // lets include a little message since we are performing a lot..
                            // if ever on a botnet, or worm.. disable this obviously
                            strcpy(&pdata->msg, "performing traceroute research");
                            
                            // set the identifiers so we know which traceroute queue the responses relates to
                            pdata->identifier = tptr->identifier;
                            pdata->ttl = iptr->ttl;
                        }

                        // lets build a packet from the instructions we just designed for either ipv4, or ipv6
                        // for either ipv4, or ipv6
                        if (iptr->type & PACKET_TYPE_ICMP_6)
                            i = BuildSingleICMP6Packet(iptr);
                        else if (iptr->type & PACKET_TYPE_ICMP_4)
                            i = BuildSingleICMP4Packet(iptr);

                        // if the packet building was successful
                        if (i == 1) {
                            // allocate a structure for the outgoing packet to get wrote to the network interface
                            if ((optr = (AttackOutgoingQueue *)calloc(1, sizeof(AttackOutgoingQueue))) != NULL) {
                                // we need to pass it the final packet which was built for the wire
                                optr->buf = iptr->packet;
                                optr->type = iptr->type;
                                optr->size = iptr->packet_size;

                                // remove the pointer from the instruction structure so it doesnt get freed in this function
                                iptr->packet = NULL;
                                iptr->packet_size = 0;

                                // the outgoing structure needs some other information
                                optr->dest_ip = iptr->destination_ip;
                                optr->ctx = ctx;

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
                        // dont need this anymore.. (we removed the data pointer from it so lets just clear everyting else)
                        PacketBuildInstructionsFree(&iptr);
                    }
                }
            }
        }

        tptr = tptr->next;
    }

    // now process all queued responses we have from incoming network traffic.. it was captured on a thread specifically for reading packets
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

    // we cleared the list so ensure the context is updated
    ctx->traceroute_responses = NULL;

    // *** we will log to the disk every 20 calls (for dev/debugging)
    if ((ccount % 20)==0)
        Spider_Print(ctx);

    // count how many traceroutes are in queue and active
    tcount = Traceroute_Count(ctx, 0);

    // if the amount of active is lower than our max, then we will activate some other ones
    if (tcount < MAX_ACTIVE_TRACEROUTES) {
        
        // how many to ativate?
        tcount = MAX_ACTIVE_TRACEROUTES - tcount;
    
        // start on the  linked list...enumerating each
        tptr = ctx->traceroute_queue;
        while (tptr != NULL) {
            // ensure this one isnt completed, and isnt already enabled..
            if (!tptr->completed && !tptr->enabled) {
                // if we already activated enough then we are done
                if (!tcount) break;

                // activate this particular traceroute target
                tptr->enabled = 1;

                // decrease the coutner
                tcount--;
            }

            // move to the next target
            tptr = tptr->next;
        }
    }

    end:;

    return ret;
}



// dump traceroute data to disk.. printing a little information..
// just here temporarily.. 
int Spider_Print(AS_context *ctx) {
    TracerouteSpider *sptr = NULL;
    int count = 0;
    FILE *fd2 = NULL;
    char fname[32];
    TracerouteSpider *bptr = NULL;
    char Ahop[16], Atarget[16];
    struct in_addr conv;

    // filename for debug data
    sprintf(fname, "traceroute.txt", "w");
    //fd2 = fopen(fname, "w");
    fd2 = NULL; // disabling it by settinng to NULL

    // enumerate spider and list information
    sptr = ctx->traceroute_spider_hops;
    while (sptr != NULL) {
        // if the output file is open then lets write some data
        if (fd2) {
            // we wanna turn the target, and hop IP from long to ascii
            conv.s_addr = sptr->hop_ip;
            strcpy((char *)&Ahop, inet_ntoa(conv));
            conv.s_addr = sptr->target_ip;
            strcpy((char *)&Atarget, inet_ntoa(conv));
            // and finally format & write it to the output file
            fprintf(fd2, "HOP,%s,%s,%u,%d\n", Ahop, Atarget, sptr->identifier_id, sptr->ttl);
        }

        // this message is for debugging/development.. how many branches are in this hop (similar)
        count = L_count_offset((LINK *)sptr->branches, offsetof(TracerouteSpider, branches));
        //count = branch_count(sptr->branches);
        // we want only if its more than 10 to show to the sccreen because a lot are small numbers (1-10)
        if (count > 10) {
            printf("spider hop %u branches %p [count %d] next %p\n", sptr->hop_ip, sptr->branches, count, sptr->hops_list);
        }

        // if this particular hop has other branches (relations to other traceroute queries/targets)
        // then we wanna log those to the file as well
        bptr = sptr->branches;

        // loop for each branch
        while (bptr != NULL) {
            // if the file is open
            if (fd2) {
                // convert long ips to ascii
                conv.s_addr = bptr->hop_ip;
                strcpy((char *)&Ahop, inet_ntoa(conv));
                conv.s_addr = bptr->target_ip;
                strcpy((char *)&Atarget, inet_ntoa(conv));
                // and format & write the data to the file
                fprintf(fd2, "BRANCH,%s,%s,%u,%d\n", Ahop, Atarget, sptr->identifier_id, sptr->ttl);
            }

            // move to next in branch list
            bptr = bptr->branches;
        }

        // move to next in hop list (routers which have resppoonded to traceroute queries)
        sptr = sptr->hops_list;
    }

    // how many traceroute hops do we have? (unique.. dont count branches)
    // *** fix this.. we neeed an L_count() for _offset() because this will count the total fromm the first element
    printf("Traceroute Spider count: %d\n", L_count((LINK *)ctx->traceroute_spider_hops));

    // close file if it was open
    if (fd2) fclose(fd2);

    return 0;
}



// load data from a file.. this is for development.. so I can use the python interactive debugger, and write various C code
// for the algorithms required to determine the best IP addresses for manipulation of the mass surveillance networks
int Spider_Load(AS_context *ctx, char *filename) {
    FILE *fd = NULL;
    char buf[1024];
    char *sptr = NULL;
    char type[16], hop[16],target[16];
    int ttl = 0;
    uint32_t identifier = 0;
    int i = 0;
    int n = 0;
    TracerouteSpider *Sptr = NULL;
    TracerouteSpider *snew = NULL;
    TracerouteSpider *slast = NULL, *Blast = NULL;

    // open ascii format file
    if ((fd = fopen(filename, "r")) == NULL) return -1;
        
    // read all lines
    while (fgets(buf,1024,fd)) {
        i = 0;
        // if we have \r or \n in the buffer (line) we just read then lets set it to NULL
        if ((sptr = strchr(buf, '\r')) != NULL) *sptr = 0;
        if ((sptr = strchr(buf, '\n')) != NULL) *sptr = 0;

        // change all , (like csv) to " " spaces for sscanf()
        n = strlen(buf);
        while (i < n) {
            if (buf[i] == ',') buf[i] = ' ';
            i++;
        }

        // grab entries
        sscanf(buf, "%s %s %s %u %d", &type, &hop, &target, &ttl, &identifier);

        //printf("type: %s\nhop %s\ntarget %s\nident %u\nttl %d\n", type, hop,target, ttl , identifier);

        // allocate structure for storing this entry into the traceroute spider
        if ((snew = (TracerouteSpider *)calloc(1, sizeof(TracerouteSpider))) == NULL) break;

        // set various information we have read fromm the file into the new structure
        snew->hop_ip = inet_addr(hop);
        snew->target_ip = inet_addr(target);
        snew->ttl = ttl;
        snew->identifier_id = identifier;

        // add to main linked list.. (where every entry goes)
        // use last so its faster..
        if (slast == NULL) {
            L_link_ordered_offset((LINK **)&ctx->traceroute_spider, (LINK *)snew, offsetof(TracerouteSpider, next));
            slast = snew;
        } else {
            slast->next = snew;
            slast = snew;
        }

        if ((Sptr = Spider_Find(ctx, snew->hop_ip, NULL)) != NULL) {
            //printf("ADDED as branch! %s %u %u\n", hop, snew->hop, Sptr->hop);
            L_link_ordered_offset((LINK **)&Sptr->branches, (LINK *)snew, offsetof(TracerouteSpider, branches));
        } else {
            // add to waiting hops
            L_link_ordered_offset((LINK **)&ctx->traceroute_spider_hops, (LINK *)snew, offsetof(TracerouteSpider, hops_list));
        }

        // before we fgets() again lets clear the buffer
        memset(buf,0,1024);
    }

    fclose(fd);

    return 1;
}


//http://www.binarytides.com/get-local-ip-c-linux/
uint32_t get_local_ipv4() {
    const char* google_dns_server = "8.8.8.8";
    int dns_port = 53;
    uint32_t ret = 0;
    struct sockaddr_in serv;     
    int sock = 0;
    
    //return inet_addr("192.168.0.100");
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return 0;
     
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
    
    // get our own ip addresses for packet building
    ctx->my_addr_ipv4 = get_local_ipv4();
    get_local_ipv6(&ctx->my_addr_ipv6);

    ret = 1;

    end:;

    // free structures if they were not used for whatever reasons
    if (ret != 1) {
        PtrFree(&flt);
        PtrFree(&nptr);
    }

    return ret;
}



// count the amount of non completed (active) traceroutes in queue
int Traceroute_Count(AS_context *ctx, int return_completed) {
    TracerouteQueue *qptr = ctx->traceroute_queue;
    int ret = 0;

    // loop until we enuerate the entire list of queued traceroute activities
    while (qptr != NULL) {
        // check if they are completed.. if not we increase the counter
        if (!return_completed && !qptr->completed && qptr->enabled)
            ret++;

        if (return_completed && qptr->completed)
            ret++;

        qptr = qptr->next;
    }

    return ret;
}


// find a traceroute structure by address.. and maybe check ->target as well (traceroute queue IP as well as hops)

TracerouteSpider *Traceroute_Find(AS_context *ctx, uint32_t address, struct  in6_addr *addressv6, int check_targets) {
    TracerouteSpider *ret = NULL;
    TracerouteSpider *sptr = ctx->traceroute_spider;
    struct in_addr src;

    while (sptr != NULL) {

        // for turning long IP to ascii for dbg msg
        //src.s_addr = sptr->hop_ip;
        //printf("FIND checking against IP: %s\n", inet_ntoa(src));

        // ***maybe create an address structuure which can hold IPv4, and 6 and uses an integer so we dont just check if ipv4 doesnt exist..
        if (address && sptr->hop_ip == address) {
            //printf("Checking %u against %u", address, sptr->hop);
            break;
        }
        if (!address && CompareIPv6Addresses(addressv6, &sptr->hop_ipv6)) {
            break;
        }

        // if it passed a flag to check targets.. then we arent only checking routers (hops)
        // we will match with anything relating to that target
        if (check_targets && address && sptr->target_ip == address)
            break;

        if (check_targets && !address && CompareIPv6Addresses(addressv6, &sptr->target_ipv6))
            break;

        // move to the next in the list to check for the address
        sptr = sptr->next;
    }

    return sptr;

}