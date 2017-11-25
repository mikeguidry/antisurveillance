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
#include "utils.h"

/*

Research is everything related to strategy choices.  For example, which sites do we wish to spend the majority
of our bandwidth falsifying connections towards?  It will perform DNS lookups, traceroutes, and BGP analysis to
determine the best IP 4/6 addresses to use for attacks.

For local attacks: NIDs, etc.. It will take the local IP addresses, and find the best ways of attacking
the platform to either hide in other packets, or attempt to force other issues such as Admin believing hacks
are taking place elsewhere.. etc

I'll try to require as little hard coded information as possible.  I'd like everything to work without requiring any updates -- ever.
*/


// this can be handeled recursively because we have max TTL of 30.. its not so bad
int Traceroute_Search(TracerouteSpider *start, TracerouteSpider *looking_for, int distance) {
    TracerouteSpider *search = NULL;
    TracerouteSpider *search_branch = NULL;
    int cur_distance = distance;
    int ret = 0;
    int ttl_diff = 0;

    if (distance > MAX_TTL) return 0;

    if (!start || !looking_for) return 0;

    printf("Traceroute_Search: start %p [%u] looking for %p [%u] distnace: %d\n", 
    start, start->hop, looking_for, looking_for->hop, distance);
    
    // use context here and use the next list..
    search = start;
    
    // first we search all branches, and perform it recursively as well...
    while (search != NULL) {

        if (search->branches) {
            cur_distance++;
            
            search_branch = search->branches;

            while (search_branch != NULL) {

                if (search_branch->hop == looking_for->hop) return cur_distance;

                ret = Traceroute_Search(search_branch, looking_for, cur_distance+1);

                // if it was found..
                if (ret) return ret;

                search_branch = search_branch->branches;
            }

            cur_distance--;
        }

        search = search->next;
    }

    // next we wanna search fromm the  identifiers list (it could be 2 routers away) so distance of 2..
    search = start->identifiers;

    cur_distance++;
    while (search != NULL) {

        if (start->hop == looking_for->hop) {
            ttl_diff = start->ttl - looking_for->ttl;

            if (ttl_diff < 0) ttl_diff = abs(ttl_diff);

            if (ttl_diff) {
                ret = ttl_diff + cur_distance;
                break;
            }

            search_branch = search->branches;

            while (search_branch != NULL) {
                // we wanna check branches of that traceroute (identifier) we are checking    

                ret = Traceroute_Search(search_branch, looking_for, cur_distance+1);

                    // if it was found..
                if (ret) return ret;

                search_branch = search_branch->branches;
            }
        }

        search = search->identifiers;
    }

    cur_distance--;

    return ret;
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
    if (first->hop == second->hop) return 1;

    distance = Traceroute_Search(first, second, 0);

    printf("distance: %d\n", distance);

    ret = distance;



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
TracerouteSpider *Spider_Find(AS_context *ctx, uint32_t hop, struct in6_addr *hopv6) {
    TracerouteSpider *sptr = ctx->traceroute_spider_hops;

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

        sptr = sptr->hops_list;
    }

    return sptr;
}

int branch_count(TracerouteSpider *sptr) {
    int ret = 0;
    while (sptr != NULL) {
        ret++;
        sptr = sptr->branches;
    }
    return ret;
}

int Spider_IdentifyTogether(AS_context *ctx, TracerouteSpider *sptr) {
    TracerouteSpider *srch = ctx->traceroute_spider;
    int ret = 0;

    while (srch != NULL) {

        if (srch->identifier_id == sptr->identifier_id) {
            // link it to the identifiers list..
            sptr->identifiers = srch;
            srch->identifiers = sptr;
            ret = 1;
            break;
        }

        srch = srch->next;
    }

    return ret;
}

// Analyze a traceroute response against the current queue and build the spider web of traceroutes
// for further strategies
int TracerouteAnalyzeSingleResponse(AS_context *ctx, TracerouteResponse *rptr) {
    int ret = 0;
    TracerouteQueue *qptr = ctx->traceroute_queue;
    TracerouteSpider *sptr = NULL, *snew = NULL;
    struct in_addr src;
    int i = 0;
    int left = 0;

    //printf("Traceroute Analyze Single responsse %p\n", rptr);

    // if the pointer was NULL.. lets just return with 0 (no error...)
    if (rptr == NULL) return ret;

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

    src.s_addr = rptr->hop;
    //printf("Response IP: %s\n", inet_ntoa(src));
    
    // we had a match.. lets link it in the spider web
    if (qptr != NULL) {

        // if this hop responding matches an actual target in the queue... then that traceroute is completed
        
        if ((rptr->hop && rptr->hop == qptr->target) ||
            (!rptr->hop && !qptr->target && CompareIPv6Addresses(&rptr->hopv6, &qptr->targetv6))) {

                // this used to mean its completed when TTL was done in order... now that we are randomizing.. it just means
                // anything ABOVE the ttl that responded is useless... and we only complete when all are done...
                //printf("------------------\nTraceroute completed %p [%u %u]\n-------------------\n", qptr, rptr->hop, qptr->target);
                //qptr->completed = 1;
                
                //for when randomization of ttl is done
                            for (i = 0; i < MAX_TTL; i++) {
                                if (qptr->ttl_list[i] >= rptr->ttl) qptr->ttl_list[i] = 0;
                                if (qptr->ttl_list[i] != 0) left++;
                            }

                            if (!left) qptr->completed = 1;
                

        }


        // allocate space for us to append this response to our interal spider web for analysis
        if ((snew = (TracerouteSpider *)calloc(1, sizeof(TracerouteSpider))) != NULL) {
            // we need to know which TTL later (for spider web analysis)
            snew->ttl = rptr->ttl;

            // ensure we log identifier so we can connect all for target easily
            snew->identifier_id = qptr->identifier;
            // take note of the hops address (whether its ipv4, or 6)
            snew->hop = rptr->hop;
            CopyIPv6Address(&snew->hopv6, &rptr->hopv6);

            // take noote of the target ip address
            snew->target_ip = qptr->target;
            CopyIPv6Address(&qptr->targetv6, &rptr->targetv6);

            // in case later we wanna access the original queue which created the entry
            snew->queue = qptr;

            // link into list containing all..
            snew->next = ctx->traceroute_spider;
            ctx->traceroute_spider = snew;


            // now lets link into 'hops' list.. all these variations are required for final strategy
            if ((sptr = Spider_Find(ctx, rptr->hop, &rptr->hopv6)) != NULL) {
                //printf("--------------\nFound Spider %p [%u] branches %d\n", sptr, rptr->hop, branch_count(sptr->branches));
                // we found it as a spider.. so we can add it to a branch

                snew->branches = sptr->branches;
                
                sptr->branches = snew;
            } else {

                snew->hops_list = ctx->traceroute_spider_hops;
                ctx->traceroute_spider_hops = snew;

            }
            //else {
                //printf("---------------\nCouldnt find spider... added new %u\n", rptr->hop);
                // lets link directly to main list .. first time seeing this hop

            // lets link them all directly into the regular list
            // this is so the spider_find will always find the first one....
            // i'll have to either separate the full linked list fromm spider_find() or do somemthing else... in progress
            //L_link_ordered((LINK **)&ctx->traceroute_spider, (LINK *)snew);

              
            //}

            // link with other from same identifier...
            // this is another dimension of the strategy.. required .. branches of a single hop wasnt enough
            Spider_IdentifyTogether(ctx, snew);

            ret = 1;
        }
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
    int i = 0;
    int n = 0;
    int ttl = 0;

    //printf("\nTraceroute Queue %u\n", target);

    // allocate memory for this new traceroute target we wish to add into the system
    if ((tptr = (TracerouteQueue *)calloc(1, sizeof(TracerouteQueue))) == NULL) goto end;

    // which IP are we performing traceroutes on
    tptr->target = target;
    //printf("Queuing target: %u\n", target);
    // if its an ipv6 addres pasased.. lets copy it (this function will verify its not NULL)
    CopyIPv6Address(&tptr->targetv6, targetv6);

    // we start at ttl 1.. itll inncrement to that when processing
    tptr->current_ttl = 0;

    // create a random identifier to find this packet when it comes from many hops
    tptr->identifier = rand()%0xFFFFFFFF;

    //printf("queued: %X\n", tptr->identifier);

    // later we wish to allow this to be set by scripting, or this function
    // for example: if we wish to find close routes later to share... we can set to max = 5-6
    // and share with p2p nodes when mixing/matching sides of the taps (when they decide to secure them more)
    tptr->max_ttl = MAX_TTL;

    // current timestamp stating it was added at this time
    tptr->ts = time(0);

    // add to traceroute queue...
    tptr->next = ctx->traceroute_queue;
    ctx->traceroute_queue = tptr;

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

    
    while (i < 15) {
        n = rand()%15;
        ttl = tptr->ttl_list[n];

        tptr->ttl_list[n] = tptr->ttl_list[i];

        tptr->ttl_list[i] = ttl;

        i++;
    }

    i = 20;
    // lets randomize the last third...
    while (i < MAX_TTL) {
        n = i + (rand()%(MAX_TTL - i));
        ttl = tptr->ttl_list[n];

        tptr->ttl_list[n] = tptr->ttl_list[i];

        tptr->ttl_list[i] = ttl;

        i++;
    }

    end:;
    return ret;
}


// if we have active traceroutes, then this function should take the incoming packet
// analyze it,  and determine if it relates to any active traceroute missions
// It should handle all types of packets... id say UDP/ICMP... 
// its a good thing since it wont have to analyze ALL tcp connections ;)
int Traceroute_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = -1;
    struct in_addr cnv;
    //PacketBuildInstructions *iptr = NULL;
    //PacketInfo *pnext = NULL;
    TracerouteResponse *rptr = NULL;
    TraceroutePacketData *pdata = NULL;
    FILE *fd=NULL;
    char fname[32];

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

    sprintf(fname, "packets/incoming_%d_%d.bin", getpid(), rand()%0xFFFFFFFF);
    if (1==2 && (fd = fopen(fname, "wb")) != NULL) {
        fwrite(iptr->data, 1, iptr->data_size, fd);
        fclose(fd);
    }
        

    // data isnt big enough to contain the identifier
    if (iptr->data_size < sizeof(TraceroutePacketData)) {
        goto end;
    }

    if (iptr->data_size > sizeof(TraceroutePacketData) && ((iptr->data_size >= sizeof(TraceroutePacketData) + 28))) {
    // (sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(TraceroutePacketData))) {
        pdata = (TraceroutePacketData *)(iptr->data + 28);//(sizeof(struct iphdr) + sizeof(struct icmphdr)));

    } else {
        pdata = (TraceroutePacketData *)iptr->data;
    }/*

    //printf("Got packet from network! data size %d\n", iptr->data_size);
    printf("\n\n---------------------------\nTraceroute Incoming\n");

    cnv.s_addr = iptr->source_ip;
    printf("SRC: %s\n", inet_ntoa(cnv));

    cnv.s_addr = iptr->destination_ip;
    printf("DST: %s\n", inet_ntoa(cnv));
    */


    
    // extract identifier+ttl here fromm the packet characteristics, or its data.. if its not a traceroute, just goto end
    //identifier = *(uint32_t *)(iptr->data);

    // ttl = right 16 bits
    //ttl = (identifier & 0x0000FFFF);

    // identifier = left 16 bits
    //identifier = (identifier & 0xFFFF0000) >> 16;
    ttl = pdata->ttl;
    identifier = pdata->identifier;
    //printf("pdata msg: %s\n", pdata->msg);

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
    TracerouteSpider *sptr = NULL;
    int tcount  = 0;

    memset(&icmp, 0, sizeof(struct icmphdr));

    int ret = 0;
    // timestamp required for various states of traceroute functionality
    int ts = time(0);

    // if the list is empty.. then we are done here
    if (tptr == NULL) goto end;

    printf("Traceroute_Perform: Queue %d [completed %d]\n", L_count((LINK *)tptr), Traceroute_Count(ctx, 1));
    // loop until we run out of elements
    while (tptr != NULL) {

        
        // if we have reached max ttl then mark this as completed.. otherwise it could be marked completed if we saw a hop which equals the target
        if (tptr->current_ttl >= MAX_TTL) {
            //printf("traceroute completed\n");
            tptr->completed = 1;
        }

        if (!tptr->completed && tptr->enabled) {
            // lets increase TTL every 10 seconds.. id like to perform thousands of these at all times.. so 10 seconds isnt a big deal...
            // thats 5 minutes till MAX ttl (30)
            if ((ts - tptr->ts_activity) > 1) {

                //tptr->ts_activity = time(0);

                //printf("traceroute activity timer.. increasing ttl %d\n", tptr->current_ttl);
                tptr->current_ttl++;

                // in case we have more in a row for this queue that are 0 (because it responded fromm a higher ttl already)
                // and we just need its lower hops...
                while ((tptr->current_ttl < MAX_TTL) && tptr->ttl_list[tptr->current_ttl] == 0) {
                    tptr->current_ttl++;
                }

                if (tptr->ttl_list[tptr->current_ttl] != 0) {

                    // lets merge these two variables nicely into a 32bit variable for the ICMP packet  (to know which request when it comes back)
                    // using it like this allows us to perform mass scans using a small amount of space
                    // it ensures we can keep a consistent queue of active traceroutes
                    packet_data = (((tptr->identifier << 16) & 0xFFFF0000) | (tptr->current_ttl & 0x0000FFFF));

                    icmp.type = ICMP_ECHO;
                    icmp.code = 0;
                    // i forgot about these.. might be able to use them as identifer/ttl
                    icmp.un.echo.sequence = tptr->identifier;

                    // lets use the TTL list entry.. its randomized..
                    icmp.un.echo.id = tptr->ttl_list[tptr->current_ttl];

                    // make packet, or call funnction to handle that..
                    // mark some identifier in tptr for Traceroute_Incoming()

                    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {

                        iptr->ttl = tptr->ttl_list[tptr->current_ttl];
                        
                        if (tptr->target != 0) {
                            iptr->type = PACKET_TYPE_ICMP_4;
                            iptr->destination_ip = tptr->target;
                            iptr->source_ip = ctx->my_addr_ipv4;
                        } else {
                            iptr->type = PACKET_TYPE_ICMP_6;
                            // destination is the target
                            CopyIPv6Address(&iptr->destination_ipv6, &tptr->targetv6);
                            // source is our ip address
                            CopyIPv6Address(&iptr->source_ipv6, &ctx->my_addr_ipv6);
                        }

                        // copy ICMP parameters into this instruction packet
                        memcpy(&iptr->icmp, &icmp, sizeof(struct icmphdr));

                        

                        iptr->data_size = sizeof(TraceroutePacketData);
                        iptr->data = (char *)calloc(1, iptr->data_size);
                        if (iptr->data != NULL) {
                            
                            pdata = (TraceroutePacketData *)iptr->data;
                            strcpy(&pdata->msg, "performing traceroute research");
                            //memcpy(&pdata->msg, "hello", 5);
                            pdata->identifier = tptr->identifier;
                            pdata->ttl = iptr->ttl;
                        }

                        

                        // ok so we need a way to queue an outgoing instruction without an attack structure....
                        // lets build a packet from the instructions we just designed
                        // lets build whichever type this is by calling the function directly from packetbuilding.c
                        // for either ipv4, or ipv6
                        if (iptr->type & PACKET_TYPE_ICMP_6) {
                            //printf("building icmp6\n");
                            i = BuildSingleICMP6Packet(iptr);
                        } else if (iptr->type & PACKET_TYPE_ICMP_4) {
                            i = BuildSingleICMP4Packet(iptr);
                        }

                        if (i == 1) {
                            if ((optr = (AttackOutgoingQueue *)calloc(1, sizeof(AttackOutgoingQueue))) != NULL) {
                                optr->buf = iptr->packet;
                                optr->type = iptr->type;
                                optr->size = iptr->packet_size;

                                iptr->packet = NULL;
                                iptr->packet_size = 0;

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

                        // dont need this anymore..
                        PacketBuildInstructionsFree(&iptr);
                    }


                    } else {
                        // maybe issue w memory? lets roll back and let the next round try
                        tptr->current_ttl--;
                        break;
                    }
            }
        }

        tptr = tptr->next;
    }


    // now process all queued responses we have from incoming network traffic on a different thread
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

    Spider_Print(ctx);

    tcount = Traceroute_Count(ctx, 0);

    // if we are below our max active.. lets try to activate some more
    if (tcount < MAX_ACTIVE_TRACEROUTES) {
        
        // how many to ativate?
        tcount = MAX_ACTIVE_TRACEROUTES - tcount;

    
        tptr = ctx->traceroute_queue;
        while (tptr != NULL) {
            if (!tptr->completed && !tptr->enabled) {
                if (!tcount) break;

                tptr->enabled = 1;

                tcount--;
            }

            tptr = tptr->next;
        }
    }

    end:;
    return ret;
}

int Spider_Print(AS_context *ctx) {
    TracerouteSpider *sptr = NULL;
    int count = 0;
    FILE *fd = NULL, *fd2 = NULL;
    char fname[32];
    TracerouteSpider *bptr = NULL;
    char Ahop[16], Atarget[16];
    struct in_addr conv;

    sprintf(fname, "traceroute.bin", "wb");
    fd = fopen(fname, "wb");
    sprintf(fname, "traceroute.txt", "w");
    fd2 = fopen(fname, "w");



    // enumerate spider and list information
    sptr = ctx->traceroute_spider_hops;
    while (sptr != NULL) {
        if (fd) {
            
            fwrite(&sptr->hop, sizeof(uint32_t), 1, fd);
            fwrite(&sptr->target_ip, sizeof(uint32_t), 1, fd);
            fwrite(&sptr->ttl, sizeof(int), 1, fd);
        }
        if (fd2) {
            conv.s_addr = sptr->hop;
            strcpy((char *)&Ahop, inet_ntoa(conv));
            conv.s_addr = sptr->target_ip;
            strcpy((char *)&Atarget, inet_ntoa(conv));
            fprintf(fd2, "HOP,%s,%s,%u,%d\n", Ahop, Atarget, sptr->identifier_id, sptr->ttl);
        }

        count = branch_count(sptr->branches);
        if (count > 10) {
            printf("spider hop %u branches %p [count %d] next %p\n", sptr->hop, sptr->branches, count, sptr->hops_list);
        }

        bptr = sptr->branches;
        if (fd)
            fwrite(&count, sizeof(int), 1, fd);

        while (bptr != NULL) {
            if (fd) {
                fwrite(&sptr->hop, sizeof(uint32_t), 1, fd);
                fwrite(&sptr->target_ip, sizeof(uint32_t), 1, fd);
                fwrite(&sptr->identifier_id, sizeof(uint32_t), 1, fd);
                fwrite(&sptr->ttl, sizeof(int), 1, fd);
            }
            if (fd2) {
                conv.s_addr = bptr->hop;
                strcpy((char *)&Ahop, inet_ntoa(conv));
                conv.s_addr = bptr->target_ip;
                strcpy((char *)&Atarget, inet_ntoa(conv));
                fprintf(fd2, "BRANCH,%s,%s,%u,%d\n", Ahop, Atarget, sptr->identifier_id, sptr->ttl);
            }

            bptr = bptr->branches;
        }

        sptr = sptr->hops_list;
    }

    printf("Traceroute Spider count: %d\n", L_count((LINK *)ctx->traceroute_spider_hops));

    if (fd) fclose(fd);
    if (fd2) fclose(fd2);

    return 0;
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
        if (!return_completed && !qptr->completed && qptr->enabled) {
            ret++;
        } 

        if (return_completed && qptr->completed)
            ret++;

        qptr = qptr->next;
    }    
    // return count
    return ret;
}


// find a traceroute structure by address.. and maybe check ->target as well (traceroute queue IP as well as hops)
TracerouteSpider *Traceroute_Find(AS_context *ctx, uint32_t address, struct  in6_addr *addressv6, int check_targets) {
    TracerouteSpider *ret = NULL;
    TracerouteSpider *sptr = ctx->traceroute_spider;

    while (sptr != NULL) {


        if (address && sptr->hop == address) {
            //printf("Checking %u against %u", address, sptr->hop);
            break;
        }
        if (!address && CompareIPv6Addresses(addressv6, &sptr->hopv6)) {
            break;
        }

        if (check_targets && address && sptr->target_ip == address) {
            printf("Checking targets %u against %u", address, sptr->target_ip);
            break;
        }
        if (check_targets && !address && CompareIPv6Addresses(addressv6, &sptr->target_ipv6)) break;

        sptr = sptr->next;
    }

    if (sptr == NULL) {
        printf("couldnt find %u\n", address);
    }


    return sptr;

}