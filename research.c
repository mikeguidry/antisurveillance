

/*

Research is everything related to strategy choices.  For example, which sites do we wish to spend the majority
of our bandwidth falsifying connections towards?  It will perform DNS lookups, traceroutes, and BGP analysis to
determine the best IP 4/6 addresses to use for attacks.

For local attacks: NIDs, etc.. It will take the local IP addresses, and find the best ways of attacking
the platform to either hide in other packets, or attempt to force other issues such as Admin believing hacks
are taking place elsewhere.. etc

I'll try to require as little hard coded information as possible.  I'd like everything to work without requiring any updates -- ever.



It took 15 hours at 50 active traceroute queue to complete 53,000 traceroutes (DNS results from top 1mil sites using massdns)
Obviously 53,000 isnt all of them.. ill have to add more timeout interval later...

The data seemed incomplete so I think I finalized the save, and load mechanism.  It can also attempt to retry any missing TTL
entries for targets whenever the queue reaches zero.  It will also randomly disable/enable different queues.  I need to perfect
the system.  I figured sending out more than 50 (maybe 1000) packets a second should mean 1000 responses..

Fact is.. the hops/routers seem to rate limit ICMP, and supposed to block something like 66% in general.  I know
sending more packets per second to close routes (0-3 hops) means they get every single traceroute lookup.

I'll finish and make the RandomizeTTLs first try 8-15 on large amounts of active queue.  I'm pretty sure the targets, and distant
routers/hops will respond therefore if you are sending to a high amount of these then the amount of active traceroutes SHOULD
in fact be increased....

I might just revamp the entire 'queue' system and move it from an active count based to attempting high ttl amounts more, and
going for the LOW ttl amounts later.  It could allow normal until it finds all hosts which are probably the local ISP..
for instance.. trace routing 3000 hosts, and 1000-1500 hit this particular hop then its more than likely going to be uused for most..
the 1500 (near 50%) was what i was seeing for hops 0-3.. so obviously there was some that were ignored by the routes and should be retried
therefore this 1500(or 50%) should be dynamically calculated between the first 3 hops and the initial few thousand lookups
then it can reuse that number to determine which hops are probably the closest to prioritize as last..

so it should get handled after the higher TTL.. so it can set a 'minimum' TTL until the majority of the queue is completed..

it also means that we can auto 'invisibly' add these hops until we get the actual data.. which means we can do more with less...

I hoped to finish today but I should by tommorrow...

btw 15 hours at 3-4kb/sec isnt that serious.. LOL its not as bad as it sounds.. packets are small

for strategies using research:
we wanna construct a context of the strategy we are trying to build
if we cannot find all traceroute, or other information we can then retry, or queue and allow a callback to continue
the strategies whenever the information is complete...

this is also necessary for one of the upcomming attacks

if a single hop is missing, or two.. we can use other results and just fill in the gaps if they share simmilar/near nodes/hops/routers

traceroute_max_active shouild count incoming packets/successful lookups and autoatically adjust itself to get the most packets



The data and information from the automated traceroute can get reused in several different ways.  Reverse DDoS (to detect hacking
even through tor, etc) can use information/routes from this to pick, and calculate the attacks to perform to automate
finding the target


we shouild dns lookup traceroutees to get more IPs (Reverse, and regular..) we can also look for dns responses with multiple ips
need to scan for open dns servers (to get geoip dns automatically)



*/


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

// for geoip
#include "GeoIP.h"
#include "GeoIPCity.h"



#ifndef offsetof
#define offsetof(type, member) ( (int) & ((type*)0) -> member )
#endif

// geoip countries for turning geoip ASCII to simple identifier (1-255)
// i found this list in the PHP version, and just reformatted it to C
const char *geoip_countries[] = {"00","AP","EU","AD","AE","AF","AG",
        "AI","AL","AM","CW","AO","AQ","AR","AS","AT","AU","AW","AZ",
        "BA","BB","BD","BE","BF","BG","BH","BI","BJ","BM","BN","BO",
        "BR","BS","BT","BV","BW","BY","BZ","CA","CC","CD","CF","CG",
        "CH","CI","CK","CL","CM","CN","CO","CR","CU","CV","CX","CY",
        "CZ","DE","DJ","DK","DM","DO","DZ","EC","EE","EG","EH","ER",
        "ES","ET","FI","FJ","FK","FM","FO","FR","SX","GA","GB","GD",
        "GE","GF","GH","GI","GL","GM","GN","GP","GQ","GR","GS","GT",
        "GU","GW","GY","HK","HM","HN","HR","HT","HU","ID","IE","IL",
        "IN","IO","IQ","IR","IS","IT","JM","JO","JP","KE","KG","KH",
        "KI","KM","KN","KP","KR","KW","KY","KZ","LA","LB","LC","LI",
        "LK","LR","LS","LT","LU","LV","LY","MA","MC","MD","MG","MH",
        "MK","ML","MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV",
        "MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI","NL","NO",
        "NP","NR","NU","NZ","OM","PA","PE","PF","PG","PH","PK","PL",
        "PM","PN","PR","PS","PT","PW","PY","QA","RE","RO","RU","RW",
        "SA","SB","SC","SD","SE","SG","SH","SI","SJ","SK","SL","SM",
        "SN","SO","SR","ST","SV","SY","SZ","TC","TD","TF","TG","TH",
        "TJ","TK","TM","TN","TO","TL","TR","TT","TV","TW","TZ","UA",
        "UG","UM","US","UY","UZ","VA","VC","VE","VG","VI","VN","VU",
        "WF","WS","YE","YT","RS","ZA","ZM","ME","ZW","A1","A2","O1",
        "AX","GG","IM","JE","BL","MF","BQ","SS",NULL};


// find a spider structure by target address
TracerouteSpider *Traceroute_FindByTarget(AS_context *ctx, uint32_t target_ipv4, struct in6_addr *target_ipv6) {
    TracerouteSpider *sptr = ctx->traceroute_spider;

    while (sptr != NULL) {
        if (target_ipv4 && target_ipv4 == sptr->target_ip)
            break;

        if (!target_ipv4 && CompareIPv6Addresses(&sptr->target_ipv6, target_ipv6))
            break;

        sptr = sptr->next;
    }

    return sptr;
}


// find a spider structure by its hop (router) address
TracerouteSpider *Traceroute_FindByHop(AS_context *ctx, uint32_t hop_ipv4, struct in6_addr *hop_ipv6) {
    TracerouteSpider *sptr = ctx->traceroute_spider;

    while (sptr != NULL) {
        if (hop_ipv4 && hop_ipv4 == sptr->hop_ip)
            break;

        if (!hop_ipv4 && CompareIPv6Addresses(&sptr->hop_ipv6, hop_ipv6))
            break;

        sptr = sptr->next;
    }

    return sptr;
}


// find a spider structure by its identifier (query identification ID fromm traceroute packets)
TracerouteSpider *Traceroute_FindByIdentifier(AS_context *ctx, uint32_t id, int ttl) {
    TracerouteQueue *qptr = TracerouteQueueFindByIdentifier(ctx, id);

    if (qptr == NULL) return NULL;

    return qptr->responses[ttl];
}


// retry for all missing TTL for a particular traceroute queue..
int Traceroute_Retry(AS_context *ctx, TracerouteQueue *qptr) { //uint32_t identifier) {
    int i = 0;
    int ret = -1;
    int cur_ttl = 0;
    TracerouteSpider *sptr = NULL;
    //TracerouteQueue *qptr = NULL;
    int missing = 0;

    //printf("traceroute_retry\n");
    if (qptr == NULL) return -1;
    
    if (ctx->traceroute_max_retry && (qptr->retry_count > ctx->traceroute_max_retry)) {
        //printf("reached max retry.. max: %d qptr: %d\n", ctx->traceroute_max_retry, qptr->retry_count);
        ret = 0;
        goto end;
    }

    // loop for all TTLs and check if we have a packet from it
    for (i = ctx->traceroute_min_ttl; i < MAX_TTL; i++) {
        //sptr = Traceroute_FindByIdentifier(ctx, qptr->identifier, i);
        sptr = qptr->responses[i];

        // if we reached the target... its completed
        // *** add ipv6
        if (sptr && sptr->target_ip == qptr->target_ip) {
            break;
        }

        // if we cannot find traceroute responses this query, and this TTL
        if (sptr == NULL) {
            if (cur_ttl < MAX_TTL) {
                // we put it back into the list..
                qptr->ttl_list[cur_ttl++] = i;
            }
            missing++;
        }
        // if the source IP matches the target.. then it is completed
    }

    if (missing) {
        // set queue structure to start over, and have a max ttl of how many we have left
        qptr->current_ttl = 0;
        qptr->max_ttl = cur_ttl;
        qptr->retry_count++;

        RandomizeTTLs(qptr);

        // its not completed yet..
        qptr->completed = 0;

        //printf("Enabling incomplete traceroute %u [%d total]\n", qptr->target_ip, cur_ttl);
    }


    ret = 1;

    end:;
    return ret;
}


// loop and try to find all missing traceroute packets
// we wanna do this when our queue reaches 0
int Traceroute_RetryAll(AS_context *ctx) {
    int i = 0;
    int ret = -1;
    TracerouteQueue *qptr = NULL;

    //printf("retry all\n");

    // loop for all in queue
    qptr = ctx->traceroute_queue;

    while (qptr != NULL) {
        // retry command for this queue.. itll mark to retransmit all missing
        i = Traceroute_Retry(ctx, qptr);

        if (i) {
            //printf("successful retry on %p\n", qptr);
            ret++;
        }

        qptr = qptr->next;
    }

    if (ret) {
        Traceroute_AdjustActiveCount(ctx);
        //printf("%d traceroutes being retried\n", ret);
    }

    return ret;
}





// this can be handeled recursively because we have max TTL of 30.. its not so bad
int Traceroute_Search(AS_context *ctx, TracerouteSpider *start, TracerouteSpider *looking_for, int distance) {
    int i = 0, n = 0;
    int ret = 0, r = 0;
    TracerouteSpider *sptr = NULL;
    TracerouteQueue *q[2];

    // if distance is moore than max ttl.. lets return
    if (distance >= MAX_TTL) return 0;

    // if pointers are NULL for some reason
    if (!start || !looking_for) return 0;

    // dbg msg
    printf("Traceroute_Search: start %p [%u] looking for %p [%u] distance: %d\n",  start, start->hop_ip, looking_for, looking_for->hop_ip, distance);

    // get both original queue structures
    if ((q[0] = TracerouteQueueFindByIdentifier(ctx, start->identifier_id)) == NULL) goto end;
    if ((q[1] = TracerouteQueueFindByIdentifier(ctx, looking_for->identifier_id)) == NULL) goto end;


    // first we check q[0] looking for the target IP from looking_for (thus why we set n=0.. )
    for (i = n = 0; i < MAX_TTL; i++) {
        sptr = q[n]->responses[i];
        if (sptr->hop_ip == looking_for->hop_ip) {

            r = sptr->ttl - looking_for->ttl;
            if (r < 0) r = abs(r);
            return r;

            break;
        }
    }

    // now lets recursively scan both sides looking for a response
    for (n = 0; n < 2; n++) {
        for (i = 0; i < MAX_TTL; i++) {
            sptr = q[n]->responses[i];
            if (sptr != NULL) {
                // recursively call using this structure
                r = Traceroute_Search(ctx, sptr, looking_for, distance + 1);
            }
        }
    }

    end:;

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
    if (first->hop_ip == second->hop_ip) return 1;

    // we wanna call this function Traceroute_Search to find the distance  of the two spider parameters passed
    distance = Traceroute_Search(ctx,first, second, 0);

    // print distance to screen
    printf("distance: %d\n", distance);

    // prepare to return it..
    ret = distance;

    end:;

    return ret;
}




// find a traceroute queue structure by the identifier it used
int TracerouteQueueFindByIdentifier(AS_context *ctx, uint32_t identifier) {
    TracerouteQueue *qptr = ctx->traceroute_queue;
    while (qptr != NULL) {

        if (qptr->identifier == identifier) break;

        qptr = qptr->next;
    }

    return qptr;
}


// link with other traceroute structures of the same queue (same target/scan)
int Spider_IdentifyTogether(AS_context *ctx, TracerouteSpider *sptr) {
    TracerouteSpider *srch = ctx->traceroute_spider;
    int ret = 0;
    int a, b;
    TracerouteQueue *qptr = TracerouteQueueFindByIdentifier(ctx, sptr->identifier_id);

    if (qptr == NULL) return -1;

    // lets give the original queue a direct pointer to every TTL responses regarding its lookup
    // its much easier than having it in a linked list.. especially for later analysis
    qptr->responses[sptr->ttl] = sptr;

    ret = 1;    

    return ret;
}


// randomize TTLs.. for adding a new traceroutee queue, and loading data files with missing TTLs we wish to retry
void RandomizeTTLs(TracerouteQueue *tptr) {
    int i = 0, n = 0, ttl = 0;

    // only randomize if more than 5
    if (tptr->max_ttl <= 5) return;

    // randomize TTLs between 0 and 15 (so each hop doesnt get all 50 at once.. higher chance of scanning  probability of success)    
    for (i = 0; i < (tptr->max_ttl / 2); i++) {
        // array randomization
        // pick which 0-15 we will exchange the current one with
        n = rand()%tptr->max_ttl;
        // use 'ttl' as temp variable to hold that TTL we want to swap
        ttl = tptr->ttl_list[n];

        // swap it with this current enumeration by the i for loop
        tptr->ttl_list[n] = tptr->ttl_list[i];

        // move from swapped variable to complete the exchange
        tptr->ttl_list[i] = ttl;
    }
}

// take the TTL list, and remove completed, or found to decrease the 'max_ttl' variable so later we can randomly
// enable/disable queues so we can scan a lot more (randomly as well)
void ConsolidateTTL(TracerouteQueue *qptr) {
    int ttl_list[MAX_TTL+1];
    int i = 0;
    int cur = 0;

    // loop and remove all completed ttls...
    while (i < qptr->max_ttl) {
        if (qptr->ttl_list[i] != 0)
            ttl_list[cur++] = qptr->ttl_list[i];
        i++;
    }

    // copy the ones we found back into the queue structure
    i = 0;
    while (i < cur) {
        qptr->ttl_list[i] = ttl_list[i];
        i++;
    }

    // set current to now so it can start
    qptr->max_ttl = cur;
    qptr->current_ttl = 0;
    qptr->ts_activity = 0;

    // done..
}

// lets randomly disable all queues, and enable thousands of others...
// this is so we dont perform lookups immediately for every traceroute target..
int Traceroute_AdjustActiveCount(AS_context *ctx) {
    int ret = 0;
    int disabled = 0;
    int count = 0;
    int r = 0;
    TracerouteQueue *qptr = ctx->traceroute_queue;

    if (!qptr) return -1;

    count = L_count((LINK *)qptr);

    // disable ALL currently enabled queues.. counting the amount
    while (qptr != NULL) {
        // if its enabled, and not completed.. lets disable
        if (qptr->enabled && !qptr->completed) {
            qptr->enabled = 0;
            disabled++;
        }
        qptr = qptr->next;
    }

    // now enable the same amount of random queues
    // ret is used here so we dont go over max amt of queue allowed..
    // this allowedw this function to get reused during modifying traffic parameters
    while (disabled && (ret < ctx->traceroute_max_active)) {
        // pick a random queue
        r = rand()%count;

        // find it..
        qptr = ctx->traceroute_queue;
        while (r-- && qptr) { qptr = qptr->next; }

        // some issues that shouldnt even take place..
        if (!qptr) continue;

        if (!qptr->completed) {
            qptr->enabled = 1;
            disabled--;
            ret++;
        }

        // we will do that same loop until we have enough enabled..
    }
    
    return ret;
}


// Analyze a traceroute response again  st the current queue and build the spider web of traceroutes
// for further strategies
int TracerouteAnalyzeSingleResponse(AS_context *ctx, TracerouteResponse *rptr) {
    int ret = 0;
    TracerouteQueue *qptr = ctx->traceroute_queue;
    TracerouteSpider *sptr = NULL, *snew = NULL, *slast = NULL;
    struct in_addr src;
    int i = 0;
    int left = 0;


    //printf("Traceroute Analyze Single responsse %p\n", rptr);

    // if the pointer was NULL.. lets just return with 0 (no error...)
    if (rptr == NULL) return ret;

    qptr = TracerouteQueueFindByIdentifier(ctx, rptr->identifier);
    
    // we had a match.. lets link it in the spider web
    if (qptr != NULL) {
        // if this hop responding matches an actual target in the queue... then that traceroute is completed
        if ((rptr->hop_ip && rptr->hop_ip == qptr->target_ip) ||
            (!rptr->hop_ip && !qptr->target_ip && CompareIPv6Addresses(&rptr->hop_ipv6, &qptr->target_ipv6))) {

                //printf("------------------\nTraceroute completed %p [%u %u]\n-------------------\n", qptr, rptr->hop, qptr->target);
                // normal non randomized traceroute TTLs we just mark it as completed
                //qptr->completed = 1;

                //  If we are doing TTLs in random order rather than incremental.. then lets enumerate over all of the ttls for this queue
                for (i = 0; i < qptr->max_ttl; i++) {
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

            snew->country = GEOIP_IPtoCountryID(ctx, snew->hop_ip);
            snew->asn_num = GEOIP_IPtoASN(ctx, snew->hop_ip);
            
            // in case later we wanna access the original queue which created the entry
            snew->queue = qptr;

            //snew->country = GEOIP_IPtoCountryID(ctx, snew->hop_ip);
            
            // link into list containing all..
            L_link_ordered_offset((LINK **)&ctx->traceroute_spider, (LINK *)snew, offsetof(TracerouteSpider, next));

            // insert into list for traceroute information
            Traceroute_Insert(ctx, snew);

            // link it to the original queue by its identifier
            Spider_IdentifyTogether(ctx, snew);

            // log for watchdog to adjust traffic speed
            Traceroute_Watchdog_Add(ctx);

            ret = 1;
        }
    }

    end:;
    return ret;
}


// inserts a traceroute structure into the linked list but does sorting on insertion
int Traceroute_Insert(AS_context *ctx, TracerouteSpider *snew) {
    int ret = -1;
    int i = 0;
    TracerouteSpider *sptr = NULL, *snext = NULL, *slast = NULL;
    TracerouteSpider *search = NULL;

    sptr = ctx->traceroute_spider_hops;

    // check if hop exist...
    if (sptr == NULL) {
        ctx->traceroute_spider_hops = snew;
    } else {
        while (sptr != NULL) {
            // compare the current elements IP, and ours.. so we know whether we belong before, match, or after it
            i = IPv4_compare(sptr->hop_ip, snew->hop_ip);

            if (i == 0) {
                // we match this element IP exactly.. add as a branch inside of its structure
                snew->branches = sptr->branches;
                sptr->branches = snew;
                break;
            } else if (i == 1) {
                // here .. lets ensure we are before this element by changing the next of last to this one
                if (slast != NULL) {

                    snew->hops_list = slast->hops_list;
                    slast->hops_list = snew;

                } else {

                    if (ctx->traceroute_spider_hops == sptr) {

                        snew->hops_list = ctx->traceroute_spider_hops;
                        ctx->traceroute_spider_hops = snew;
                    }
                    
                }

                break;
            } else if (i == -1) {

                if (ctx->traceroute_spider_hops == sptr) {
                    snew->hops_list = ctx->traceroute_spider_hops;

                    ctx->traceroute_spider_hops = snew;

                } else {

                    if (slast != NULL) {
                        snew->hops_list = slast->hops_list;
                        slast->hops_list = snew;
                    }

                }
                break;
            }

            slast = sptr;
            sptr = sptr->next;
        }
    }

    ret = 1;

    // lets setup jump table if its less than the one for this...
    // since its in order itll help find..

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

    tptr->type = TRACEROUTE_ICMP;

    // add to traceroute queue...
    //L_link_ordered_offset((LINK **)&ctx->traceroute_queue, (LINK *)tptr, offsetof(TracerouteQueue, next));
    tptr->next = ctx->traceroute_queue;
    ctx->traceroute_queue = tptr;

    // enable default TTL list
    for (i = ctx->traceroute_min_ttl; i < MAX_TTL; i++) tptr->ttl_list[i] = (i - ctx->traceroute_min_ttl);

    // randomize those TTLs
    RandomizeTTLs(tptr);

    end:;
    return ret;
}


// When we initialize using Traceroute_Init() it added a filter for ICMP, and set this function
// as the receiver for any packets seen on the wire thats ICMP
int Traceroute_IncomingICMP(AS_context *ctx, PacketBuildInstructions *iptr) {
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
// todo: allow doing random TTLS (starting at 5+) for 10x... most of the end hosts or hops will respond like this
// we can prob accomplish much more
int Traceroute_Perform(AS_context *ctx) {
    TracerouteQueue *tptr = ctx->traceroute_queue;
    TracerouteResponse *rptr = ctx->traceroute_responses, *rnext = NULL;
    struct icmphdr icmp;
    PacketBuildInstructions *iptr = NULL;
    AttackOutgoingQueue *optr = NULL;
    int i = 0, n = 0;
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

    printf("Traceroute_Perform: Queue %d [completed %d] max: %d\n", L_count((LINK *)tptr), Traceroute_Count(ctx, 1, 1), ctx->traceroute_max_active);

    // loop until we run out of elements
    while (tptr != NULL) {        
        // if we have reached max ttl then mark this as completed.. otherwise it could be marked completed if we saw a hop which equals the target
        if (tptr->current_ttl >= tptr->max_ttl) {
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
                while ((tptr->current_ttl < tptr->max_ttl) && tptr->ttl_list[tptr->current_ttl] == 0) {
                    // disqualify this ttl before we move to the next..
                    // this is for easily enabling/disabling large amounts of queues so we can
                    // attempt to scan more simultaneously (and retry easily for largee amounts)

                    // its already 0 (in the while &&)
                    //tptr->ttl_list[tptr->current_ttl] = 0;

                    tptr->current_ttl++;
                }

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
    // moved to every 40 because the randomly disabling and enabling should be more than MAX_TTL at least
    if ((ccount++ % 40)==0) {
        Spider_Save(ctx);

        // lets randomly enable or disable queues.... 20% of the time we reach this..
        if ((rand()%100) < 20)
            Traceroute_AdjustActiveCount(ctx);
    }

    // count how many traceroutes are in queue and active
    tcount = Traceroute_Count(ctx, 0, 0);

    // if the amount of active is lower than our max, then we will activate some other ones
    if (tcount < ctx->traceroute_max_active) {
        
        // how many to ativate?
        tcount = ctx->traceroute_max_active - tcount;
    
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

    // do we adjust max active?
    Traceroute_Watchdog(ctx);

    end:;
    return ret;
}



// dump traceroute data to disk.. printing a little information..
// just here temporarily.. 
int Spider_Save(AS_context *ctx) {
    TracerouteSpider *sptr = NULL;
    int count = 0;
    FILE *fd = NULL;
    FILE *fd2 = NULL;
    char fname[32];
    TracerouteSpider *bptr = NULL;
    char Ahop[16], Atarget[16];
    struct in_addr conv;
    TracerouteQueue *qptr = NULL;

    // open file for writing traceroute queues...
    sprintf(fname, "traceroute_queue.txt", "w");
    fd = fopen(fname, "w");

    // filename for debug data
    sprintf(fname, "traceroute.txt", "w");
    fd2 = fopen(fname, "w");
    //fd2 = NULL; // disabling it by settinng to NULL

    // dump all traceroute queues and their identifiers
    qptr = ctx->traceroute_queue;
    while (qptr != NULL) {

        if (fd) {
            conv.s_addr = qptr->target_ip;            
            strcpy((char *)&Atarget, inet_ntoa(conv));

            fprintf(fd, "QUEUE,%s,%u,%d,%d,%d,%d,%d\n", Atarget,
                qptr->identifier, qptr->retry_count, qptr->completed,
                qptr->enabled, qptr->ts_activity, qptr->ts);

        }

        qptr = qptr->next;
    }

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

        //printf("L2 %p\n", sptr);
    }

    // how many traceroute hops do we have? (unique.. dont count branches)
    // *** fix this.. we neeed an L_count() for _offset() because this will count the total fromm the first element
    printf("Traceroute Spider count: %d\n", L_count_offset((LINK *)ctx->traceroute_spider_hops, offsetof(TracerouteSpider, hops_list)));
    printf("Traceroute total count: %d\n", L_count((LINK *)ctx->traceroute_spider));

    // close file if it was open
    if (fd) fclose(fd);
    if (fd2) fclose(fd2);

    return 0;
}


int IPv4_compare(uint32_t comp, uint32_t ipv4) {
    struct  in_addr addr;
    char Aip[16];
    int a=0,b=0,c=0,d=0;
    int a2=0,b2=0,c2=0,d2=0;

    // get a.b.c.d for the IP we are comparing with
    d = (comp & 0xff000000) >> 24;
    c = (comp & 0x00ff0000) >> 16;
    b = (comp & 0x0000ff00) >> 8;
    a = (comp & 0x000000ff);

    // get a.b.c.d for the IP we are comparing against
    d2 = (ipv4 & 0xff000000) >> 24;
    c2 = (ipv4 & 0x00ff0000) >> 16;
    b2 = (ipv4 & 0x0000ff00) >> 8;
    a2 = (ipv4 & 0x000000ff);

    // A.b.c.d: which IP has a higher a?
    if (a2 < a) return -1;
    if (a2 > a) return 1;

    // a.B.c.d: which IP has a higher b?
    if (b2 < b) return -1;
    if (b2 > b) return 1;

    // a.b.C.d: which IP has a higher c?
    if (c2 < c) return -1;
    if (c2 > c) return 1;

    // a.b.c.D: which IP has a higher d?
    if (d2 < d) return -1;
    if (d2 > d) return 1;

    // 0 only if IPs are exact match
    if (d2 == d) return 0;
}



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



// load data from a file.. this is for development.. so I can use the python interactive debugger, and write various C code
// for the algorithms required to determine the best IP addresses for manipulation of the mass surveillance networks
int Spider_Load(AS_context *ctx, char *filename) {
    FILE *fd = NULL, *fd2 = NULL;
    char buf[1024];
    char *sptr = NULL;
    char type[16], hop[16],target[16];
    int ttl = 0;
    uint32_t identifier = 0;
    int ts =0, enabled = 0, activity = 0, completed = 0, retry = 0;
    int i = 0;
    int n = 0;
    TracerouteSpider *Sptr = NULL;
    TracerouteSpider *snew = NULL;
    TracerouteSpider *slast = NULL, *Blast = NULL;
    TracerouteQueue *qnew = NULL;
    char fname[32];
    char *asnum_name = NULL;

    // traceroute responses (spider)
    sprintf(fname, "%s.txt", filename);
    // open ascii format file
    if ((fd = fopen(fname, "r")) == NULL) goto end;

    // traceroute queue
    sprintf(fname, "%s_queue.txt", filename);
    // open ascii format file
    if ((fd2 = fopen(fname, "r")) == NULL) goto end;

    // read all lines
    while (fgets(buf,1024,fd2)) {
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
        sscanf(buf, "%s %s %"SCNu32" %d %d %d %d %d", &type, &target, &identifier,
         &retry, &completed, &enabled, &activity, &ts);

        // cannot allocate?? 
        if ((qnew = (TracerouteQueue *)calloc(1, sizeof(TracerouteQueue))) == NULL) break;

        // set parameters from data file
        qnew->completed = completed;
        qnew->retry_count = retry;
        qnew->ts = ts;
        qnew->ts_activity = activity;

        // we wanna control enabled here when we look for all TTL hops
        qnew->enabled = 0;//enabled;

        qnew->target_ip = inet_addr(target);
        qnew->identifier = identifier;

        // void GeoIP_lookup(AS_context *ctx, TracerouteQueue *qptr, TracerouteSpider *sptr) {

        // lookup on demand later.. so it loads fast...
        // GeoIP_lookup(ctx, qnew); 

        //qnew->country = GEOIP_IPtoCountryID(ctx, target);
        //qnew->asn_num = GEOIP_IPtoASN(ctx, target);
        

        // set all TTLs in the list to their values
        // ***
        // turn randomizing into its own function later and set here..
        //for (n = 0; n < MAX_TTL; n++) qnew->ttl_list[n] = n;
        //qnew->max_ttl = MAX_TTL;

        qnew->next = ctx->traceroute_queue;
        ctx->traceroute_queue = qnew;
    }

    // first we load the traceroute responses.. so we can use the list for re-enabling ones which were  in progress
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
        sscanf(buf, "%s %s %s %"SCNu32" %d", &type, &hop, &target, &identifier, &ttl);

        //printf("type: %s\nhop %s\ntarget %s\nident %X\nttl %d\n", type, hop,target, identifier, ttl);

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

        // GeoIP_lookup(ctx, qnew); 

        // link into main list
        Traceroute_Insert(ctx, snew);

        // link to original queue structure by identifier
        Spider_IdentifyTogether(ctx, snew);

        // before we fgets() again lets clear the buffer
        // *** had a weird bug with sscanf.. im pretty sure this is useless but it began working duringn 4-5 changes..
        // ill rewrite this entire format binary soon anyways.
        memset(buf,0,1024);
    }



    //printf("calling Traceroute_RetryAll to deal with loaded data\n");
    Traceroute_RetryAll(ctx);

    end:;

    if (fd) fclose(fd);
    if (fd2) fclose(fd2);

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
    nptr->incoming_function = &Traceroute_IncomingICMP;
    nptr->flt = flt;

    // insert so the network functionality will begin calling our function for these paackets
    nptr->next = ctx->IncomingPacketFunctions;
    ctx->IncomingPacketFunctions = nptr;
    
    // get our own ip addresses for packet building
    ctx->my_addr_ipv4 = get_local_ipv4();
    get_local_ipv6(&ctx->my_addr_ipv6);

    // max of 20 retries for traceroute
    // it retries when all queues are completed..
    // the data is extremely important to ensure attacks are successful
    // especially if we wanna do the most damage from a single node
    // distributed? good luck.
    ctx->traceroute_max_retry = 100;
    // start at ttl 8 (need to change this dynamically from script) doing it manually for research
    ctx->traceroute_min_ttl = 0;

    // how many active at all times? we set it here so we can addjust it in watchdog later...
    ctx->traceroute_max_active = 1850;

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
int Traceroute_Count(AS_context *ctx, int return_completed, int count_disabled) {
    TracerouteQueue *qptr = ctx->traceroute_queue;
    int ret = 0;
    //int pass = 0;

    // loop until we enuerate the entire list of queued traceroute activities
    while (qptr != NULL) {

        // ** rewrite this logic... to deall w all flags correctly.. I kept adding them instantly..
        // not logically..

        // check if they are completed.. if not we increase the counter
        if (!return_completed && !qptr->completed) {
            if (count_disabled && !qptr->enabled) ret++;

            if (!count_disabled && qptr->enabled) ret++;
        }

        if (return_completed && qptr->completed) {
            ret++;
        }

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

// we call this to let the watchdog know that some incoming traceroute was successful
void Traceroute_Watchdog_Add(AS_context *ctx) {
    int i = 0;
    int ts = time(0);

    // which part of array to use? we loop back around if over max with %1024
    i = ctx->Traceroute_Traffic_Watchdog.HistoricRawCurrent % (1024*10);

    // parameters
    ctx->Traceroute_Traffic_Watchdog.HistoricDataRaw[i].ts = ts;
    ctx->Traceroute_Traffic_Watchdog.HistoricDataRaw[i].count=1;
    ctx->Traceroute_Traffic_Watchdog.HistoricDataRaw[i].max_setting = ctx->traceroute_max_active;

    // thats all.. simple.. increase counter
    ctx->Traceroute_Traffic_Watchdog.HistoricRawCurrent++;
}




// monitors historic amount of queries that we get so we can adjust
// the active amount of traceroutes we are performing automatically for
// highest speed possible
int Traceroute_Watchdog(AS_context *ctx) {
    int ret = 0;
    int i = 0;
    TraceroutePerformaceHistory *hptr = &ctx->Traceroute_Traffic_Watchdog;
    int total = 0;
    int interval_seconds = 10;
    int ts = time(0); // current time for calculations

    int historic_count = 0;
    int interval_sum = 0;
    int interval_max = 0;
    int prior_ts = 0;
    int which = 0;
    int up = 0, down = 0;
    int total_historic_to_use = 4;
    CountElement *cptr[total_historic_to_use+1];
    
    float perc_change;
    int historic_avg_increase = 0;


    i = Traceroute_Count(ctx, 0, 0);

    if (i == 0) return 0;

    // if there arent any entries then there is nothing to do
    if (hptr->HistoricRawCurrent == 0) {
        //printf("no historic\n");
        return 0;
    }

    for (i = 0; i < (1024*10); i++) {
        if ((ts - hptr->HistoricDataRaw[i].ts) > interval_seconds) {
            interval_sum += hptr->HistoricDataRaw[i].count;
            interval_max = hptr->HistoricDataRaw[i].max_setting;
        }
    }

    // interval sum contains the amount within the last X seconds at any given moment
    // now we would like to know between a specific time period

    // on the second entry we know when the first waas calculated
    // so we can automatically choose that minute:second and start all of our interval
    // counts using that as a reference... but how to set the first?

    if (hptr->HistoricCurrent) {
        prior_ts = hptr->HistoricDataCalculated[ctx->Traceroute_Traffic_Watchdog.HistoricCurrent - 1].ts;
    }

    // prior_ts would be 0 here.. so it will trigger on the first...
    if ((ts - prior_ts) < interval_seconds) {
        //printf("not time ts %d prior %d .. interval %d [%d]\n", ts, prior_ts, interval_seconds, (ts-prior_ts));
        return 0;
    }

    // lets log...
    hptr->HistoricDataCalculated[hptr->HistoricCurrent].count = interval_sum;
    hptr->HistoricDataCalculated[hptr->HistoricCurrent].ts = ts;
    hptr->HistoricDataCalculated[hptr->HistoricCurrent].max_setting = ctx->traceroute_max_active;

    //printf("count: %d ts: %d max %d\n", interval_sum, ts, ctx->traceroute_max_active);

    // increase historic counter.. so we can keep track of more
    

    if (hptr->HistoricCurrent == (1024*10))
        hptr->HistoricCurrent = 0;

    // now we need to use the data we have to determine we wish to dynamically modify the max traceroute queue
    // we want at least 3 to attempt to modifhiy...
    if (hptr->HistoricCurrent >= total_historic_to_use) {

        if ((ts - ctx->watchdog_ts) < (60*10)) {
            return 0;
        }

        // get pointer to the last 3
        for (i = 0; i < total_historic_to_use; i++) {
            cptr[i] = (CountElement *)&ctx->Traceroute_Traffic_Watchdog.HistoricDataCalculated[ctx->Traceroute_Traffic_Watchdog.HistoricCurrent - (i+1)];

            // wait until they are all on same speed... (minute and a half at current setting)
            if (cptr[i]->max_setting != hptr->HistoricDataCalculated[hptr->HistoricCurrent - 1].max_setting) {
                //printf("dont have %d of same max\n", total_historic_to_use);
                goto end;
            }

            //printf("cptr[i].count = [%d, %d]\n", i, cptr[i]->count);
            //printf("Against %d\n", hptr->HistoricDataCalculated[hptr->HistoricCurrent].count);

            // lets get percentage change...
            perc_change = (float)((float)hptr->HistoricDataCalculated[hptr->HistoricCurrent].count / (float)cptr[i]->count);
            perc_change *= 100;

            //historic[i] /= 
            if (cptr[i]->count < hptr->HistoricDataCalculated[hptr->HistoricCurrent].count) {
                if (perc_change > 105) up++;
            } else {
                if (perc_change < 90) down++;
            }
        }


        if (up > down) {
            ctx->traceroute_max_active += 300;
        } else
        if (up < down) {
            ctx->traceroute_max_active -= 50;

        }   
        
        /*     if (good >= (total_historic_to_use/2)) ctx->traceroute_max_active += 300;
        //if (good == 1) ctx->traceroute_max_active += 50;
        else if (good > (total_historic_to_use/4)) ctx->traceroute_max_active += ((5+rand()%5) - rand()%10);
        
        else if (good <= (total_historic_to_use/4)) ctx->traceroute_max_active -= 50;
        */

        if (ctx->traceroute_max_active < 50) ctx->traceroute_max_active = 50;

        if (ctx->traceroute_max_active > 10000) ctx->traceroute_max_active = 10000;


        ctx->watchdog_ts = ts;

        //printf("up %d down %d and ret is %d\n", up, down, ret);

        ret = 1;

        if (ret == 1)
            // adjust active queue using the new setting
            Traceroute_AdjustActiveCount(ctx);
    }

    end:;
    hptr->HistoricCurrent++;
    return ret;
}


// reset all queries retry counter to 0
int TracerouteResetRetryCount(AS_context *ctx) {
    int ret = 0;
    TracerouteQueue *qptr = ctx->traceroute_queue;

    while (qptr != NULL) {
        if (qptr->retry_count) qptr->retry_count=0;

        ret++;

        qptr = qptr->next;
    }

    return ret;
}



// initialize other functionality in research besides traceroute
int Research_Init(AS_context *ctx) {
    int ret = 0;

    // set context handler for geoip
    if ((ctx->geoip_handle = GeoIP_open("GeoIP.dat", GEOIP_STANDARD | GEOIP_SILENCE)) == NULL) return -1;
    
    ctx->geoip_asn_handle = GeoIP_open("GeoIPASNum.dat", GEOIP_ASNUM_EDITION_V6 | GEOIP_SILENCE);

    ret = 1;

    return ret;
}


// geoip turn country into an int for easy storage
int GEOIP_CountryToID(char *country) {
    int i = 0;
    int ret = 0;
    
    while (geoip_countries[i] != NULL) {
        if (strcmp(geoip_countries[i], country) == 0) {
            ret = i;
            break;
        }
        i++;
    }

    return ret;
}

// turn address into a country (ascii) to country (unsigned char) value
// list came directly from maxmind but converted from php -> C
int GEOIP_IPtoCountryID(AS_context *ctx, uint32_t addr) {
    GeoIP *gi = (GeoIP *)ctx->geoip_handle;
    GeoIPRegion *region = NULL;
    char *country = NULL;
    int i = 0;
    int ret = 0;

    if (gi == NULL) return 0;

    if ((country = (char *)GeoIP_country_code_by_ipnum(gi, addr)) == NULL) {
        return 0;
    }

    // get the country ID from country ASCII
    ret = GEOIP_CountryToID(country);

    return ret;
}


// generate an IP address within a specific country (by its 2 gTLD)
// we wanna be able to find new routes to target
uint32_t ResearchGenerateIPCountry(AS_context *ctx, char *want_country) {
    uint32_t addr = 0;
    char *country = NULL;
    int tries = 5000;
    uint32_t ret = 0;

    // use max retry in case something goes wrong.. 5000 is a lot.
    // i had this fail during testing for other reasons and it still worked fine
    // due to the retry
    while (tries--) {
        // generate a random IPv4 address
        addr = rand()%0xFFFFFFFF;
        // get the  country as an ascii string for this IP address
        if ((country = (char *)GeoIP_country_code_by_ipnum(ctx->geoip_handle, addr)) != NULL) {
            // if it matches the country we are trying to generate an IP address for
            if (strcmp(country, want_country)==0) {
                // then we prepare ret to return this IP addresss
                ret = addr;
                break;
            }
        }
    }

    // return the address
    return ret;
}


// Adds a single IP address to the traceroute queue which is randomly generated, and falls inside of a specific country
int TracerouteAddCountryIP(AS_context *ctx, char *want_country) {
    int ret = 0;
    uint32_t ip = 0;

    // generate a random IP address which matches this country
    ip = ResearchGenerateIPCountry(ctx, want_country);

    // if that was successful
    if (ip != 0) {
        // then we add the IP as a traceroute queue so we have analysis information
        Traceroute_Queue(ctx, ip, NULL);

        // success
        ret = 1;
    }

    // return whether we were successful or not
    return ret;
}


// IP to ASN #
int GEOIP_IPtoASN(AS_context *ctx, uint32_t addr) {
    char asn[16];
    char *sptr = NULL;
    char *asnum_name = NULL;
    int i = 0;
    int n = 0;
    int ret = 0;

    // if the handle for ASN lookups exist from opening the database successfully
    if (ctx->geoip_asn_handle)
        asnum_name = GeoIP_name_by_ipnum(ctx->geoip_asn_handle, addr);

    if (asnum_name != NULL) {
        strncpy(asn, asnum_name, sizeof(asn));
        // find the first space ("AS0000<space>Some useless information")
        if ((sptr = strchr(asnum_name, ' ')) != NULL) {
            // turn that space into NULL, so "AS0000"
            *sptr = 0;
            // verify string is only "AS<number>""
            if (asnum_name[0] == 'A' && asnum_name[1] == 'S') {
                // if so.. get a pointer to the number only.. "0000"
                sptr = (char  *)(asnum_name+2);
                // verify all characters are numbers..
                for (i = 0; i < strlen(sptr); i++) {
                    // increase n if not a digit
                    if (!isdigit(sptr[i])) n++;
                }
                // if there were only all digits.. 
                if (n == 0) {
                    // we respond with the number itself only
                    ret = atoi(sptr);
                }
            }
        }
    }

    return ret;
}


// perform geoip lookup on either type of structure that we moved here to increase loading speed
void GeoIP_lookup(AS_context *ctx, TracerouteQueue *qptr, TracerouteSpider *sptr) {
    if (qptr != NULL) {
        qptr->country = GEOIP_IPtoCountryID(ctx, qptr->target_ip);
        qptr->asn_num = GEOIP_IPtoASN(ctx, qptr->target_ip);
    }

    if (sptr != NULL) {
        sptr->country = GEOIP_IPtoCountryID(ctx, sptr->target_ip);
        sptr->asn_num = GEOIP_IPtoASN(ctx, sptr->target_ip);   
    }
}



// get least used connection options for the next fabricated attack.. possibly filtering by countries
ResearchConnectionOptions *ResearchConnectionGet(AS_context *ctx, int country) {
    ResearchConnectionOptions *optr = NULL;
    ResearchConnectionOptions *ret = NULL;


    // find by somme criteria.. will change
    optr = ctx->research_connections;
    while (optr != NULL) {

        // checking client country. we need to check for both.. and if neither match
        // than we can  verify against all hops, and ensure its within 1-2 hops or
        // close to the country
        if (!country || (country && ((country == optr->server.country) || (country == optr->client.country)))) {
            ret = optr;
            break;
        }
        optr = optr->next;
    }

    end:;

    // increase count if we are returning w a structure
    if (ret) {
        ret->count++;
        ret->last_ts = time(0);
    }

    return ret;
}



// find an analysis structure by either two nodes, or 1.. itll check both sides..
TracerouteAnalysis *Traceroute_AnalysisFind(AS_context *ctx, TracerouteQueue *node1, TracerouteQueue *node2) {
    TracerouteAnalysis *n1 = NULL, *n2 = NULL;
    TracerouteAnalysis *tptr = ctx->analysis_list;


    while (tptr != NULL) {
        // first we find exact match
        if ((tptr->node1 == n1) && (tptr->node2 == n2)) break;
        if ((tptr->node1 == n2) && (tptr->node2 == n1)) break;

        tptr = tptr->next;
    }

    // return the full match if we found it
    if (tptr) return tptr;

    tptr = ctx->analysis_list;
    while (tptr != NULL) {
        // now we just make sure one side matches
        if ((tptr->node1 == n1) || (tptr->node2 == n1)) break;
        if ((tptr->node1 == n2) || (tptr->node2 == n2)) break;

        tptr = tptr->next;
    }

    // return the match any node query
    return tptr;
}

// create a traceroute analysis structure for storing informatiion regarding two sides of a connectioon
// to be reused, or used again
TracerouteAnalysis *Traceroute_AnalysisNew(AS_context *ctx, TracerouteQueue *node1, TracerouteQueue *node2) {
    TracerouteAnalysis *tptr = NULL;
    if ((tptr = (TracerouteAnalysis *)calloc(1, sizeof(TracerouteAnalysis))) == NULL) return NULL;

    tptr->ts = time(0);
    tptr->active_ts = 0;

    tptr->node1 = node1;
    tptr->node2 = node2;

    // curiousity is % of whether or not we attempt to modify IP, or search for
    // simmilar/close things by a random generatred nunmber modulated by this
    tptr->curiousity = 0;

    tptr->border_score = 0;

    // link into context list
    L_link_ordered_offset((LINK **)&ctx->analysis_list, (LINK *)tptr, offsetof(TracerouteAnalysis, next));

    return tptr;
}

/*
Analysis is distance, and geoip/etc investigation between two NODE_PROCESSING_INSTRUCTION + curiousity

ResearchNodeOptions is a local structure used to represent ipv4/6, OS emulation information, and original queue for a node1...
it shouldnt need the original queue, and should contain all its own memory so it doesnt reference anything else.. essentially work alone
ConnectionOptions is a list of currently used, or generated + verified details which can be used for an attack, and whether it currently is
(attack ptr)
has border score, count, and hop_country already in memory prepared for using with other things
    TracerouteQueue *node1; TracerouteQueue *node2;
    int border_score;  int curiousity;
    int active_ts; int ts;
} TracerouteAnalysis;

ResearchConnectionOptions has an analysis Pointer
a client/serfver researchnodeinformation side
border score, hop_country[MAX_TTL], ts, ,and count`

researchinformationnode has 'information' ptr to gtraceroute queue
country, asnum.. os EmulationParameters
border score both ip types ipv4/ipv6
-
traceroute analysis has border score, curiosuoity (scan near),
active ts, and ts 

nodoe1/2 traceroute queue 
{
    uint32_t ip; struct in6_addr ipv6; int is_ipv6;
    int country; int asn_num;
    int os_emulation_id; int border_score;
    TracerouteQueue *information;
} ResearchNodeInformation;
// we list all chosen client/server here for use in attack lists
{}
    ResearchNodeInformation client; ResearchNodeInformation server;
    AS_attacks *attackptr;
    TracerouteAnalysis *analysis;
    int hop_country[MAX_TTL];
    int border_score;
    int count;
    int ts; int last_ts;
} ResearchConnectionOptions;



*/