/*

Research is everything related to strategy choices.  For example, which sites do we wish to spend the majority
of our bandwidth falsifying connections towards?  It will perform DNS lookups, traceroutes, and BGP analysis to
determine the best IP 4/6 addresses to use for attacks.

For local attacks: NIDs, etc.. It will take the local IP addresses, and find the best ways of attacking
the platform to either hide in other packets, or attempt to force other issues such as Admin believing hacks
are taking place elsewhere.. etc


The data and information from the automated traceroute can get reused in several different ways.  Reverse DDoS (to detect hacking
even through tor, etc) can use information/routes from this to pick, and calculate the attacks to perform to automate
finding the target


we shouild dns lookup traceroutees to get more IPs (Reverse, and regular..) we can also look for dns responses with multiple ips
need to scan for open dns servers (to get geoip dns automatically)


border score is used to keep track of how many borders traffic between two targets goes through.. it can help determine the best
overall worldwide strategies for attacking the most platforms simultaneously... on the other hand for a virus/trojan it can determine
the best way to get logged at the least amount of ISPs, etc.... as a precaution  during attacks/hacks


also we can keep a static list of all known fiber taps later.. and possibly even use neural networks to quickly determine whether or not
others may expect to be in a location.. and other information used for research could be used as inputs in this NN

the NN is also required to verify automaticttally generated content words etc to ensure they are less likely to be automatically filtered
(using modified words/phrases/replacements and then seeing if it passes)..


--------------
with packet capturing to disk, raw packet reading.. all packet analysis already coded
and tcp/ip connection finding/pairing... we have enough parts to take arbitrary http connections
and find locations to turn into macros (fist name last name, msgs, etc)
and auto populate server/client bodies for session fabricating...

in the end i want the system to be able to run on a network.. or router and update itself, and its sites to use
for attacks dynamically fromm live traffic.. thus never having to worry about updating etc

soon ill move to python 3.. i started and decided to put it off.. but now that i realize i need to support all languages
ill do it soon to extend into unicode, and allow non-USA characters, etc...

The traceroute code isnt as necessary for attacking mass surveillance directly.  Just a few traceroutes in real time,
could help you find client ips which would reach different routing in a country.  GeoIP is pretty important since you can
assume your going through surveillance into, and out of a country.

The blackhole attack however, especially, IPv6 requires the traceroute data.. It also will increase probability, and help
find new IPv6 addresses.  

-------------

I'll have to make this thing take live capture packets and reuse them for traceroute...


'Fuzzy' links are going to be where we assume, and insert links to fill in gaps in traceroute data.
Priority should help drastically in ensuring needed targets are thoroughly analyzed for path
calculations.

I will chain IP generator to this especially for IPv6.  It wiill help take IP addresses, and then
use traceroute to attempt to find randomm subnets for use.  

I will have to try IPv6 GeoIP as well since i haven't used it before




--------------------------------------
http://etutorials.org/Networking/network+security+assessment/Chapter+4.+IP+Network+Scanning/4.2+TCP+Port+Scanning/

I have some attack, and research scenarios which will use things like this:


4.2.3.4 IP ID header scanning

IP ID header scanning (also known as idle or dumb scanning) is an obscure scanning technique that involves abusing implementation peculiarities within the TCP/IP stack of most operating systems. Three hosts are involved:

The host, from which the scan is launched

The target host, which will be scanned

A zombie or idle host, which is an Internet-based server that is queried with spoofed port scanning against the target host to identify open ports from the perspective of the zombie host

IP ID header scanning is extraordinarily stealthy due to its blind nature. Determined attackers will often use this type of scan to map out IP-based trust relationships between machines, such as firewalls and VPN gateways.

The listing returned by the scan shows open ports from the perspective of the zombie host, so you can try scanning a target using various zombies you think might be trusted (such as hosts at remote offices or DMZ machines). Figure 4-10 depicts the process undertaken during an IP ID header scan.

Figure 4-10. IP ID header scanning and the parties involved

hping2 was originally used in a manual fashion to perform such low-level TCP scanning, which was time consuming and tricky to undertake against an entire network of hosts. A white paper that fully discusses using the tool to perform IP ID header scanning by hand is available from http://www.kyuzz.org/antirez/papers/dumbscan.html.

nmap supports such IP ID header scanning with the option:

-sI <zombie host[:probe port]>


OR
nmap/idle_scan.cc

---------------------

This is a nice example of how you can mix several subsystems, and technologies requiring analysis and still automate it completely.

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
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stddef.h> /* For offsetof */
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "research.h"
#include "utils.h"
#include "identities.h"
#include "scripting.h"

// for geoip
#include "GeoIP.h"
#include "GeoIPCity.h"



#ifndef offsetof
#define offsetof(type, member) ( (int) & ((type*)0) -> member )
#endif


extern char generator_function[];


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

// Global Mass Surveillance - The Fourteen Eyes (https://www.privacytools.io/)
// These will be priority.. especially since anything crossing these borders can more than likely assume that path
// will have surveillance platforms monitoring their packets crossing these borders.
char *fourteen_eyes[] = {"AU","CA","NZ","GB","US","DE","FR","NL","NO","BE","DE","IT","ES","SE",NULL};

// check if a country is in the 'fourteen eyes' list.. higher probability of state surveillance during analysis
int fourteen_check(char *country) {
    int i = 0;

    for (;i < 14; i++) if (strcmp(country, fourteen_eyes[i]) == 0) return 1;

    return 0;
}

// check if a country is in the 'fourteen eyes' list.. higher probability of state surveillance during analysis
int fourteen_check_id(int country_id) {
    int i = 0;

    for (;i < 14; i++) if (strcmp(geoip_countries[country_id], fourteen_eyes[i]) == 0) return 1;

    return 0;
}


// count border score from a particular traceroute spider to us
int BorderScore(AS_context *ctx, TracerouteSpider *sptr) {
    int ret = 0, n = 0;
    int border_score = 0;
    TracerouteQueue *qptr = NULL;
    int last_country = 0;


    if (sptr == NULL) return -1;

    GeoIP_lookup(ctx, NULL, sptr);

    // cannot calculate if the country lookup didnt work
    if (!sptr->country) return -1;

    // we have a traceroute spider which relates to the country right here..
    // we wanna trace further back its TTL to US using the original queue
    if ((qptr = sptr->queue) == NULL) goto end;

    // we start with the country.. so we can count each time the border changes
    last_country = sptr->country;

    // lets count how many countries we go through to reach this destination
    // yes it is using a random path but thats acceptable for now..
    // enumerate all TTLs going from the current (hop in couuntry) to us
    for (n = sptr->ttl; n > 0; n--) {
        // if we found a response for this lower TTL
        if ((sptr = qptr->responses[n]) != NULL) {
            // did we have a country code from this response?
            // lookup geoip in case
            GeoIP_lookup(ctx, NULL, sptr);
            
            // if the country lookup went well
            if (sptr->country) {
                // is this country different than the last hop that we verified against?
                if (last_country != sptr->country) {
                    border_score++;
                    last_country = sptr->country;
                }
            }
        }
    }

    ret = border_score;

    end:;
    return ret;
}


// we'd like to know how many hops we have until we reach a country if it is a fourteen eyes country
// if it matches, thne we want to find a hop.. and count all TTL before it and their countries..
// for each country swapp we increase border_score
int fourteen_borderscore(AS_context *ctx, char *country) {
    int ret = 0;
    int country_id = country ? GEOIP_CountryToID(country) : 0;
    TracerouteSpider *sptr = NULL;

    // we search for a response by its  country
    sptr = ctx->traceroute_spider;
    while (sptr != NULL) {
        if (sptr->country && sptr->country == country_id) break;

        sptr = sptr->next;
    }

    if (sptr)
        return BorderScore(ctx, sptr);

    return 0;
}



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
    TracerouteSpider *sptr = ctx->traceroute_spider_jump[IP_JTABLE(hop_ipv4, &hop_ipv6)];

    while (sptr != NULL) {
        if (hop_ipv4 && hop_ipv4 == sptr->hop_ip)
            break;

        if (!hop_ipv4 && CompareIPv6Addresses(&sptr->hop_ipv6, hop_ipv6))
            break;

        sptr = sptr->jump;
    }

    return sptr;
}


// find a spider structure by its identifier (query identification ID fromm traceroute packets)
TracerouteSpider *Traceroute_FindByIdentifierTTL(AS_context *ctx, uint32_t id, int ttl) {
    TracerouteQueue *qptr = TracerouteQueueFindByIdentifier(ctx, id);

    if (qptr == NULL) return NULL;

    return qptr->responses[ttl];
}


// retry for all missing TTL for a particular traceroute queue..
int Traceroute_Retry(AS_context *ctx, TracerouteQueue *qptr) {
    int i = 0;
    int ret = -1;
    int cur_ttl = 0;
    TracerouteSpider *sptr = NULL;
    int missing = 0;

    //printf("traceroute_retry\n");
    if (qptr == NULL) return -1;
    
    if (ctx->traceroute_max_retry && (qptr->retry_count > ctx->traceroute_max_retry)) {
        //printf("reached max retry.. max: %d qptr: %d\n", ctx->traceroute_max_retry, qptr->retry_count);
        ret = 0;
        goto end;
    }

    // loop for all TTLs and check if we have a packet from it
    for (i = 0; i < MAX_TTL; i++) {
        //sptr = Traceroute_FindByIdentifier(ctx, qptr->identifier, i);
        sptr = qptr->responses[i];

        // if we reached the target... its completed
        // *** add ipv6
        if (sptr && sptr->hop_ip && qptr->target_ip && sptr->hop_ip == qptr->target_ip) {
            //printf("ip same ttl %d\n", i);
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

        // randommize the TTLs which are left
        RandomizeTTLs(qptr);

        // its not completed yet..
        qptr->completed = 0;
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





SearchQueue *Context_FindQueue(AS_context *ctx, SearchContext *search_context, TracerouteSpider *sptr) {
    SearchQueue *qptr = search_context->queue;

    while (qptr != NULL) {
        if (qptr->spider_ptr == sptr) break;

        qptr = qptr->next;
    }

    return qptr;
}


int Search_QueueAdd(AS_context *ctx, SearchContext *search_context, TracerouteSpider *sptr, int distance) {
    SearchQueue *qptr = NULL;

    if ((qptr = Context_FindQueue(ctx, search_context, sptr)) != NULL) {
        // if distance is lower.. then lets change it.. *warning* maybe not thikning throug h every solution.. check
        if (distance < qptr->distance) {
            printf("QPTR Seardch context %p CHANGED distance from %d -> %d\n", qptr->spider_ptr, qptr->distance, distance);
            qptr->distance = distance;
        }
    }

    if ((qptr = (SearchQueue *)calloc(1, sizeof(SearchQueue))) == NULL) return -1;

    qptr->spider_ptr = sptr;
    qptr->distance = distance;

    L_link_ordered((LINK **)&search_context->queue, (LINK *)qptr);

    search_context->count++;

    printf("Added search directory to queue .. count %d\n", search_context->count);

    return 1;
}

SearchQueue *Search_QueuePop(AS_context *ctx, SearchContext *search_context, int *distance) {
    SearchQueue *qptr = search_context->queue;

    printf("count: %d\n", L_count((LINK *)qptr));

    if (qptr) {
        *distance = qptr->distance;
        search_context->queue = qptr->next;

        search_context->count--;
    }

    return qptr;
}

// pops and verifies against 1 stack entry
int Search_QueueCheck(AS_context *ctx, SearchContext *sctx, TracerouteSpider *needle, int cur_distance) {
    SearchQueue *qptr = NULL;
    int distance = 0;
    TracerouteSpider *sptr = NULL;

    printf("count: %d %d\n", L_count((LINK *)sctx->queue), sctx->count);

    // pop a single item which was queued for checking against
    if ((qptr = Search_QueuePop(ctx, sctx, &distance)) == NULL) return 0;

    if (qptr->distance > cur_distance) return 0;
    sptr = qptr->spider_ptr;

    if (!needle->hop_ip && sptr->hop_ip == needle->hop_ip)
        return qptr->distance;

    if (!needle->hop_ip && CompareIPv6Addresses(&needle->hop_ipv6, &sptr->hop_ipv6)) return qptr->distance;

    return 0;
}



// this can be handeled recursively because we have max TTL of 30.. its not so bad
int Traceroute_Search(AS_context *ctx, SearchContext *search_context, TracerouteSpider *start, TracerouteSpider *looking_for, int distance, int fuzzy) {
    int i = 0, n = 0;
    int ret = 0, r = 0;
    TracerouteSpider *sptr = NULL;
    TracerouteQueue *q[2];
    int d[MAX_TTL][2];
    int imaginary = 0;


    // if distance is moore than max ttl.. lets return
    if (distance >= MAX_TTL) {
        printf("we reached max ttl.. quitting\n");
        return 0;
    }

    // if pointers are NULL for some reason
    if (!start || !looking_for) {
        printf("null ptr\n");
        return 0;
    }

    // dbg msg
    printf("Traceroute_Search: start %p [%u] looking for %p [%u] distance: %d imaginary %d\n",  start, start->hop_ip, looking_for, looking_for->hop_ip, distance, imaginary);


    // this call is allowing/wanting fuzzy relationships.. we should fill in anything that isnt found
    if (fuzzy) {

    }

    // get both original queue structures
    if ((q[0] = TracerouteQueueFindByIdentifier(ctx, start->identifier_id)) == NULL) {
        printf("Queue find  by identifier q[0] start->id %X not found\n", start->identifier_id);
        goto end;
    }
    if ((q[1] = TracerouteQueueFindByIdentifier(ctx, looking_for->identifier_id)) == NULL) {
        printf("Queue find  by identifier q[1] needle->id %X not found\n", looking_for->identifier_id);
        goto end;
    }


    // first we check q[0] looking for the target IP from looking_for (thus why we set n=0.. )
    for (i = n = 0; i < MAX_TTL; i++) {
        sptr = q[n]->responses[i];
        if (sptr != NULL) {
            if (sptr->hop_ip == looking_for->hop_ip) {

                r = sptr->ttl - looking_for->ttl;
                if (r < 0) r = abs(r);
                return r;

                break;
            }
        }
    }

    // now lets recursively scan both sides looking for a response
    // without imaginary first...then with
    for (imaginary = 0; imaginary < 2; imaginary++) {
        for (n = 0; n < 2; n++) {
            for (i = 0; i < MAX_TTL; i++) {
                sptr = q[n]->responses[i];
                //printf("n: %d i: %d sptr: %p\n", n, i, sptr);
                if (sptr != NULL) {
                    //printf("Adding to queue\n");
                    Search_QueueAdd(ctx, search_context, sptr, distance + 1);
                    // recursively call using this structure
                    //r = Traceroute_Search(ctx, search_context, sptr, looking_for, distance + 1, imaginary);
                }
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
int Traceroute_Compare(AS_context *ctx, TracerouteSpider *first, TracerouteSpider *second, int imaginary) {
    int ret = 0;
    TracerouteSpider *srch_main = NULL;
    TracerouteSpider *srch_branch = NULL;
    int distance = 0;
    SearchContext search_context;
    int r = 0;

    // make sure both were passed correctly
    if (!first || !second) return -1;

    // if they are the same..
    if (first->hop_ip == second->hop_ip) return 1;

    memset(&search_context, 0, sizeof(SearchContext));

    printf("Traceroute Compare first %p second %p [%X %X]\n", first, second, first->identifier_id, second->identifier_id);

    // we wanna call this function Traceroute_Search to find the distance  of the two spider parameters passed
    distance = Traceroute_Search(ctx, &search_context, first, second, 0, imaginary);

    // now lets go through the queue..
    printf("count: %d\n", search_context.count);
    while (search_context.count) {
        r = Search_QueueCheck(ctx, &search_context, second, distance);

        printf("r: %d\n", r);

        // we dont wanna break here since we should pop everything no matter what
        // to free the space
        if (r && r < distance) distance = r;

    }
    // print distance to screen
    printf("distance: %d\n", distance);

    // prepare to return it..
    ret = distance;

    end:;

    return ret;
}




// find queue by IP
int TracerouteQueueFindByIP(AS_context *ctx, uint32_t ipv4) {
    TracerouteQueue *qptr = ctx->traceroute_queue;
    while (qptr != NULL) {

        if (qptr->target_ip == ipv4) break;

        qptr = qptr->next;
    }

    return qptr;
}

// find a traceroute queue structure by the identifier it used
// This was taking forever (15-20 minutes) to load 250k traceroute context.  I inserted this
// jump table, and changed the format from ASCII to binary for saving/loading.  It is less than a second now.
int TracerouteQueueFindByIdentifier(AS_context *ctx, uint16_t identifier) {
    TracerouteQueue *qptr = ctx->traceroute_queue_identifier[identifier % JTABLE_SIZE];

    while (qptr != NULL) {

        if (qptr->identifier == identifier) break;

        qptr = qptr->next_identifier;
    }

    return qptr;
}


// link with other traceroute structures of the same queue (same target/scan)
int Spider_IdentifyTogether(AS_context *ctx, TracerouteSpider *sptr) {
    TracerouteSpider *srch = ctx->traceroute_spider;
    int ret = 0;
    int a, b;
    TracerouteQueue *qptr = TracerouteQueueFindByIdentifier(ctx, sptr->identifier_id);

    if (qptr == NULL) {
        return -1;
    }

    // lets give the original queue a direct pointer to every TTL responses regarding its lookup
    // its much easier than having it in a linked list.. especially for later analysis
    qptr->responses[sptr->ttl] = sptr;
    sptr->queue = qptr;
    //printf("qptr %p responses for ttl %d to %p [resp %p]\n", qptr, sptr->ttl, sptr, qptr->responses[sptr->ttl]);

    ret = 1;    

    return ret;
}


// randomize TTLs.. for adding a new traceroutee queue, and loading data files with missing TTLs we wish to retry
void RandomizeTTLs(TracerouteQueue *tptr) {
    int i = 0, n = 0, ttl = 0;

    //return;
    
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

    memset(&ttl_list, 0, sizeof(int)*MAX_TTL);

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
    int r = 0;
    int i = 0;
    int total_count = 0;
    TracerouteQueue *qptr = ctx->traceroute_queue;
    int *random_count = NULL;

    if (!qptr) return -1;

    // disable ALL currently enabled queues.. counting the amount
    while (qptr != NULL) {
        if (!qptr->priority) {
            // if its enabled, and not completed.. lets disable
            if (qptr->enabled && !qptr->completed) {
                qptr->enabled = 0;
                disabled++;
            }
        }

        total_count++;
        qptr = qptr->next;
    }

    // by making an array of which to re-enable.. we dont loop over the  list several times..
    // it'll just handle it in one shot
    if ((random_count = (int *)calloc(1, sizeof(int) * disabled)) == NULL) goto end;

    // pick which to enable
    for (r = 0; r < disabled; r++) random_count[r] = rand()%total_count;

    // iterate the traceroute queue list and enable ones in the array we just created
    qptr = ctx->traceroute_queue;
    while (qptr && (ret < ctx->traceroute_max_active)) {
        for (r = 0; r < disabled; r++) {
            if (random_count[r] == i) {
                qptr->enabled = 1;
                qptr->type = TRACEROUTE_UDP;//(rand()%100) > 50 ? 1 : 0;
                ret++;
            }
        }
        i++;

        qptr = qptr->next;
    }

    end:;

    // free array since we dont need it anymore
    if (random_count != NULL) free(random_count);
    
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
    char *IP = NULL;

    // if the pointer was NULL.. lets just return with 0 (no error...)
    if (rptr == NULL) return ret;

    if (rptr->ttl > MAX_TTL) return ret;

    //printf("Traceroute Analyze Single responsse %p\n", rptr);

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
                if (!left) {
                    qptr->completed = 1;
                }
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

            // calculate border score between us and this response
            snew->border_score = BorderScore(ctx, snew);

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

int IP_JTABLE(uint32_t ip, struct in6_addr *ipv6) {
    int i = 0;
    uint32_t _ip = 0;
    uint32_t *_ipv6 = NULL;

    if (ip) {
        _ip = ip;
    } else {
        // add all 4 parts of ipv6 together to make a fake IPv4 just so we can calculate the jump table.. so they share the same
        while (i < 4) {
            _ipv6 = (uint32_t *)((char *)ipv6+(sizeof(uint32_t)*i));
            _ip += *_ipv6;

            i++;
        }
    }

    return (_ip % JTABLE_SIZE);
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

                    snew->hops_list = sptr->hops_list;
                    sptr->hops_list = snew;

                    //snew->hops_list = slast->hops_list;
                    //slast->hops_list = snew;

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

    snew->jump = ctx->traceroute_spider_jump[IP_JTABLE(snew->hop_ip, &snew->hop_ipv6)];
    ctx->traceroute_spider_jump[IP_JTABLE(snew->hop_ip, &snew->hop_ipv6)] = snew;

    // every 1000 entries.. lets fill some gaps with other queue data
    //if (ctx->new_traceroute_entries++ >= 1000) { Traceroute_FillAll(ctx); ctx->new_traceroute_entries = 0; }

    ret = 1;

    // lets setup jump table if its less than the one for this...
    // since its in order itll help find..

    end:;
    return ret;
}



// Queue an address for traceroute analysis/research
TracerouteQueue *Traceroute_Queue(AS_context *ctx, uint32_t target, struct in6_addr *targetv6) {
    TracerouteQueue *tptr = NULL;
    int ret = -1;
    int i = 0;
    int n = 0;
    int ttl = 0;
    //struct in_addr addr;

    if ((tptr = TracerouteQueueFindByIP(ctx, target)) != NULL) return tptr;
    

    //addr.s_addr = target;
    //printf("\nTraceroute Queue %u: %s\n", target, inet_ntoa(addr));

    // allocate memory for this new traceroute target we wish to add into the system
    if ((tptr = (TracerouteQueue *)calloc(1, sizeof(TracerouteQueue))) == NULL) goto end;

    // which IP are we performing traceroutes on
    tptr->target_ip = target;

    // if its an ipv6 addres pasased.. lets copy it (this function will verify its not NULL)
    CopyIPv6Address(&tptr->target_ipv6, targetv6);

    // we start at ttl 1.. itll inncrement to that when processing
    tptr->current_ttl = 0;

    while(1) {
        // create a random identifier to find this packet when it comes from many hops
        tptr->identifier = rand()%0xFFFFFFFF;
        // lets be sure the identifier doesnt already exist..
        if (TracerouteQueueFindByIdentifier(ctx, tptr->identifier) == NULL) break;
    }

    // later we wish to allow this to be set by scripting, or this function
    // for example: if we wish to find close routes later to share... we can set to max = 5-6
    // and share with p2p nodes when mixing/matching sides of the taps (when they decide to secure them more)
    tptr->max_ttl = MAX_TTL;

    // current timestamp stating it was added at this time
    tptr->ts = time(0);

    // set for traceroute ICMP
    tptr->type = TRACEROUTE_UDP;//(rand()%100) > 50 ? 1 : 0;

    // add to traceroute queue...
    //L_link_ordered_offset((LINK **)&ctx->traceroute_queue, (LINK *)tptr, offsetof(TracerouteQueue, next));
    tptr->next = ctx->traceroute_queue;
    ctx->traceroute_queue = tptr;

    // create the jump table to skip those 15 minutes of loading I was getting with 280k stored traceroute contexts
    tptr->next_identifier = ctx->traceroute_queue_identifier[tptr->identifier % JTABLE_SIZE];
    ctx->traceroute_queue_identifier[tptr->identifier % JTABLE_SIZE] = tptr;


    // enable default TTL list
    for (i = ctx->traceroute_min_ttl; i < MAX_TTL; i++) tptr->ttl_list[i] = (i - ctx->traceroute_min_ttl);

    // randomize those TTLs
    RandomizeTTLs(tptr);

    end:;
    return tptr;
}



static int icount = 0;
// When we initialize using Traceroute_Init() it added a filter for ICMP, and set this function
// as the receiver for any packets seen on the wire thats ICMP
int Traceroute_IncomingICMP(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = -1;
    TracerouteResponse *rptr = NULL;
    TraceroutePacketData *pdata = NULL;
    char data[]="@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
    struct udphdr *udph = NULL;
    // when we extract the identifier from the packet.. put it here..
    uint16_t identifier = 0;
    // ttl has to be extracted as well (possibly from the identifier)
    int ttl = 0;
    char *IP = NULL;
    FILE *fd = NULL;
    char fname[32];


    if (iptr->source_ip && (iptr->source_ip == ctx->my_addr_ipv4)) {
        //printf("ipv4 Getting our own packets.. probably loopback\n");
        return 0;
    }

    if (!iptr->source_ip && CompareIPv6Addresses(&ctx->my_addr_ipv6, &iptr->source_ipv6)) {
        //printf("ipv6 Getting our own packets.. probably loopback\n");
        return 0;
    }

    
    // data isnt big enough to contain the identifier
    if (iptr->source_ip) {
        if (iptr->data_size >= (20 + sizeof(struct udphdr))) {
            // udp header in packet
            udph = ((char *)(iptr->data) + 20);
            if (ntohs(udph->dest) >= 1024) {
                // we assume its correct if its >1024... in reality if someone screws with this by spoofing..
                // whats it really going to accomplish?.. not much.
                identifier = ntohs(udph->source);
                ttl = ntohs(udph->dest) - 1024;
            }
        } else {
            goto end;
        }
    } else {
        if (iptr->data_size >= (48 + sizeof(struct udphdr))) {
            udph = ((char *)(iptr->data) + 48);
            if (ntohs(udph->dest) >= 1024) {
                // we assume its correct if its >1024... in reality if someone screws with this by spoofing..
                // whats it really going to accomplish?.. not much.
                identifier = ntohs(udph->source);
                ttl = ntohs(udph->dest) - 1024;
            }
            
        } else {
            goto end;
        }
    }
    
    /*
    if (1==0 && !ttl && !identifier) {
        //printf("Getting ttl/ident from included data\n");
        // the responding hops may have encapsulated the original ICMP within its own.. i'll turn the 28 into a sizeof() calculation
        // ***
        if (iptr->data_size > sizeof(TraceroutePacketData) && ((iptr->data_size >= (sizeof(data) + sizeof(TraceroutePacketData) + 28))))
            pdata = (TraceroutePacketData *)((char *)(iptr->data) + 28 + sizeof(data));//(sizeof(struct iphdr) + sizeof(struct icmphdr)));
        else
            pdata = (TraceroutePacketData *)((char *)(iptr->data) + sizeof(data));

        // the packet has the TTL, and the identifier (to find the original target information)
        ttl = pdata->ttl;
        identifier = pdata->identifier;
        //printf("got from data\n");
    }
    */
    //printf("incoming icmp ttl %d identifier %u\n", ttl, identifier);
    // this function is mainly to process quickly.. so we will fill another structure so that it can get processed
    // later again with calculations directly regarding its query

    // allocate a new structure for traceroute analysis functions to deal with it later
    if ((rptr = (TracerouteResponse *)calloc(1, sizeof(TracerouteResponse))) == NULL) goto end;
    rptr->identifier = identifier;
    rptr->ttl = ttl;
    //rptr->ts = time(0);
    
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




// UDP will send a fake 'response' for DNS to a client from port 53.. this will allow bypassing a lot of firewalls
// http://www.binarytides.com/dns-query-code-in-c-with-winsock/
// *** must finish.. in reality the packet is irrelevant.. since routers dont process the infromation whatsoever...
// only the final host would even 'see' or process the DNS structure
int Traceroute_SendUDP(AS_context *ctx, TracerouteQueue *tptr) {
    int i = 0, ret = 0;
    PacketBuildInstructions *iptr = NULL;
    TraceroutePacketData *pdata = NULL;
    char data[]="@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
   
   //printf("traceroute send udp\n");
    
    // create instruction packet for the ICMP(4/6) packet building functions
    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
        // this is the current TTL for this target
        iptr->ttl = tptr->ttl_list[tptr->current_ttl];

        // determine if this is an IPv4/6 so it uses the correct packet building function
        if (tptr->target_ip != 0) {
            iptr->type = PACKET_TYPE_UDP_4|PACKET_TYPE_UDP;
            iptr->destination_ip = tptr->target_ip;
            iptr->source_ip = ctx->my_addr_ipv4;
        } else {
            iptr->type = PACKET_TYPE_UDP_6|PACKET_TYPE_UDP;
            // destination is the target
            CopyIPv6Address(&iptr->destination_ipv6, &tptr->target_ipv6);
            iptr->destination_ip = 0;
            // source is our ip address
            CopyIPv6Address(&iptr->source_ipv6, &ctx->my_addr_ipv6);
            iptr->source_ip = 0;
        }

        // ports to use (we can  randomize later on diff tries besides 53)
        // This will look like a DNS response coming back to the client
        iptr->source_port = tptr->identifier;//1024 + (rand()%(65535-1024));
        iptr->destination_port = 1024 + iptr->ttl;//1024 + (rand()%(65535-1024));
    
        // set size to the traceroute packet data structure's size...
        iptr->data_size = sizeof(data) + sizeof(TraceroutePacketData);

        if ((iptr->data = (char *)calloc(1, iptr->data_size)) != NULL) {
            pdata = (TraceroutePacketData *)((char  *)(iptr->data)+sizeof(data));

            // prepare dns response packet...
            
            // lets include a little message since we are performing a lot..
            // if ever on a botnet, or worm.. disable this obviously
            strncpy(&pdata->msg, "performing traceroute research", sizeof(pdata->msg));

            // set the identifiers so we know which traceroute queue the responses relates to
            pdata->identifier = tptr->identifier;
            pdata->ttl = iptr->ttl;


            memcpy(iptr->data, &data, sizeof(data));

            iptr->header_identifier = tptr->identifier;

        }

        //printf("sending traceroute identifier %u ttl %d\n", tptr->identifier, iptr->ttl);

        // lets build a packet from the instructions we just designed for either ipv4, or ipv6
        // for either ipv4, or ipv6
        if (iptr->type & PACKET_TYPE_UDP_6)
            i = BuildSingleUDP6Packet(iptr);
        else if (iptr->type & PACKET_TYPE_UDP_4)
            i = BuildSingleUDP4Packet(iptr);

        // if the packet building was successful
        if (i == 1)
            NetworkQueueAddBest(ctx, iptr, 0);

    }

    PacketBuildInstructionsFree(&iptr);
   
    end:;
    return ret;
}



// moved into its own function so i can finish supporting UDP, and TCP traceroutes
int Traceroute_SendICMP(AS_context *ctx, TracerouteQueue *tptr) {
    PacketBuildInstructions *iptr = NULL;
    struct icmphdr icmp;
    int ret = 0;
    TraceroutePacketData *pdata = NULL;
    int i = 0;
    AttackOutgoingQueue *optr = NULL;
    struct icmp6_hdr icmp6;
    
    memset(&icmp, 0, sizeof(struct icmphdr));
    memset(&icmp6, 0, sizeof(struct icmphdr));

    

    // create instruction packet for the ICMP(4/6) packet building functions
    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) != NULL) {
        // this is the current TTL for this target
        iptr->ttl = tptr->ttl_list[tptr->current_ttl];

        // determine if this is an IPv4/6 so it uses the correct packet building function
        // prepare the ICMP header for the traceroute
        if (tptr->target_ip != 0) {
            iptr->type = PACKET_TYPE_ICMP_4|PACKET_TYPE_ICMP|PACKET_TYPE_ICMP;
            iptr->destination_ip = tptr->target_ip;
            iptr->source_ip = ctx->my_addr_ipv4;

            icmp.type = ICMP_ECHO;
            icmp.un.echo.sequence = tptr->identifier;
            icmp.un.echo.id = tptr->identifier + tptr->ttl_list[tptr->current_ttl];

        } else {
            iptr->type = PACKET_TYPE_ICMP_6|PACKET_TYPE_ICMP|PACKET_TYPE_ICMP;

            icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6.icmp6_id = tptr->identifier + tptr->ttl_list[tptr->current_ttl];
            icmp6.icmp6_seq = tptr->identifier;
            
            // destination is the target
            CopyIPv6Address(&iptr->destination_ipv6, &tptr->target_ipv6);
            // source is our ip address
            CopyIPv6Address(&iptr->source_ipv6, &ctx->my_addr_ipv6);
        }

        // copy ICMP parameters into this instruction packet as a complete structure
        memcpy(&iptr->icmp, &icmp, sizeof(struct icmphdr));
        memcpy(&iptr->icmp6, &icmp6, sizeof(struct icmp6_hdr));

        // set size to the traceroute packet data structure's size...
        iptr->data_size = sizeof(TraceroutePacketData);

        if ((iptr->data = (char *)calloc(1, iptr->data_size)) != NULL) {
            pdata = (TraceroutePacketData *)iptr->data;

            // lets include a little message since we are performing a lot..
            // if ever on a botnet, or worm.. disable this obviously
            strncpy(&pdata->msg, "performing traceroute research", sizeof(pdata->msg));

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
        if (i == 1)
            NetworkQueueAddBest(ctx, iptr, 0);
    }

    PacketBuildInstructionsFree(&iptr);
   
    end:;
    return ret;
}


// analyze all queued responses...
int Traceroute_AnalyzeResponses(AS_context *ctx) {
    int ret = 0;
    TracerouteResponse *rptr = NULL, *rnext = NULL;

    // now process all queued responses we have from incoming network traffic.. it was captured on a thread specifically for reading packets
    rptr = ctx->traceroute_responses;

    // loop until all responsses have been analyzed
    while (rptr != NULL) {
        // call this function which will take care of the response, and build the traceroute spider for strategies
        if (TracerouteAnalyzeSingleResponse(ctx, rptr) == 1) ret++;

        // get pointer to next so we have it after freeing
        rnext = rptr->next;

        // free this response structure..
        free(rptr);

        // move to next
        rptr = rnext;
    }

    // we cleared the list so ensure the context is updated
    ctx->traceroute_responses = NULL;

    return ret;
}


// This being put into the main loop will ensure that there are always the max number of active traceroute queues.
int Traceroute_MaxQueue(AS_context *ctx) {
    int ret = 0;
    int tcount = 0;
    TracerouteQueue *tptr = NULL;

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

                ret++;
            }

            // move to the next target
            tptr = tptr->next;
        }
    }


    end:;
    return ret;
}



// iterate through all current queued traceroutes handling whatever circumstances have surfaced for them individually
// todo: allow doing random TTLS (starting at 5+) for 10x... most of the end hosts or hops will respond like this
// we can prob accomplish much more
// *** need to add UDP/TCP traceroute support for retry
int Traceroute_Perform(AS_context *ctx) {
    TracerouteQueue *tptr = ctx->traceroute_queue;
    int i = 0, n = 0;
    int ret = 0;
    // timestamp required for various states of traceroute functionality
    int ts = time(0);

    // if the list is empty.. then we are done here
    if (tptr == NULL) goto end;

    printf("Traceroute_Perform: Queue %d [completed %d] max: %d\n", L_count((LINK *)tptr), Traceroute_Count(ctx, 1, 1), ctx->traceroute_max_active);

    // loop until we run out of elements
    while (tptr != NULL) {
        // if we have reached max ttl then mark this as completed.. otherwise it could be marked completed if we saw a hop which equals the target
        if (tptr->current_ttl >= tptr->max_ttl) {
            tptr->completed = 1;

            ConsolidateTTL(tptr);

            // perform traceroute completion callback if it exists
            if (!tptr->max_ttl) {
                if (tptr->callback != NULL) {
                    tptr->callback(ctx, tptr->callback_id);
                    tptr->callback = NULL;
                }
            }

            // if its completed.. and its priority.. lets consolidate the missing TTL hops so itll continue
            // this is so we can immediately find more information required for an attack
            if (tptr->priority && tptr->priority < 100) {
                
                // if any are left.. keep it enabled.
                if (tptr->max_ttl) {
                    tptr->completed = 0;
                    tptr->priority++;
                }
            }
        }

        if (!tptr->completed && tptr->enabled) {
            // lets increase the TTL by this number (every 1 second right now)
            if ((ts - tptr->ts_activity) > 1 || 1==1) {
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
                    //if (tptr->type == TRACEROUTE_ICMP)
                      //  Traceroute_SendICMP(ctx, tptr);
                    //else if (tptr->type == TRACEROUTE_UDP)

                    for (i = 0; i < 3; i++) {
                        Traceroute_SendUDP(ctx, tptr);
                    }

                    /*    else if (tptr->type == TRACEROUTE_TCP)
                        Traceroute_SendTCP(ctx, tptr);*/
                }
            }
        }

        tptr = tptr->next;
    }

    // analyze all queued responses from the network thread
    Traceroute_AnalyzeResponses(ctx);
    
    // if our queue is lower than the max.. then enable some others
    Traceroute_MaxQueue(ctx);     

    // *** we will log to the disk every 20 calls (for dev/debugging)
    // moved to every 40 because the randomly disabling and enabling should be more than MAX_TTL at least
    if ((ccount++ % 40)==0) {
        // save data to disk... need to redo this for incremental
        Spider_Save(ctx);

        // lets randomly enable or disable queues.... 20% of the time we reach this..
        if ((rand()%100) < 20)
            Traceroute_AdjustActiveCount(ctx);
    }

    // do we adjust max active?
    Traceroute_Watchdog(ctx);

    // fill all missing... do this sometimes.
    //if ((rand()%100) > 90) 

    end:;

    return ret;
}

FILE *file_open_dump(char *filename) {
    char fname[1024];
    char  *sptr = NULL;
    char *zptr = NULL;
    int i = 0;

    i = file_exist(filename);
    if (!i) {
        return fopen(filename, "wb");
    }
    if ((sptr = strchr(filename, '.')) == NULL) return NULL;
    *sptr = 0; sptr++;
    strcpy(fname, filename);
    zptr = (char *)((&fname) + strlen(fname));
    zptr += sprintf(zptr, "%d_%d", getpid(), rand()%65535);
    strcpy(zptr, sptr);

    return fopen(fname, "wb");
}

#pragma pack(push,1)
typedef struct _data_entry {
    unsigned char code;
    uint32_t target_ip;
    uint32_t hop_ip;
    struct in6_addr hop_ipv6;
    uint16_t identifier;
    unsigned char completed;
    unsigned char enabled;
    int ts;
    int activity;
    int retry;
    int ttl;
} DataEntry;
#pragma pack(pop)



// dump traceroute data to disk.. printing a little information..
// just here temporarily.. 
int Spider_Save(AS_context *ctx) {
    TracerouteSpider *sptr = NULL;
    int count = 0;
    FILE *fd = NULL;
    
    char fname[32];
    TracerouteSpider *bptr = NULL;
    char Ahop[16], Atarget[16];
    struct in_addr conv;
    TracerouteQueue *qptr = NULL;
    DataEntry dentry;

    // open file for writing traceroute queues...
    sprintf(fname, "traceroute.dat");
    fd = fopen(fname, "wb");


    //Traceroute_FillAll(ctx);

    // dump all traceroute queues and their identifiers
    qptr = ctx->traceroute_queue;
    while (qptr != NULL) {

        memset(&dentry, 0, sizeof(DataEntry));
        // 1 = queue
        dentry.code = 1;

        dentry.target_ip = qptr->target_ip;  
        // !!! ipv6 save/load
        //CopyIPv6Address(&dentry.target_ipv6, &qptr->target_ipv6);
      
        dentry.identifier = qptr->identifier;
        dentry.completed = qptr->completed;
        dentry.activity = qptr->ts_activity;
        dentry.ts = qptr->ts;
        dentry.retry = qptr->retry_count;

        fwrite(&dentry, 1, sizeof(DataEntry), fd);

        qptr = qptr->next;
    }

    // enumerate spider and list information
    sptr = ctx->traceroute_spider_hops;
    while (sptr != NULL) {
        memset(&dentry, 0, sizeof(DataEntry));

        // hop..
        dentry.code = 2;

        dentry.target_ip = sptr->target_ip;
        // !!! ipv6 save/load
        //CopyIPv6Address(&dentry.target_ipv6, &sptr->target_ipv6);

        dentry.hop_ip = sptr->hop_ip;
        dentry.identifier = sptr->identifier_id;
        dentry.ts = sptr->ts;
        dentry.ttl = sptr->ttl;

        fwrite(&dentry, 1, sizeof(DataEntry), fd);
        
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
            memset(&dentry, 0, sizeof(DataEntry));

            // branch connected to most recent hop
            dentry.code = 3;
            dentry.target_ip = sptr->target_ip;
            // !!! ipv6 save/load
            //CopyIPv6Address(&dentry.target_ipv6, &sptr->target_ipv6);            
            dentry.hop_ip = sptr->hop_ip;
            dentry.identifier = sptr->identifier_id;
            dentry.ts = sptr->ts;            
            dentry.ttl = sptr->ttl;

            fwrite(&dentry, 1, sizeof(DataEntry), fd);

            // move to next in branch list
            bptr = bptr->branches;
        }

        // move to next in hop list (routers which have resppoonded to traceroute queries)
        sptr = sptr->hops_list;
    }

    // how many traceroute hops do we have? (unique.. dont count branches)
    // *** fix this.. we neeed an L_count() for _offset() because this will count the total fromm the first element
    printf("Traceroute Spider count: %d\n", L_count_offset((LINK *)ctx->traceroute_spider_hops, offsetof(TracerouteSpider, hops_list)));
    printf("Traceroute total count: %d\n", L_count((LINK *)ctx->traceroute_spider));

    // close file if it was open
    if (fd) fclose(fd);

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
// *** IPv6
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
            if (!hop && CompareIPv6Addresses(&sptr->hop_ipv6, hopv6))  break;
        }

        sptr = sptr->hops_list;
    }

    return sptr;
}




//  Loads data from a file, and does its best to ensure the structures are exactly as they were logged.  It ensures
//  we dont have to waste extra resources for processing whenever it was dumped directly from memory in an exact order.
//  This and a jumpp table for traceroute queue identifiers helped it load in 15-20minutes down to around 1-2seconds.
int Spider_Load(AS_context *ctx, char *filename) {
    FILE *fd = NULL, *fd2 = NULL;
    char buf[1024];
    char *sptr = NULL;
    char type[16], hop[16],target[16];
    int ttl = 0;
    uint16_t identifier = 0;
    int ts =0, enabled = 0, activity = 0, completed = 0, retry = 0;
    int i = 0;
    int n = 0;
    TracerouteSpider *Sptr = NULL;
    TracerouteSpider *snew = NULL;
    TracerouteSpider *hop_last = NULL;
    TracerouteSpider *slast = NULL, *Blast = NULL;

    TracerouteQueue *qnew = NULL;
    char fname[32];
    char *asnum_name = NULL;
    DataEntry dentry;
    

    // traceroute responses (spider)
    sprintf(fname, "%s.dat", filename);
    // open ascii format file
    if ((fd = fopen(fname, "rb")) == NULL) goto end;

    while (!feof(fd)) {
        if (fread(&dentry, 1, sizeof(DataEntry), fd) != sizeof(DataEntry)) break;

        if (!dentry.target_ip) continue;

        if (dentry.code == 1) {
            // cannot allocate?? 
            if ((qnew = (TracerouteQueue *)calloc(1, sizeof(TracerouteQueue))) == NULL) break;

            // set parameters from data file
            qnew->completed = dentry.completed;
            qnew->retry_count = dentry.retry;
            qnew->ts = dentry.ts;
            qnew->ts_activity = dentry.activity;

            // we wanna control enabled here when we look for all TTL hops
            qnew->enabled = dentry.enabled;
            qnew->target_ip = dentry.target_ip;
            // !!! save/load ipv6
            //CopyIPv6Address(&snew->target_ipv6, &dentry.target_ipv6);

            qnew->identifier = dentry.identifier;


            qnew->type = TRACEROUTE_UDP;//((rand()%100) > 50) ? 1 : 0;

            qnew->max_ttl = MAX_TTL;

            // add to queue list
            qnew->next = ctx->traceroute_queue;
            ctx->traceroute_queue = qnew;

            // put  in jump table.. for finding by identifier quickly
            qnew->next_identifier = ctx->traceroute_queue_identifier[qnew->identifier % JTABLE_SIZE];
            ctx->traceroute_queue_identifier[qnew->identifier % JTABLE_SIZE] = qnew;

        } else if (dentry.code == 2) {
            // allocate structure for storing this entry into the traceroute spider
            if ((snew = (TracerouteSpider *)calloc(1, sizeof(TracerouteSpider))) == NULL) break;

            // set various information we have read fromm the file into the new structure
        
            snew->target_ip = dentry.target_ip;
            snew->hop_ip = dentry.hop_ip;
            // !!! save/load ipv6
            //CopyIPv6Address(&snew->hop_ipv6, &dentry.hop_ipv6);

            snew->ttl = dentry.ttl;
            snew->identifier_id = dentry.identifier;
            snew->ts = dentry.ts;


            if (!slast) {
                ctx->traceroute_spider = snew;
                slast = snew;
            } else {
                slast->next = snew;
                slast = snew;
            }

            if (!hop_last) {
                ctx->traceroute_spider_hops = snew;
                hop_last = snew;
            } else {
                hop_last->hops_list = snew;
                hop_last = snew;
            }


        } else if (dentry.code == 3) {
            // allocate structure for storing this entry into the traceroute spider
            if ((snew = (TracerouteSpider *)calloc(1, sizeof(TracerouteSpider))) == NULL) break;

            // set various information we have read fromm the file into the new structure
        
            snew->target_ip = dentry.target_ip;
            snew->hop_ip = dentry.hop_ip;
            // !!! save/load ipv6
            //CopyIPv6Address(&snew->hop_ipv6, &dentry.target_ipv6);
            snew->ttl = dentry.ttl;
            snew->identifier_id = dentry.identifier;
            snew->ttl = dentry.ttl;

            if (slast != NULL) {
                snew->branches = slast->branches;
                slast->branches = snew;
            }
        }

        // if its more than just a queue.. we wanna link it together.. (for 2/3)
        if (snew && dentry.code && dentry.code > 1) {    
            //printf("ident together.. id %X\n", snew->identifier_id);
            Spider_IdentifyTogether(ctx, snew);


            snew->jump = ctx->traceroute_spider_jump[IP_JTABLE(snew->hop_ip, &snew->hop_ipv6)];
            ctx->traceroute_spider_jump[IP_JTABLE(snew->hop_ip, &snew->hop_ipv6)] = snew;

        }
    }


    //printf("calling Traceroute_RetryAll to deal with loaded data\n");
    Traceroute_RetryAll(ctx);

    end:;

    if (fd) fclose(fd);

    return 1;
}




//http://www.binarytides.com/get-local-ip-c-linux/
uint32_t get_local_ipv4() {
    const char* google_dns_server = "8.8.8.8";
    int dns_port = 53;
    uint32_t ret = 0;
    struct sockaddr_in serv;     
    int sock = 0;
    
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

    // lets prepare incoming ICMP processing for our traceroutes
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL) goto end;
    FilterPrepare(flt, FILTER_PACKET_ICMP, 0);
    if (Network_AddHook(ctx, flt, &Traceroute_IncomingICMP) != 1) goto end;

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
    ctx->traceroute_max_active = 50;

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
        // ***maybe create an address structuure which can hold IPv4, and 6 and uses an integer so we dont just check if ipv4 doesnt exist..
        if (address && sptr->hop_ip == address) {
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
    int total_historic_to_use = 6;
    CountElement *cptr[total_historic_to_use+1];
    
    float perc_change = 0;
    int historic_avg_increase = 0;


    if (ctx->traceroute_max_active > 10000) return 0;

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
            ctx->traceroute_max_active += 100;
        } else
        if (up < down) {
            ctx->traceroute_max_active -= 20;

        }   
        
        if (ctx->traceroute_max_active < 10) ctx->traceroute_max_active = 10;

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

    // ipv4 geoip
    ctx->geoip_handle = GeoIP_open("GeoIP.dat", GEOIP_STANDARD | GEOIP_SILENCE);
    
    // ASN? ipv4/6??
    ctx->geoip_asn_handle = GeoIP_open("GeoIPASNum.dat", GEOIP_ASNUM_EDITION_V6 | GEOIP_SILENCE);

    // ipv6 geoip
    ctx->geoipv6_handle = GeoIP_open("GeoIPv6.dat", GEOIP_STANDARD | GEOIP_SILENCE);

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
int TracerouteAddRandomIP(AS_context *ctx, char *want_country) {
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
        if (qptr->target_ip) {
            qptr->country = GEOIP_IPtoCountryID(ctx, qptr->target_ip);
            qptr->asn_num = GEOIP_IPtoASN(ctx, qptr->target_ip);
        } else {
            if (ctx->geoipv6_handle) {
                qptr->country = GeoIP_country_code_by_ipnum_v6(ctx->geoipv6_handle, qptr->target_ipv6);
                //qptr->asn_num = GEOIP_IPtoASN(ctx, qptr->target_ip);
            }
        }
    }

    if (sptr != NULL) {
        if (sptr->target_ip) {
            sptr->country = GEOIP_IPtoCountryID(ctx, sptr->target_ip);
            sptr->asn_num = GEOIP_IPtoASN(ctx, sptr->target_ip);   
        } else {
            if (ctx->geoipv6_handle) {
                sptr->country = GeoIP_country_code_by_ipnum_v6(ctx->geoipv6_handle, sptr->target_ipv6);
            }            
        }
    }
}


/*
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
TracerouteAnalysis *Traceroute_AnalysisFind(AS_context *ctx, TracerouteQueue *client, TracerouteQueue *server) {
    TracerouteAnalysis *n1 = NULL, *n2 = NULL;
    TracerouteAnalysis *tptr = ctx->analysis_list;


    while (tptr != NULL) {
        // first we find exact match
        if ((tptr->client == n1) && (tptr->server == n2)) break;
        if ((tptr->client == n2) && (tptr->server == n1)) break;

        tptr = tptr->next;
    }

    // return the full match if we found it
    if (tptr) return tptr;

    tptr = ctx->analysis_list;
    while (tptr != NULL) {
        // now we just make sure one side matches
        if ((tptr->client == n1) || (tptr->server == n1)) break;
        if ((tptr->client == n2) || (tptr->server == n2)) break;

        tptr = tptr->next;
    }

    // return the match any node query
    return tptr;
}



// create a traceroute analysis structure for storing informatiion regarding two sides of a connectioon
// to be reused, or used again
TracerouteAnalysis *Traceroute_AnalysisNew(AS_context *ctx, TracerouteQueue *client, TracerouteQueue *server) {
    TracerouteAnalysis *tptr = NULL;
    
    if ((tptr = (TracerouteAnalysis *)calloc(1, sizeof(TracerouteAnalysis))) == NULL) return NULL;

    tptr->ts = time(0);
    tptr->active_ts = 0;

    tptr->client = client;
    tptr->server = server;

    // curiousity is % of whether or not we attempt to modify IP, or search for
    // simmilar/close things by a random generatred nunmber modulated by this
    tptr->curiousity = 0;

    tptr->border_score = 0;

    // link into context list
    L_link_ordered_offset((LINK **)&ctx->analysis_list, (LINK *)tptr, offsetof(TracerouteAnalysis, next));

    return tptr;
}



// count how many attacks/connections are being used in a country..
// this will allow us to take a list of countries, and load balance between attacking their surveillance platforms
// the rest  of the system should be commpletely automated... insert targets, and walaaa
int Research_CountCountry(AS_context *ctx, int country) {
    int c = 0;
    ResearchConnectionOptions *optr = ctx->research_connections;
    
    while (optr != NULL) {
        ResearchNodeInformation *nptr = &optr->server;

        if (nptr->country == country) c++;

        optr = optr->next;
    }


    return c;
}



TracerouteAnalysis *Research_AnalysisGet(AS_context *ctx) {
    int c = L_count((LINK *)ctx->analysis_list);
    int r = rand()%c;
    int is_active = 0;
    int ts = time(0);

    TracerouteAnalysis *tptr = ctx->analysis_list;
    while (tptr && r--) { tptr = tptr->next; }

    if (tptr) {
        // ** finish timmer.. to not use active attacks (anything with 5seconds or less activity..
        // a single AS_perform() should reset this timer 0-1.5 seconds .. Max? maybe somemtimes on 
        // completing queue itll be more but that wont matter then
        //if ((ts - tptr->attackptr->ts_activity) < 5)
    }

    return tptr;
}





// *** we can expand beyond country soon.. in development
// this is for HTTP specifically right now
// ill move to another way with a call back to generate for a particular type
int Research_BuildSmartASAttack_version_1(AS_context *ctx, int country) {
    int ret = 0;
    char *content_server = NULL;
    int content_server_size = 0;
    char *content_client = NULL;
    int content_client_size = 0;
    int ts = time(0);

    TracerouteAnalysis *tptr = Research_AnalysisGet(ctx);
    ResearchConnectionOptions *optr = NULL;
    AS_attacks *aptr = NULL;

    // generate fabricated http session body for client/server... using either C, or python callback for it
    // this is one of the most important things to take place overall.. to ensure everything is different for resource exhaustion..
    // or to link speccific macros/profiles/target sites with messaging, etc for intelligence manipulation
    // the attacks will actually be taking aim at several subsystems all at once
    //if (ResearchContentGenerator(ctx, country, country, &content_server, &content_server_size, &content_client, &content_client_size) != 1) goto end;

    if ((rand()%100) < tptr->curiousity) {
        // go modify tptr for curiousity.. using anoither function.. which can also initiate new resewarch etc
    }

    // allocate space for this structure we will use to store the final information
    if ((optr = (ResearchConnectionOptions *)calloc(1, sizeof(ResearchConnectionOptions))) == NULL) goto end;

    // ensure we know we are using traceroute analysis structure by time
    tptr->ts = ts;

    // ensure it has pointers  to client content
    optr->client.content = content_client;
    optr->client.content_size = content_client_size;

    // ensure it has pointers to server content
    optr->server.content = content_server;
    optr->server.content_size = content_server_size;

    // set to 0 so we dont free later..
    optr->client.content = NULL;
    optr->client.content_size = 0;

    optr->server.content = NULL;
    optr->server.content_size = 0;

    // have somme way to configure lateer... lets use these two addresses for 1000 sessions
    optr->count = 1000;
    // timestamp
    optr->ts = ts;


    // copy address over
    GeoIP_lookup(ctx, tptr->client, NULL);
    optr->client.ip = tptr->client->target_ip;
    GeoIP_lookup(ctx, tptr->server, NULL);
    optr->server.ip = tptr->server->target_ip;

    optr->client.country = tptr->client->country;
    optr->server.country = tptr->server->country;

    optr->client.asn_num = tptr->client->asn_num;
    optr->server.asn_num = tptr->server->asn_num;

    optr->server.os_emulation_id = 0;
    optr->client.os_emulation_id = 0;

    // country is same so... score is 1..
    optr->border_score = 1;

  
    // perform a walk from both client/server and fill in hop_country
    // with each country between them
    // modify border_score using this... or use a diff border score
    // which can be used later for note below

    // optr->client has a border score as well as server..
    // they will be used later for advanced strategy..
    // so we can assure we hit the most platforms possible
    // by using particular targets in particular regions
    // thus increasing overall worldwide effect
  

    // call some functions related to this analysis structure? before/after.. finish later
    //ResearchSmartHook()

    // call http4 create with these parameters?? to generate AS_attacks structure

    // link attack structure to this connection options

    optr->attackptr = aptr;

    ret = 1;

    end:;
    return ret;
}
*/



// This will call a python function  which is meant to generate client, and server side content
int ResearchPyCallbackContentGenerator(AS_context *ctx, int language, int site_id, int site_category, char *IP_src, char *IP_dst, char *Country_src, char *Country_dst, char **client_body, int *client_body_size, char **server_body, int *server_body_size) {
    int ret = -1;
    PyObject *pArgs = NULL;
    PyObject *pIP_src = NULL, *pIP_dst = NULL;
    PyObject *pCountry_src = NULL, *pCountry_dst = NULL;
    PyObject *pBodyClient = NULL, *pBodyServer = NULL;
    PyObject *pBodyClientSize = NULL, *pBodyServerSize = NULL;
    PyObject *pSiteCategory = NULL, *pSiteID = NULL;
    PyObject *pLanguage = NULL;
    PyObject *pFunc = NULL, *pValue = NULL, *pTuple = NULL;
    AS_scripts *eptr = ctx->scripts;
    AS_scripts *sptr = ctx->scripts;
    
    char *new_client_body = NULL;
    int new_client_body_size = 0;
    char *new_server_body = NULL;
    int new_server_body_size = 0;
    char *ret_client_body = NULL;
    char *ret_server_body = NULL;

    pIP_src = PyString_FromString(IP_src);
    pIP_dst = PyString_FromString(IP_dst);
    pCountry_src = PyString_FromString(Country_src);
    pCountry_dst = PyString_FromString(Country_dst);

    // if original bodies were passed then lets use them, otherwise we use a NULL byte and size of 1
    if (*client_body) {
        pBodyClient = PyString_FromStringAndSize(*client_body, *client_body_size);
        pBodyClientSize = PyInt_FromLong(*client_body_size);
    } else {
        pBodyClient = PyString_FromStringAndSize("", 1);
        pBodyClientSize = PyInt_FromLong(1);
    }
    if (*server_body) {
        pBodyServer = PyString_FromStringAndSize(*server_body, *server_body_size);
        pBodyServerSize = PyInt_FromLong(*server_body_size);
    } else {
        pBodyServer = PyString_FromStringAndSize("", 1);
        pBodyServerSize = PyInt_FromLong(1);
    }

    pSiteID = PyInt_FromLong(site_id);
    pSiteCategory = PyInt_FromLong(site_category);
    pLanguage = PyInt_FromLong(language);


    if ((pArgs = PyTuple_New(11)) == NULL) goto end;

    //def content_generator(language,site_id,site_category,ip_src,ip_dst,ip_src_geo,ip_dst_geo,client_body,client_body_size,server_body,server_body_size):

    PyTuple_SetItem(pArgs, 0, pLanguage);
    PyTuple_SetItem(pArgs, 1, pSiteID);
    PyTuple_SetItem(pArgs, 2, pSiteCategory);
    PyTuple_SetItem(pArgs, 3, pIP_src);
    PyTuple_SetItem(pArgs, 4, pIP_src);
    PyTuple_SetItem(pArgs, 5, pCountry_src);
    PyTuple_SetItem(pArgs, 6, pCountry_dst);
    PyTuple_SetItem(pArgs, 7, pBodyClient);
    PyTuple_SetItem(pArgs, 8, pBodyClientSize);
    PyTuple_SetItem(pArgs, 9, pBodyServer);
    PyTuple_SetItem(pArgs,10, pBodyServerSize);

    // call all scripts looking for content_generator..
    // i need a new way to do callback, and checking for their functions.. ill redo scripting context system shortly
    // to support
    //while (sptr != NULL) {

    // find the script which has this function
    sptr = Scripting_FindFunction(ctx, generator_function);

    if (sptr) {

        Scripting_ThreadPre(ctx, sptr);

        pFunc = PyObject_GetAttrString(sptr->pModule, generator_function);

            // now we must verify that the function is accurate
        if (pFunc && PyCallable_Check(pFunc)) {
            // call the python function

            pValue = PyObject_CallObject(pFunc, pArgs);
        }


        if (pValue != NULL) {        
            // parse the returned 2 bodies into separate variables for processing
            // it needs to get returned as a tuple.. (body, body2)
            PyArg_ParseTuple(pValue, "s#s#", &new_client_body, &new_client_body_size, &new_server_body, &new_server_body_size);

            // allocate memeory to hold these pointers since the returned ones are inside of python memory
            if ((ret_client_body = (char *)malloc(new_client_body_size)) == NULL) goto end;
            if ((ret_server_body = (char *)malloc(new_server_body_size)) == NULL) goto end;

            // copy the data from internal python storage into the ones for the calling function
            memcpy(ret_client_body, new_client_body, new_client_body_size);
            memcpy(ret_server_body, new_server_body, new_server_body_size);

            // free passed client body if they were even passed
            if (*client_body != NULL) free(*client_body);
            if (*client_body != NULL) free(*server_body);

            *client_body = ret_client_body;
            *client_body_size = new_client_body_size;
            *server_body = ret_server_body;
            *server_body_size = new_server_body_size;

            // so we dont free these at the end of the function  (calling function gets their pointers above)
            ret_client_body = NULL;
            ret_server_body = NULL;   

            ret = 1;
        }

        Scripting_ThreadPost(ctx, sptr);
    }

    // cleanup
    end:;
    if (pValue != NULL) Py_DECREF(pValue);
    if (pFunc != NULL) Py_DECREF(pFunc);

    //if (pArgs != NULL) Py_DECREF(pArgs);

    if (pLanguage != NULL) Py_DECREF(pLanguage);
    if (pSiteCategory != NULL) Py_DECREF(pSiteCategory);
    if (pSiteID != NULL) Py_DECREF(pSiteID);
    if (pBodyServerSize != NULL) Py_DECREF(pBodyServerSize);
    if (pBodyClientSize != NULL) Py_DECREF(pBodyClientSize);
    if (pBodyServer != NULL) Py_DECREF(pBodyServer);
    if (pBodyClient != NULL) Py_DECREF(pBodyClient);
    if (pCountry_dst != NULL) Py_DECREF(pCountry_dst);
    if (pCountry_src != NULL) Py_DECREF(pCountry_src);
    if (pIP_dst != NULL) Py_DECREF(pIP_dst);
    if (pIP_src != NULL) Py_DECREF(pIP_src);
    

    if (ret_client_body != NULL) free(ret_client_body);
    if (ret_server_body != NULL) free(ret_server_body);

    return ret;
}


//int ResearchPyCallbackContentGenerator(AS_context *ctx, int language, int site_id, int site_category, char *IP_src, char *IP_dst, char *Country_src, *Country_dst, char **client_body, int *client_body_size, char **server_body, int *server_body_size);
// generate content for an upcoming connection
int ResearchContentGenerator(AS_context *ctx, int src_country, int dst_country, char **content_client, int *content_client_size, char **content_server, int *content_server_size) {
    int ret = 0;
    char *new_content_server = NULL, *new_content_client = NULL;
    int new_content_server_size = 0, new_content_client_size = 0;
    int country = GEOIP_CountryToID("US");
    int language=0;
    int site_id = 0;
    int site_category = 0;
    char *IP_src = "127.0.0.1";
    char *IP_dst = "127.0.0.1";

    // try python version from scripts (callback)    
    ret = ResearchPyCallbackContentGenerator(ctx, language, site_id, site_category, IP_src, IP_dst,
        "US", "US", content_client, content_client_size, content_server, content_server_size);

    end:;
    return ret;

}



// macros are needed to replace things like first names, usernames, emails, passwords, messages, etc.. in sessions
typedef struct _macro_variable {
    struct _macro_variable *next;

    char *macro_name;

    void *macro_ctx;
    void *function;

    // if we have some static data that we can replace it with
    // itll randomly pick an element
    char  **macro_data;
    int macro_data_count;
} MacroVariable;




// Adds a URL to a specific site for future attacks using that domain... so each can look very different
SiteURL *URL_Add(SiteIdentifier *sident, char *url) {
    SiteURL *siteptr = (SiteURL *)calloc(1, sizeof(SiteURL));

    if (siteptr == NULL) goto end;

    // lets duplicate the url
    siteptr->url = strdup(url);
    // eng static for now
    siteptr->language = 1;

    L_link_ordered_offset((LINK **)&sident->url_list, (LINK *)siteptr, offsetof(SiteURL, next));

    end:;
    return siteptr;
}

// adds a site, and  url to that site if given.. http.c should send all headers  pulled here so the information can be reused
SiteIdentifier *Site_Add(AS_context *ctx, char *site, char *url) {
    int ret = 0;
    SiteIdentifier *siteptr = ctx->site_list;
    SiteURL *uptr = NULL;

    while (siteptr != NULL) {
        if (strcmp(site, siteptr->domain)==0) {
            break;
        }
    }

    if (siteptr == NULL) {
        if ((siteptr = (SiteIdentifier *)calloc(1, sizeof(SiteIdentifier))) == NULL) return -1;
        siteptr->domain = strdup(site);
    }

    if (url) {
        if  ((uptr = URL_Add(siteptr, url)) != NULL) {
            uptr->language = siteptr->language;
        }
    }
    

    return siteptr;
}


// find generated, or loaded attack addresses by country
IPAddresses *IPAddressesbyGeo(AS_context *ctx, int country) {
    IPAddresses *iptr = ctx->ip_list;

    while (iptr != NULL) {

        if (iptr->country == country)
            break;

        iptr = iptr->next;
    }

    return iptr;
}

// obtains, and allocates if necessary an ip address structure (attack structure for a specific country)
// *** add ways to separate countries into different regions by long/latitude distances.. automated w geoip/other db
IPAddresses *IPAddressesPtr(AS_context *ctx, char *country) {
    int country_id = country ? GEOIP_CountryToID(country) : 0;
    IPAddresses *iptr = IPAddressesbyGeo(ctx, country_id);

    if (iptr == NULL) {
        // allocate space for the main structure
        if ((iptr = (IPAddresses *)calloc(1, sizeof(IPAddresses))) == NULL) return NULL;

        iptr->country = country_id;
        iptr->next = ctx->ip_list;
        ctx->ip_list = iptr;
    }

    return iptr;
    
}


int IPAddressesAddGeo(AS_context *ctx, char *country, uint32_t ip, struct in6_addr *ipv6) {
    int ret = 0;
    IPAddresses *iptr = IPAddressesPtr(ctx,country);
    uint32_t *new_ipv4 = NULL;
    struct in6_addr *new_ipv6 =  NULL;
    int i = 0;

    if (iptr == NULL) return -1;

    if (ip) {
        // ipv4

        // first lets verify the IP address doesnt already exist... these are specific lists for attacks
        // either fromm research or live packets
        for (i = 0; i < iptr->v4_count; i++)
            if (iptr->v4_addresses[i] == ip) return 0;

        if (iptr->v4_count == iptr->v4_buffer_size) {
            // need more space (increase by 5000)
            new_ipv4 = (uint32_t *)realloc(iptr->v4_addresses, sizeof(uint32_t) * (iptr->v4_count + 5000));
            if (!new_ipv4) return -1;
            iptr->v4_addresses = new_ipv4;
            iptr->v4_buffer_size += 5000;
        }

        // add ip into the list
        iptr->v4_addresses[iptr->v4_count++] = ip;
    } else {

        for (i = 0; i < iptr->v6_count; i++)
            if (CompareIPv6Addresses(&iptr->v6_addresses[i], ipv6)) return 0;

        // ipv6
        if (iptr->v6_count == iptr->v6_buffer_size) {
            // need more space (increase by 5000)
            new_ipv6 = (uint32_t *)realloc(iptr->v6_addresses, sizeof(struct in6_addr) * (iptr->v6_count + 5000));
            if (!new_ipv6) return -1;
            iptr->v6_addresses = new_ipv6;
            iptr->v6_buffer_size += 5000;
        }

        // copy ipv6 addresss into the list
        CopyIPv6Address(&iptr->v6_addresses[iptr->v6_count++], ipv6);
    }

    end:;
    return ret;
}



// generates a list of ip addresses in a particular country..
// then we can use these to traceroute to gather information, then fill in gaps
// w virtual traceroutes, and create smart attacks on fiber taps etc
IPAddresses *GenerateIPAddressesCountry_ipv4(AS_context *ctx, char *country, int count) {
    int ret = 0;
    int i = 0;
    uint32_t ip = 0;

    while (i < count) {
        ip = ResearchGenerateIPCountry(ctx, country);
        if (ip) {
            if (IPAddressesAddGeo(ctx, country, ip, NULL) == 1) {
                ret++;
            }
        }

        i++;
    }
    
    return ret;
}


struct in6_addr *IPv6SetRandom(AS_context *ctx, char *country) {
    int country_id = country ? GEOIP_CountryToID(country) : 0;
    IPAddresses *iptr = IPAddressesbyGeo(ctx, country_id);
    int r = 0;

    // make sure it exists..
    if (iptr == NULL) return NULL;

    // pick random IPv6
    r = rand()%iptr->v6_count;

    return &iptr->v6_addresses[r];
}

uint32_t IPv4SetRandom(AS_context *ctx, char *country) {
    int country_id = country ? GEOIP_CountryToID(country) : 0;
    IPAddresses *iptr = IPAddressesbyGeo(ctx, country_id);
    int r = 0;

    // make sure it exists..
    if (iptr == NULL) return NULL;

    // pick random IPv6
    r = rand()%iptr->v4_count;

    return iptr->v4_addresses[r];
}

// generating IPv6 addresses is a little more difficult than ipv4.. traceorute will help us accomplish  somme things
// other subsystems need to automatically append IPv6 addreses to a specfici list to help...
// we want all possible addresses.. then we can rev dns them, as well as grab AAAA from domains/etc (even domains found in wild without
// taking their sessions)
int GenerateIPv6Address(AS_context *ctx, char *country, struct in6_address *address) {
    int ret = 0;
    int retry = 100000;
    struct in6_addr ipv6;
    struct in6_addr doner_ipv6;
    int i = 0;
    char *sptr = (char *)&ipv6;
    char *IP = NULL;
    char *geo = NULL;
    // if we do not have any IP addresses which are ipv6 then we can initiate a traceroute here to gather some
    char google_ipv6[] = "2607:f8b0:4000:811::200e";
    int r = 0;
    int diff = 0;

    // we can use gathered ips from packet sniffing instead of static doner IPs..
    IPAddresses *iptr = IPAddressesPtr(ctx, country);


    if (iptr == NULL || !iptr->v6_count) {
        //printf("adding google\n");
        // turn ascii google ipv6 into binary prepared for network
        IP_prepare(google_ipv6, NULL, &ipv6, NULL);
        // add it as a traceroute queue
        Traceroute_Queue(ctx, 0, &ipv6);

        // return so we can try again later..
        return 0;
    }


    // pick which IP we will use randomly
    r = rand()%iptr->v6_count;

    // copy rando IPv6 from the list
    CopyIPv6Address(&doner_ipv6, &iptr->v6_addresses[r]);

    for (i = 0; i < sizeof(struct in6_addr); i++) {
        sptr[i] += -4 + (rand()%10);
    }

    /*
    sptr[0] = 32;//(rand()%6) + 32;
    sptr[1] = (rand()%20);

    for (i = 4; i < sizeof(struct in6_addr); i++) {
        if (sptr[i] == 0) {
            if (i >= 8) {                
                // most IPs ive noticed thus  far are below 200 .. so lets try those first
                //this isnt an absolute concept.. im going to obtain more IPs, ,and perform some entropy
                // cals and use those here as well... its a *little* more difficult than ipv4 but not impossible :)
                sptr[i]=(rand()%100 < 20) ? rand()%255 : rand()%190;
            } else {
                sptr[i] = rand()%255;
            }
        }
    }*/



    if (ctx->geoipv6_handle) {
        geo = GeoIP_country_code_by_ipnum_v6(ctx->geoipv6_handle, ipv6);
        if (geo != NULL) {

            // found geo we want
            if (strcmp(geo, country)==0) {
                

                IP = (char *)IP_prepare_ascii(0, &ipv6);

                if (IP != NULL) {
                    printf("1: %02x\n", (unsigned char)sptr[0]);
                    printf("geo : %s [retry %d]\n", geo, retry);
                    printf("IPv6: %s %X\n", IP, ctx->geoipv6_handle);
                    free(IP);
                }
                return 1;
            }
        }
    }
        

    if (address != NULL)
        // copy the address
        CopyIPv6Address(address, &ipv6);

    // return success
    return 1;
}





IPAddresses *GenerateIPAddressesCountry_ipv6(AS_context *ctx, char *country, int count) {
    int ret = 0;
    int i = 0;
    struct in6_addr address_ipv6;

    while (i < count) {
        // if we can generate an ipv6 adadress correctly for this country
        if (GenerateIPv6Address(ctx, country, &address_ipv6)) {
            // then add it to the list
            if (IPAddressesAddGeo(ctx, country, 0, &address_ipv6) == 1)
            //if all  was OK, then count it
                ret++;
        }

        i++;
    }
    
    return ret;
}



/*

/*

geoip6
commplete ipv6 for traceroute, and newer functioonality sinnce last weekend

imaginary/fuzzy routes

callbacks for packet incomming/outgoing

identities (getter/setter, OR synchronization w python/C)
sites (sync)
urls (sync)

*/




typedef struct _attack_targets  {
    struct _attack_targets *next;
    char *country; // for instanec, US?.. GB? (gb from US wouldd target all US->EURO fiber taps)
    int count;
    int identifier;  // categorial identifier to find connections later for specific targets to manipulate.. like a sub identifier
    int ts;          // last timestamp intelligence management affected, or used
    int language;
    IPAddresses *ip_list;
} AttackTarget;

AttackTarget *TargetRandom(AS_context *ctx) {
    AttackTarget *tptr = ctx->research_target_list;
    int c = L_count((LINK *)tptr);

    while (c-- && tptr != NULL) {
        tptr = tptr->next;
    }

    return tptr;
}

/*
Traceroute isnt as successful as I imagined at first on a mass scale.  The UDP version I believe is doing a little bettter.. Anyways.
I added prioritization for attacks which require a particular path, or target to be accurate.  The others I decided would work fine by
using fuzzy branches, or imaginary nodes.  It is the best guess at placing information, or links where they have not been proven.

onne way to link 'imaginary'routes is using information fromm tjings like maxmind  IP -> ASN

asn is another way to determine which providers are using similar backbones, and hops
*/
int Traceroute_Imaginary_Check(AS_context *ctx, TracerouteSpider *node1, TracerouteSpider *node2) {
    int ret = 0;


    end:;
    return ret;
}


TracerouteQueue *TracerouteFindQueueByIP(AS_context *ctx, uint32_t address, struct in6_addr *addressv6) {
    TracerouteQueue *qptr = ctx->traceroute_queue;

    while (qptr != NULL) {
        // ipv4
        if (address && qptr->target_ip == address) break;
        // ipv6
        if (!address && CompareIPv6Addresses(&qptr->target_ipv6, addressv6)) break;

        qptr = qptr->next;
    }

    return qptr;
}



// callback queue for traceroute.. so that will continue to next stage when it reaches this..
int Research_QueueComplete_Increase_Stage(AS_context *ctx, GenericCallbackQueue *cptr) {
    int ret = 0;

    ret = ctx->intel_stage++;

    end:;
    return ret;
}


// add IP lists fromm a target to traceroute queue.. preparing a calllback when it is completed by 75%
int Research_Traceroute_Target(AS_context *ctx, AttackTarget *tptr, int max_to_queue) {
    int ret = 0;
    int i = 0;
    int count = 0;
    TracerouteQueue *qptr = NULL;
    IPAddresses *iptr = NULL;
    int callback_id = rand()%0xFFFFFFFF;

    if (tptr == NULL) goto end;

    if ((iptr = IPAddressesbyGeo(ctx, tptr->country)) == NULL) goto end;
    

    // ipv4
    for (i = 0; i < iptr->v4_count; i++) {
        if (max_to_queue && count >= max_to_queue) break;

        qptr = TracerouteFindQueueByIP(ctx, iptr->v4_addresses[i], NULL);

        if (qptr == NULL) {
            if ((qptr = Traceroute_Queue(ctx, iptr->v4_addresses[i], NULL)) != NULL) {

                qptr->callback = &Generic_CallbackQueueCheck;
                qptr->callback_id = callback_id;
                count++;
            }
        }
    }

    // ipv6
    for (i = 0; i < iptr->v6_count; i++) {
        if (max_to_queue && count >= max_to_queue) break;

        qptr = TracerouteFindQueueByIP(ctx, NULL, &iptr->v6_addresses[i]);

        if (qptr == NULL) {
            if ((qptr = Traceroute_Queue(ctx, 0, &iptr->v6_addresses[i])) != NULL) {
                qptr->callback = &Generic_CallbackQueueCheck;
                qptr->callback_id = callback_id;
                
                count++;
            }
        }
    }

    // add a traceroute callback to continue to next stage after 75% of these are completed
    Research_AddGenericCallback(ctx, callback_id, (void *)&Research_QueueComplete_Increase_Stage, count, 75);

    ret = 1;

    end:;
    return ret;
}


// find the callback by its ID to retrieve the  information, and veri0fy whethe ro rnot its commpleted
GenericCallbackQueue *GenericCallbackByID(AS_context *ctx, int id) {
    GenericCallbackQueue *cptr = ctx->generic_callback_queue;

    while (cptr != NULL) {
        if (cptr->id == id) break;

        cptr = cptr->next;
    }

    return cptr;
}



// to call callback after traceroute is done...
//if (qptr->callback) if (qptr->callback(ctx, qptr->callback_id)) qptr->callback = NULL;

// checks if we are 75% completed during traceroute queue.. if so call the function that was left
int Generic_CallbackQueueCheck(AS_context *ctx, int callback_id) {
    int ret = 0;
    float perc = 0;
    GenericCallbackQueue *cptr = GenericCallbackByID(ctx, callback_id);

    if (cptr == NULL) return -1;


    if (cptr->done) return  0;

    cptr->completed++;

    // percent completed
    perc = (float)((float)cptr->completed / (float)cptr->count) * (float)100;

    if (perc >= cptr->min_percent) {
        ret = cptr->function(ctx, cptr);

        if (ret) cptr->done = 1;
    }

    end:;
    return ret;
}



// add a callback queue for traceroute...
int Research_AddGenericCallback(AS_context *ctx, int id, void *function, int count, int percent) {
    GenericCallbackQueue *cptr = GenericCallbackByID(ctx, id);

    // we dont wanna add the same ID...
    if (cptr != NULL) return -1;

    cptr->function = (GenericCallbackFunction)function;
    cptr->min_percent = percent;
    cptr->count = count;
    cptr->id = id;

    cptr->next = ctx->generic_callback_queue;
    ctx->generic_callback_queue = cptr;

    return 1;

}

//  Stage 1 .. begin gathering data required for attacks (sessions, internet paths, whatever)
int Research_Intelligence_Management_Stage1(AS_context *ctx) {
    int i = 0;
    int ret = -1;
    TracerouteQueue *qptr = NULL;
    // 1) generate IP addresses for a target region/country
    AttackTarget *tptr = NULL;
    IPAddresses *iptr = NULL;
    AS_attacks *aptr = NULL;
    int attack_count = 0;

    if ((tptr = TargetRandom(ctx)) == NULL) goto end;

    // 2) initiate traceroutes on those targets setting priority depending on prior dataset, and aggressive-ness
    Research_Traceroute_Target(ctx, tptr, 0);

    // --------------------------------------------------------
    /*    
        3) enable/disable local packet to www (either for python callback manipulation, or directly to real attacks)
        these www sessions can also use somme python regexp, etc to find usernames, passwords, peoples names, email addresses, etc which can populate
        those sections
    */

    // lets enable live packet capture of www... to gather sessions from live data
    ctx->http_discovery_enabled = 1;

    /*
      6) determine if an attack should  be disqualified due to overuse, etc... (it can be random, or change its parameters over time depending on location,
        virtual traceroute information,etc)
    */

    end:;
    return ret;
}


/* stage 2 */
/*
        4) if having enough raw data then it should attempt to tokenize/macro-ize the data so that the subsystem can easily replace things
        without having to call python every time.. this will increease overall output substantially commpared to having a unique body
        each time from python
*/
    // verify whether or not any captured www sessions were not already analyzed
    // to find dynamic fields such as usser identification numbers, email addresses, etc
    // which can get turned into a macro for automatic replacement and session building

/*
        5) determine if enough information for attacks exist at some interval.. if found then generate the bodies, or pass to python to gete generated..
        or modify an already queued attack structure copyingg things, and changing whats necessary
*/
 
int Research_Intelligence_Management_Stage2(AS_context *ctx) {
    int ret = 0;

    // we should have some entropy calculations from sessions BEFORE release so that it can automatically determine better sessions to use
    // from HTTP discovery... the 2hour timeout can also get modified depending on how quickly those sessions were even loaded

    // we also need to replay somme TLS sessions.. (its time to start manipulation of attacks to attack NSA decryption engines)


    end:;
    return ret;
}

int Research_Intelligence_Management_Stage3(AS_context *ctx) {
    int ret = 0;

    end:;
    return ret;
}


// The staging increases as it gets used here.. then it awaits for othe thiings (for instance for 1, traceroute queue completetion call back) to move on
int Research_Intel_Perform(AS_context *ctx) {
    int ret = 0;
    AS_attacks *aptr = NULL;
    struct timeval tv;
    struct timeval time_diff;
    gettimeofday(&tv, NULL);

    // staging skips a number in between.. this is so it wont do anything until whatever callbacks from operations complete..
    // for instance.. stage 1 begins some scans, etc.. and when 75% of them completes then it moves to stage 2
    // i might expand it further in between.. for instance it should increase +1 for traceroute completes, and also once more
    //   when it obtains enough HTTP sessions via raw socket capturing
    if (ctx->intel_stage == 0) {
        // Initiate things required for gathering data, research etc required for attacks
        ret = Research_Intelligence_Management_Stage1(ctx);
        ctx->intel_stage++; // set to 1.. 
    } else if (ctx->intel_stage == 2) {
        ret = Research_Intelligence_Management_Stage2(ctx);
        ctx->intel_stage++; // set to 3...
    } else if (ctx->intel_stage == 4) {
        ret = Research_Intelligence_Management_Stage3(ctx);
        ctx->intel_stage++; // set to 5...
    }// else if (ctx->intel_stage == 6) {}

    if (ctx->http_discovery_enabled) {
        // lets perform this at evvery stage
        aptr = ctx->attack_list;
        // disqualify old attacks to get replaced with new
        while (aptr != NULL) {
            timeval_subtract(&time_diff, &aptr->ts, &tv);

            // lets kill attacks after 2 hours..IF discovery is on!
            if (aptr->live_source && time_diff.tv_sec >= (60*60*2))
                aptr->completed = 1;

            aptr = aptr->next;
        }
    }

    end:;
    return ret;
}


// !!!
// write, and link to python for script
int Research_SyslogSend(AS_context *ctx, uint32_t ip, struct in6_addr ipv6, char *data, int size) {
    int ret = -1;

    end:;
    return ret;
}


// traceroute fill...
// If hop 6 is equal to another queues hop 6.. and its missing 2-4 or 1-5... then we can automatically
// fill because we are sure it is going through a diff hop
// obviously there are a cocuple sccenarios here that are important such as multi homed etc...
// im not sure how far ill go into those strategies, or whether its even important
// that is unless someone wanted to coordinate an attack and knew there were several multihomed 
// surveillance  nodes that they wanted to reach.. i highly doubt anyone who knows that mucch
// about the networks they wish to attack cannot just perform it themselves
// the simplest way to do this is to find another traceroute or several which has the same hop
// at the same TTL, and anything below that TTL can be assumed would be OK to fill
int Traceroute_TryFill(AS_context *ctx, TracerouteQueue *qptr) {
    int i = 0, n = 0, missing_before = 0;
    TracerouteSpider *sptr = NULL;

    // check for each TTL
    for (i = 0; i < MAX_TTL; i++) {
        // if the response is NULL.. count it
        if (qptr->responses[i] == NULL) {
            missing_before++;
        } else {
        // if BEFORE this response we had some empty(NULL) AND this one exist..
            if (missing_before && qptr->responses[i]) {
                // then lets find other queues which use the same hop (router) because anything below this TTL on their queue response is equal
                if (((sptr = Traceroute_FindByHop(ctx, qptr->responses[i]->hop_ip, NULL)) != NULL) && (sptr->queue != qptr)) {
                    // loop for all missing TTLs in our queue
                    for (n = i; n > 0; n--) {
                        // and if the other queue we found has them,
                        if (sptr->queue->responses[n] && qptr->responses[n] == NULL) {
                            // then lets copy them over...
                            qptr->responses[n] = sptr->queue->responses[n];
                        }
                    }
                }
            }
        }
    }

    return 0;
}



// loops and verifies every queue against others that have the same hops.. so it can fill some of its own gaps
// most routes like 1-5 or 6 are the same.. thats the concept behind this..
// its one of 2-3 strategies to use less analysis to get information required for an attack
int Traceroute_FillAll(AS_context *ctx) {
    TracerouteQueue *qptr = ctx->traceroute_queue;
    int ret = 0;

    while (qptr != NULL) {
        // make sure that the queue has some TTL that are incomplete otherwise its a waste of CPU cycles
        if (qptr->max_ttl)
            ret += Traceroute_TryFill(ctx, qptr);

        qptr = qptr->next;
    }

    return ret;
}



// Gather IP addresses out of all packets we see on the wire.. especially IPv6
int IPGather_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = 0;
    char *country_src = NULL, *country_dst = NULL;
    GeoIP *gi = (GeoIP *)ctx->geoip_handle;
    
    if (gi) {
        if (iptr->source_ip) {
            country_src = (char *)GeoIP_country_code_by_ipnum(gi, iptr->source_ip);
            country_dst = (char *)GeoIP_country_code_by_ipnum(gi, iptr->destination_ip);
        } else {
            if (ctx->geoipv6_handle) {
                country_src = GeoIP_country_code_by_ipnum_v6(ctx->geoipv6_handle, iptr->source_ipv6);
                country_dst = GeoIP_country_code_by_ipnum_v6(ctx->geoipv6_handle, iptr->destination_ipv6);
            }
        }
    }

    // add each IP address (whether its ipv4, or 6)
    IPAddressesAddGeo(ctx, country_src, iptr->source_ip, &iptr->source_ipv6);
    IPAddressesAddGeo(ctx, country_dst, iptr->destination_ip, &iptr->destination_ipv6);

    end:;
    return ret;
}



// we wanna capture ip addresses out of al packets we read fromm the wire (especially ipv6)
int IPGather_Init(AS_context *ctx) {
    int ret = -1;
    NetworkAnalysisFunctions *nptr = NULL;
    FilterInformation *flt = NULL;

    // lets prepare incoming ICMP processing for our traceroutes
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL)
        goto end;

    // lets filter ipv6 for now.. we can arrange this later  automatically using intelligence_management() above
    // *** we need a function to MODIFy the filter of an already existing network filter for a network subsystem dropp (incoming functions)
    FilterPrepare(flt, FILTER_PACKET_IPV6, 0);

    if (Network_AddHook(ctx, flt, &IPGather_Incoming) != 1)
        goto end;

    ret =  1;

    end:;
    return ret;
}




/*

This function is so we can find live httpp sessioons (or from pcap) and automatically macro-ize it so that portions of it gets changed.
I'm doing my best to require  zero configuration for the entire operation of attacks.  This is one of the last portions necessary.

This function needs to guess where it should tokenize for macros, or it should investigate other URLs on the same domain which it has come across.
Obviously if it has more data, or other urls to check against then it will work more efficient, and b e that  much more difficult for anyone to filter.

*/
/*

also need client body -> url variables
to match     URL variables here (GET vs POST) so that the macros can be used on both....

it should also attempt to replace any names with naming macros.. email addresses.. etc...
for example: 


*/

int URL_macroize(AS_context *ctx, SiteIdentifier *siteptr, SiteURL *urlptr) {
    int ret = 0;

    end:;
    return ret;
}



//  http parse so we can pull out URLs and macro-ize things
// ***