
struct _traceroute_spider;
typedef struct _traceroute_spider TracerouteSpider;



// one single dns record (response about a hostname, prepared to stay on record)
// it can be reused for preparing further attacks against the same sites, etc
// using different residential, or business ip addresses
typedef struct _dns_record {
    struct _dns_record *next;
    // raw response..
    unsigned char *response;
    int response_size;

    unsigned char type; // enums from before

    uint32_t ipv4;
    //struct in6_addr ipv6;

    // ts of last lookup
    int ts;

    // this is necessary for different strageies which will be developed
    int country_id;
} DNSRecord;


typedef struct _lookup_queue {
    struct _lookup_queue *next;

    // MX/ PTR/ A/ AAAA/ etc
    int type;

    char *hostname;

    // spider would be for using different dns servers in different geos
    // it allows using geo ips which look more legit
    // one of the first responses to these attacks will be to filter the attacks out
    // using scenarios like this...
    struct _lookup_queue *spider;
    struct _lookup_queue *recursive;

    // is this queue complete? (it wouuld mean that all recursive/spider are completed as well)
    int complete;

    uint32_t ipv4;
    //struct in6_addr ipv6;

    // how many responses? (different geos, etc)
    int count;
    int ts;

    DNSRecord **responses;
} DNSQueue;


// this is pretty standard...
#define MAX_TTL 30

/*

Traceroute queue which is used to determine the best IPs for manipulation of fiber cables

*/
typedef struct _traceroute_queue {
    struct _traceroute_queue *next;

    // IPv4 or 6 address
    uint32_t target_ip;
    struct in6_addr target_ipv6;
    int target_is_ipv6;

    //timestamp added
    int ts;

    // last time we noticed activity.. for timeouts, and next ttl
    int ts_activity;

    // ttl (starts at 1 and goes up)
    int current_ttl;
    int max_ttl;
    int sent_ttl;

    int current_retry;

    int ttl_list[MAX_TTL+1];

    // identifier to tie this to the responses since we will perform mass amounts
    uint32_t identifier;

    int country;

    int completed;

    // so we dont do too many at once.. so we can insert a huge list and let it analyze
    int enabled;

    int retry_count;

    TracerouteSpider *responses[MAX_TTL+1];
} TracerouteQueue;


// a way to stop recursion/inf loops while searching
typedef struct _search_context {
    TracerouteSpider *first;
    TracerouteSpider *second;
    int seen;
} SearchContext;

// this linked list is for the final data w traceroute responses
// it has to link next as a regular way to contain the data
// branches is the same routers/hops together...
// and identifier is to link all of a targets traceroute nodes together
// all 3 are required to perform the correct analysis, and attack building 
typedef struct _traceroute_spider {
    //routine linked list management..
    struct _traceroute_spider *next;

    // branches is like next but for all branches (this hop matches anothers)
    struct _traceroute_spider *branches;

    // identifier wil link the entire traceroute for a particular target together
    // regardless of branch, or hops.. purely by the value we used to identify the packet
    // and TTL
    //struct _traceroute_spider *identifiers;

    // all same hops end up linked to the first one in the list
    struct _traceroute_spider *hops_list;

    // the queue which linked into this tree
    // it wiill get removed fromm the active list to speed up the process
    // of analyzing responses... but itll stay linked here for the original
    // information for the strategies for picking targets for blackholing and sureillance attacks
    TracerouteQueue *queue;

    // time this entry was created
    int ts;

    int country;

    // quick reference of IP (of the router.. / hop / gateway)
    uint32_t hop_ip;
    struct in6_addr hop_ipv6;
    int hop_is_ipv6;

    // what was being tracerouted to conclude this entry
    uint32_t target_ip;
    struct in6_addr target_ipv6;
    int target_is_ipv6;

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

    uint32_t identifier_id;

    SearchContext search_context;
} TracerouteSpider;



// when reading the traceroute responses from the raw socket.. it should get added into this list immediately
// further information could be handled from another thread, or queue... this ensures less packet loss than
// dealing with anything inline as it comes in.. and also allows dumping the data to a save file
// for the spider in the future to pick & choose mass surveillance platforms
typedef struct _traceroute_response {
    struct _traceroute_response *next;

    // to know where the packet relates to
    uint32_t identifier;

    // what ttl was this hop?
    int ttl;

    // the hop which responded
    uint32_t hop_ip;
    struct in6_addr hop_ipv6;
    int hop_is_ipv6;

    // what was the target fromm the original queue
    uint32_t target_ip;
    struct in6_addr target_ipv6;
    int target_is_ipv6;
} TracerouteResponse;



// *** later we either wanna encrypt this, or hide it in regular traceroute type packets (read traceroute sources)
typedef struct _traceroute_data {
    char msg[32];
    uint32_t identifier;
    int ttl;
} TraceroutePacketData;


int Traceroute_Perform(AS_context *ctx);
int Traceroute_Incoming(AS_context *ctx, PacketBuildInstructions *iptr);
void get_local_ipv6(struct in6_addr *dst);
uint32_t get_local_ipv4();
int Traceroute_Init(AS_context *ctx);
int Traceroute_Queue(AS_context *ctx, uint32_t target, struct in6_addr *targetv6);
int Traceroute_Count(AS_context *ctx, int, int);
int Spider_Print(AS_context *ctx);

int Traceroute_Search(AS_context *, TracerouteSpider *start, TracerouteSpider *looking_for, int distance);
int Traceroute_Compare(AS_context *ctx, TracerouteSpider *first, TracerouteSpider *second);
int Spider_Load(AS_context *ctx, char *filename);
TracerouteSpider *Traceroute_FindByIdentifier(AS_context *ctx, uint32_t id, int ttl);
TracerouteSpider *Traceroute_FindByHop(AS_context *ctx, uint32_t hop_ipv4, struct in6_addr *hop_ipv6);
TracerouteSpider *Traceroute_FindByTarget(AS_context *ctx, uint32_t target_ipv4, struct in6_addr *target_ipv6);
int Traceroute_RetryAll(AS_context *ctx);
void Traceroute_Watchdog_Add(AS_context *ctx);
int Traceroute_Watchdog(AS_context *ctx);
int Traceroute_AdjustActiveCount(AS_context *ctx);
TracerouteSpider *Spider_Find(AS_context *ctx, uint32_t hop, struct in6_addr *hopv6);
int Traceroute_Insert(AS_context *ctx, TracerouteSpider *snew);

int TracerouteQueueFindByIdentifier(AS_context *ctx, uint32_t identifier);
int TracerouteResetRetryCount(AS_context *ctx);

int Research_Init(AS_context *ctx);
int GEOIP_CountryToID(char *country);
int GEOIP_IPtoCountryID(AS_context *ctx, uint32_t addr);
uint32_t ResearchGenerateIPCountry(AS_context *ctx, char *want_country);
int TracerouteAddCountryIP(AS_context *ctx, char *want_country);