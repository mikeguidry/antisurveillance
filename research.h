
struct _traceroute_spider;
typedef struct _traceroute_spider TracerouteSpider;


// search queue for finding paths
typedef struct _search_queue {
    struct _search_queue *next;

    TracerouteSpider *spider_ptr;
    int distance;

} SearchQueue;

// context for queue
typedef struct _search_context {
    SearchQueue *queue;

    int min_distance;
    SearchQueue *min_ptr;

    SearchQueue *max_ptr;

    int max_distance;
    int count;

} SearchContext;




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
    struct in6_addr ipv6;

    uint32_t *ipv4_list;
    struct in6_addr *ipv6_list;

    // how many responses? (different geos, etc)
    int count;
    int ts;

    DNSRecord **responses;
} DNSQueue;


// this is pretty standard...
#define MAX_TTL 30


enum {
    TRACEROUTE_ICMP,
    TRACEROUTE_UDP,
    TRACEROUTE_TCP
};

/*

Traceroute queue which is used to determine the best IPs for manipulation of fiber cables

*/

typedef int (*GenericQueueCallback)(AS_context *, int);


typedef struct _traceroute_queue {
    struct _traceroute_queue *next;
    struct _traceroute_queue *next_identifier;

    // IPv4 or 6 address
    uint32_t target_ip;
    struct in6_addr target_ipv6;
    int target_is_ipv6;

    // what type of traceroute are we performing?
    int type;

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
    uint16_t identifier;

    int country;
    int asn_num;

    int completed;

    // so we dont do too many at once.. so we can insert a huge list and let it analyze
    int enabled;

    int retry_count;

    TracerouteSpider *responses[MAX_TTL+1];

    TracerouteSpider *queue_fuzzy_list;

    // higher priorities are checked more often, and wont have a retry max
    int priority;

    // when this traceroute is completed.. do we have a calllback function we wish to use?  so it can be used in some ways?
    GenericQueueCallback callback;
    int callback_id;
} TracerouteQueue;





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

    struct _traceroute_spider *jump;

    struct _traceroute_spider *main_fuzzy_list;
    struct _traceroute_spider *queue_fuzzy_list;

    // the queue which linked into this tree
    // it wiill get removed fromm the active list to speed up the process
    // of analyzing responses... but itll stay linked here for the original
    // information for the strategies for picking targets for blackholing and sureillance attacks
    TracerouteQueue *queue;

    // time this entry was created
    int ts;

    int country;
    int asn_num;

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

    uint16_t identifier_id;
} TracerouteSpider;



// when reading the traceroute responses from the raw socket.. it should get added into this list immediately
// further information could be handled from another thread, or queue... this ensures less packet loss than
// dealing with anything inline as it comes in.. and also allows dumping the data to a save file
// for the spider in the future to pick & choose mass surveillance platforms
typedef struct _traceroute_response {
    struct _traceroute_response *next;

    // to know where the packet relates to
    uint16_t identifier;

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
TracerouteQueue *Traceroute_Queue(AS_context *ctx, uint32_t target, struct in6_addr *targetv6);
int Traceroute_Count(AS_context *ctx, int, int);
int Spider_Print(AS_context *ctx);

int Traceroute_Search(AS_context *, SearchContext *, TracerouteSpider *start, TracerouteSpider *looking_for, int distance, int);
int Traceroute_Compare(AS_context *ctx, TracerouteSpider *first, TracerouteSpider *second, int);
int Spider_Load(AS_context *ctx, char *filename);
TracerouteSpider *Traceroute_FindByIdentifierTTL(AS_context *ctx, uint32_t id, int ttl);
TracerouteSpider *Traceroute_FindByHop(AS_context *ctx, uint32_t hop_ipv4, struct in6_addr *hop_ipv6);
TracerouteSpider *Traceroute_FindByTarget(AS_context *ctx, uint32_t target_ipv4, struct in6_addr *target_ipv6);
int Traceroute_RetryAll(AS_context *ctx);
void Traceroute_Watchdog_Add(AS_context *ctx);
int Traceroute_Watchdog(AS_context *ctx);
int Traceroute_AdjustActiveCount(AS_context *ctx);
TracerouteSpider *Spider_Find(AS_context *ctx, uint32_t hop, struct in6_addr *hopv6);
int Traceroute_Insert(AS_context *ctx, TracerouteSpider *snew);

int TracerouteQueueFindByIdentifier(AS_context *ctx, uint16_t identifier);
int TracerouteResetRetryCount(AS_context *ctx);

int Research_Init(AS_context *ctx);
int GEOIP_CountryToID(char *country);
int GEOIP_IPtoCountryID(AS_context *ctx, uint32_t addr);
uint32_t ResearchGenerateIPCountry(AS_context *ctx, char *want_country);
int TracerouteAddRandomIP(AS_context *ctx, char *want_country);
int GEOIP_IPtoASN(AS_context *ctx, uint32_t addr);
void GeoIP_lookup(AS_context *ctx, TracerouteQueue *qptr, TracerouteSpider *sptr);


// we list all chosen client/server here for use in attack lists
typedef struct _research_connection_options {
    struct _research_connection_options *next;

    TracerouteQueue *client;
    char *client_content;
    int client_content_size;

    TracerouteQueue *server;
    char  *server_content;
    int server_content_size;

    // attack structure for these options
    AS_attacks *attackptr;

    // did we use fuzzy data to build relationship?
    int imaginary;

    int site_id;
    int site_category;
    int client_os;
    int server_os;

    
    // list of all countries we pass through between these two clients
    int hop_country[MAX_TTL];
    // access to the hops directly for further info
    // this is a 'virtual traceroute' from one host to another
    TracerouteSpider *hops[MAX_TTL];

    // score between client, and server (should be low)
    int border_score;

    // how many times can we reuse?
    int count;

    // timestamp created
    int ts;

    // last timestamp used
    int last_ts;
} ResearchConnectionOptions;



// All logged/loaded URLs (from live, pcap, or built in)
typedef struct _site_url {
    struct _site_url *next;

    // how many times used?
    int count;
    // language for this url/content
    int language;
    // ajax? etc? it can determine things for % of gzip attack.. ajaxx = small
    char *url;

    // does this URL wannaa use a specific body we can modify/insert?
    char *content;
    int content_size;
} SiteURL;

// site specifics
typedef struct _site_identifiers {
    struct _site_identifiers *next;

    // what language?
    int language;

    // which category ID?
    int category_id;

    // domain/site
    char *domain;

    // URLs (macro-able) for building sessions...
    SiteURL *url_list;
    int url_count;    
} SiteIdentifier;

// site categories
typedef struct _site_categories {
    struct _site_categories *next;

    // category ID for this site
    int category_id;

    // language (redundant.. since site identifiers has language.. maybe remove)
    int language;

    // category name
    char *name;
} SiteCategories;

// languages
typedef struct _languages {
    struct _languages *next;

    int language_id;
    char *name;

    // IE: chinese
    int requires_unicode;
} Languages;


// pool for picking ip addresses..
typedef struct _ip_addresses {
    struct _ip_addresses *next;

    // easy geo?
    int country;

    // what language? (if a country has multiple.. u can decide to change?)
    int language;

    // time is for frabricating messages between  parties to emulate 9am-5pm or afternoon...
    // real as possible is best.
    int time_restrictions;

    uint32_t *v4_addresses;
    int v4_count;
    int v4_buffer_size;

    struct in6_addr *v6_addresses;
    int v6_count;  
    int v6_buffer_size;

    // so we have easy access to all traceroutes relating to these IP addresses
    // *** maybe dont need?
    TracerouteQueue *ip_traces;  
} IPAddresses;





int fourteen_check_id(int country_id);
int fourteen_check(char *country);
int TracerouteQueueFindByIP(AS_context *ctx, uint32_t ipv4);
int testcallback(AS_context *ctx);
int Spider_Load_threaded(AS_context *ctx, char *filename);
SiteIdentifier *Site_Add(AS_context *ctx, char *site, char *url);
SiteURL *URL_Add(SiteIdentifier *sident, char *url);

IPAddresses *GenerateIPAddressesCountry_ipv4(AS_context *ctx, char *country, int count);
IPAddresses *GenerateIPAddressesCountry_ipv6(AS_context *ctx, char *country, int count);



typedef int (*GenericCallbackFunction)(AS_context *, GenericCallbackQueue *);

// this structure will have a count of how many traceroutes we are waiting  to finish...
// once they are all done (or a % like 70%?) it will finally call a callback..
// in this case it will force research management to go to the next stage for attacks..
typedef struct _traceroute_callback_queue {
    struct _traceroute_calllback_queue *next;

    int id;
    // we set this to how many we are awaiting to finish..
    int count;

    int completed;

    // minimum percent required before we callback?
    int min_percent;


    int done;

    // smoe way to identify this queue when we call the function? 
    GenericCallbackFunction function;
} GenericCallbackQueue;

int Generic_CallbackQueueCheck(AS_context *ctx, int);
int Traceroute_FillAll(AS_context *ctx);