#include <pthread.h>
#include <stdint.h>
#include <Python.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include "GeoIP.h"

struct _packet_info;
struct _packet_instructions;
//typedef struct _packet_info PacketInfo;
struct _bh_queue;
typedef struct _bh_queue BH_Queue;

struct _traceroute_queue;
typedef struct _traceroute_queue TracerouteQueue;

struct _as_scripts;
typedef struct _as_scripts AS_scripts;

struct _traceroute_spider;
typedef struct _traceroute_spider TracerouteSpider;

struct _traceroute_response;
typedef struct _traceroute_response TracerouteResponse;

struct _network_analysis_functions;
typedef struct _network_analysis_functions NetworkAnalysisFunctions;

struct ifreq;

struct _research_connection_options;
typedef struct _research_connection_options ResearchConnectionOptions;

typedef struct _traceroute_analysis;
typedef struct _traceroute_analysis TracerouteAnalysis;

struct _pcap_operations;
typedef struct _pcap_operations PCAPOperation;


// general attack structure...
// should support everything from syn packets, to virtual connections
typedef struct _as_attacks {
    struct _as_attacks *next;

    int id;

    // what kind of attack is this? syn only? spoofed full sessions..
    int type;

    // src / dest matters only if the box is expectinng to be handled on both sides of the tap
    // if its 0 then it will go along with the packet structures
    uint32_t src;
    uint32_t dst;

    struct in6_addr src6;
    struct in6_addr dst6;

    uint32_t source_port;
    uint32_t destination_port;

    // state / id of current packet
    int send_state;
    int recv_state;

    // instructions for building raw packets..
    struct _packet_instructions *packet_build_instructions;

    uint32_t client_base_seq;
    uint32_t server_base_seq;

    // actual built packets ready for going out
    struct _pkt_info *packets;
    struct _pkt_info *current_packet;

    
    // is this queue paused for some reason? (other thread working on it)
    int paused;
    int join;
    pthread_mutex_t pause_mutex;// : PTHREAD_MUTEX_INITIALIZER;

    
    pthread_t thread;

    // do we repeat this attack again whenever its completed?
    int count;
    int repeat_interval;
    struct timeval ts;

    // if it has a count>0 then completed would get set whenever
    int completed;

    // function which sets up the attack
    // such as building packets (pushing to queue will done by a 'main loop' function)
    //attack_func function;
    void *function;

    // lets hold information for all connections locally, and easily for use in packet building functions..
    // this will also allow easily expanding to do DNS, and other subsequent attacks to perform more like real clients
    // before submitting falsified web queries.. they aint ready
    //VirtualConnection *connections;

    // this should contain extra attacks...
    // when the gzip code became ready.. i decided I needed more parameters
    // than general.. to enable gzip and decide what % of packets it would inject into
    // also the option to pthread off the gzip to another thread, or process (using sockets)
    void *extra_attack_parameters;

    AS_context *ctx;

    // we dont apply adjustments to this packet
    int skip_adjustments;
} AS_attacks;


// this is a linked list so we can possible keep conectoin open over long periods of time pushing packet as needed... 
typedef struct _connection_properties {
	struct _connection_properties *next;

	AS_attacks *aptr;
    // IPv4
	uint32_t server_ip;
	uint32_t client_ip;
    // IPv6
    struct in6_addr server_ipv6;
    struct in6_addr client_ipv6;

    int is_ipv6;
    
	uint32_t server_port;
	uint32_t client_port;
	uint32_t server_identifier;
	uint32_t client_identifier;
	uint32_t server_seq;
    uint32_t client_seq;
    
    struct timeval ts;
    
    int client_ttl;
    int server_ttl;

    int max_packet_size_client;
    int max_packet_size_server;
    
    int client_emulated_operating_system;
    int server_emulated_operating_system;
} ConnectionProperties;



typedef struct _count_element {
    int count;
    int ts;
    int max_setting;
} CountElement;


// for dynamically modifying our speed to help progress for diff times of day (local, or world traffic)
typedef struct _perform_history {
    CountElement HistoricDataRaw[1024*10];
    CountElement HistoricDataCalculated[1024*10];
    int HistoricRawCurrent;
    int HistoricCurrent;
} TraceroutePerformaceHistory;


// lets contain all 'global' variables inside of a context structure
// this will allow compiling as a library and including in other applications
typedef struct _antisurveillance_context {
    // start time
    int start_ts;

    // socket for writing to the ethernet device
    int raw_socket;

    // promisc read socket for incoming packet events
    int read_socket;

    // list of attacks
    AS_attacks *attack_list;

    // global parameters being used (http client/server body)
    char *G_client_body;
    char *G_server_body;
    int G_client_body_size;
    int G_server_body_size;

    // GZIP attack parameters
    int total_gzip_count;
    char *gzip_cache;
    int gzip_cache_size;
    int gzip_initialized;
    int gzip_cache_count;

    pthread_mutex_t gzip_cache_mutex;

    // network queue
    AttackOutgoingQueue *network_queue;
    AttackOutgoingQueue *network_queue_last;
    pthread_mutex_t network_queue_mutex;
    pthread_t network_write_thread;
    pthread_mutex_t network_incoming_mutex;
    pthread_t network_read_thread;
    int network_write_threaded;
    int network_read_threaded;

    IncomingPacketQueue *incoming_queue;
    IncomingPacketQueue *incoming_queue_last;

    int aggressive;

    BH_Queue *blackhole_queue;
    int blackhole_paused;

    AS_scripts *scripts;

    // paused operations *all*
    int paused;
    // disable writing to disk (to queue for pcap save)
    int network_disabled;

    // instead of exiting.. continue executing calling script_perform() every iteration
    int script_enable;

    NetworkAnalysisFunctions *IncomingPacketFunctions;

    uint32_t my_addr_ipv4;
    struct in6_addr my_addr_ipv6;

    struct ifreq if_mac;


    // active traceroutes
    TracerouteQueue *traceroute_queue;
    // internal database built from the traceroutes, and analysis
    TracerouteSpider *traceroute_spider;
    //void *jump_table[256*256*256];
    TracerouteSpider *traceroute_spider_hops;
    // responses coming from the network to get analyzed & put into the spiderweb
    TracerouteResponse *traceroute_responses;
    TracerouteAnalysis *analysis_list;

    ResearchConnectionOptions *research_connections;
    int traceroute_max_retry;
    // if we are doing a lot of lookups.. we can start at higher TTL
    int traceroute_min_ttl;
    int traceroute_max_active;
    TraceroutePerformaceHistory Traceroute_Traffic_Watchdog;
    int watchdog_ts;

    GeoIP *geoip_handle;
    GeoIP *geoip_asn_handle;

    PCAPOperation *pcap_operations;

    pthread_mutex_t traceroute_mutex;
    pthread_t traceroute_thread;

} AS_context;



typedef void *(*attack_func)(AS_attacks *aptr);
void AS_remove_completed(AS_context *);
void AS_Clear_All(AS_context *ctx);
int Subsystems_Perform(AS_context *);


AS_context *Antisurveillance_Init();
int Test_Generate(AS_context *ctx, int argc, char *argv[]);
int Test_PCAP(AS_context *ctx, char *filename);
int Threads_Start(AS_context *);