#include <pthread.h>
#include <stdint.h>

struct _packet_info;
struct _tcp_packet_instructions;
//typedef struct _packet_info PacketInfo;

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
    uint32_t source_port;
    uint32_t destination_port;

    // state / id of current packet
    int send_state;
    int recv_state;

    // instructions for building raw packets..
    struct _tcp_packet_instructions *packet_build_instructions;

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
} AS_attacks;


// this is a linked list so we can possible keep conectoin open over long periods of time pushing packet as needed... 
typedef struct _connection_properties {
	struct _connection_properties *next;

	AS_attacks *aptr;
	uint32_t server_ip;
	uint32_t client_ip;
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



typedef void *(*attack_func)(AS_attacks *aptr);



void AS_remove_completed();



