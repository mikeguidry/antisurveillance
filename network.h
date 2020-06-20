


struct _as_attacks;
typedef struct _as_attacks AS_attacks;

struct _pkt_info;
typedef struct _pkt_info PacketInfo;

struct _antisurveillance_context;
typedef struct _antisurveillance_context AS_context;

struct _packet_instructions;
typedef struct _packet_instructions PacketBuildInstructions;

struct _filter_information;
typedef struct _filter_information FilterInformation;


typedef struct OutgoingPacketInformation {
        char *buf;
        int size;
        int protocol;
        int ipversion;
        uint16_t dest_port;
        uint16_t source_port;
        uint32_t dest_ip;
        struct in6_addr dest_ipv6;
        AS_attacks *attack_info;
} OutgoingPacketInformation;


// this is the queue which shouldnt have anything to do with processing, or other functions.. its where
// all attacks go to get submitted directly to the wire.. 
typedef struct _outgoing_packet_queue {
    struct _outgoing_packet_queue *next;

    AS_context *ctx;

    pthread_t thread;
    int ignore;
    int failed;


    char *buf;
    int max_buf_size;
    int max_packets;

    OutgoingPacketInformation *packets;
    AS_attacks **attack_info;

    int cur_packet;
    int size;

    // so we can filter our own packets if we wish
    int ts;
} OutgoingPacketQueue;

typedef struct IncomingPacketInformation {
        char *buf;
        int size;
        int protocol;
        int ipversion;
} IncomingPacketInformation;


// linked list of incoming packets being read for processing
typedef struct _incoming_packet_queue {
    struct _incoming_packet_queue *next;

    char *buf;
    int max_buf_size;
    int max_packets;

    IncomingPacketInformation *packets;
    int cur_packet;
    int size;
} IncomingPacketQueue;

struct _packet_instructions;
typedef struct _packet_instructions PacketBuildInstructions;

typedef int (*PacketIncomingFunc)(AS_context *, PacketBuildInstructions *iptr);

// all packets being read off of the wire   will go through these functions to get delivered to wherever they belong
// traceroute for instance will have a filter which if passes then its function will obtain the packets
typedef struct _network_analysis_functions {
    struct _network_analysis_functions *next;

    // this has to be a pointer how we are declaring...
    // wont matter later after header cleanup
    FilterInformation *flt;

    PacketIncomingFunc incoming_function;

    long long bytes_processed;
} NetworkAnalysisFunctions;


void *thread_network_flush(void *arg);
int AS_queue(AS_context *ctx, AS_attacks *attack, PacketInfo *qptr);
void *AS_queue_threaded(void *arg);
int FlushOutgoingQueueToNetwork(AS_context *ctx, OutgoingPacketQueue *optr);
void ClearPackets(AS_context *ctx);
int process_packet(AS_context *ctx, char *packet, int size);
void *thread_read_network(void *arg);
int Network_AddHook(AS_context *ctx, FilterInformation *flt, void *incoming_function);
int NetworkQueueInstructions(AS_context *ctx, PacketBuildInstructions *iptr, OutgoingPacketQueue **_optr);
int NetworkAllocateReadPools(AS_context *ctx);
int NetworkAllocateWritePools(AS_context *ctx);
void OutgoingQueueLink(AS_context *ctx, OutgoingPacketQueue *optr);
int prepare_read_sockets(AS_context *ctx);
int prepare_write_sockets(AS_context *ctx);
int network_read_loop(AS_context *ctx);
int network_process_incoming_buffer(AS_context *ctx);


enum {
    IPVER_4,
    IPVER_6
};

enum {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP
};


int OutgoingQueueProcess(AS_context *ctx);