
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


// this is the queue which shouldnt have anything to do with processing, or other functions.. its where
// all attacks go to get submitted directly to the wire.. 
typedef struct _attack_outgoing_queue {
    struct _attack_outgoing_queue *next;

    AS_attacks *attack_info;

    char *buf;
    int size;

    uint32_t dest_ip;
    uint16_t dest_port;
    

    pthread_t thread;

    AS_context *ctx;
#ifdef TESTING_DONT_FREE_OUTGOING
    int submitted;
#endif

    int ignore;

    int failed;

    int type;
} AttackOutgoingQueue;


#define MAX_BUF_SIZE 1024*1024*5
#define MAX_PACKETS 10000

// linked list of incoming packets being read for processing
typedef struct _incoming_packet_queue {
    struct _incoming_packet_queue *next;

    char buf[MAX_BUF_SIZE];
    int max_buf_size;
    int packet_starts[MAX_PACKETS];
    int packet_ends[MAX_PACKETS];
    int cur_packet;
    int size;
} IncomingPacketQueue;

typedef int (*PacketIncomingFunc)(AS_context *, PacketBuildInstructions *iptr);

// all packets being read off of the wire will go through these functions to get delivered to wherever they belong
// traceroute for instance will have a filter which if passes then its function will obtain the packets
typedef struct _network_analysis_functions {
    struct _network_analysis_functions *next;

    // this has to be a pointer how we are declaring...
    // wont matter later after header cleanup
    FilterInformation *flt;

    PacketIncomingFunc incoming_function;

    long long bytes_processed;
} NetworkAnalysisFunctions;


int prepare_socket();
void *thread_network_flush(void *arg);
int AS_queue(AS_context *ctx, AS_attacks *attack, PacketInfo *qptr);
void *AS_queue_threaded(void *arg);
int OutgoingQueueAdd(AS_context *,AttackOutgoingQueue *optr, int only_try);
int FlushAttackOutgoingQueueToNetwork(AS_context *ctx, AttackOutgoingQueue *optr);
void ClearPackets(AS_context *ctx);
int process_packet(AS_context *ctx, char *packet, int size);
void *thread_read_network(void *arg);
int Network_AddHook(AS_context *ctx, FilterInformation *flt, void *incoming_function);
int NetworkQueueAddBest(AS_context *ctx, PacketBuildInstructions *iptr, int);