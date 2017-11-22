
struct _as_attacks;
typedef struct _as_attacks AS_attacks;

struct _pkt_info;
typedef struct _pkt_info PacketInfo;

struct _antisurveillance_context;
typedef struct _antisurveillance_context AS_context;


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
} AttackOutgoingQueue;

typedef struct _incoming_packet_queue {
    struct _incoming_packet_queue *next;

    

} IncomingPacketQueue;

int prepare_socket();
void *thread_network_flush(void *arg);
int AS_queue(AS_context *ctx, AS_attacks *attack, PacketInfo *qptr);
void *AS_queue_threaded(void *arg);
int AttackQueueAdd(AS_context *,AttackOutgoingQueue *optr, int only_try);
int FlushAttackOutgoingQueueToNetwork(AS_context *);
void ClearPackets(AS_context *ctx);