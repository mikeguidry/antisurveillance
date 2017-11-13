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

} AttackOutgoingQueue;


int prepare_socket();
void *thread_network_flush(void *arg);
int AS_queue(AS_attacks *attack, PacketInfo *qptr);
void *AS_queue_threaded(void *arg);
int AttackQueueAdd(AttackOutgoingQueue *optr, int only_try);
int FlushAttackOutgoingQueueToNetwork();