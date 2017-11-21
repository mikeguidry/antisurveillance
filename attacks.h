

// details required for the new thread to understand its current parameters
typedef struct _gzip_thread_details {
    AS_context *ctx;
    AS_attacks *aptr;
    char *client_body;
    int client_body_size;
    char *server_body;
    int server_body_size;
} GZIPDetails;



//CIDR of ranges we wish to destroy
typedef struct _bh_queue {
    struct _bh_queue *next;

    int a;
    int b;
    int c;
    int d;
    int netmask;

    int strategy;
    int interval;
    int repeat;

} BH_Queue;


int BH_add_CIDR(AS_context *ctx, int a, int b, int c, int d, int mask);
void AttackFreeStructures(AS_attacks *aptr);


int GZipAttack(AS_context *, AS_attacks *aptr, int *size, char **server_body);
void attacks_init();
int AS_session_queue(AS_context *, int id, uint32_t src, uint32_t dst, int src_port, int dst_port, int count, int interval, int depth, void *function);
int BH_Perform(AS_context *ctx);