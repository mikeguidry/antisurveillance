

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

    struct in6_addr ipv6;

    uint32_t ip;

    int strategy;
    int interval;
    int repeat;

} BH_Queue;

void BH_Clear(AS_context *ctx) ;

int BH_add_CIDR(AS_context *ctx, int a, int b, int c, int d, int mask);
void AttackFreeStructures(AS_attacks *aptr);


int GZipAttack(AS_context *, AS_attacks *aptr, int *size, char **server_body);
void attacks_init();
int AS_session_queue(AS_context *, int id, uint32_t src, uint32_t dst, int src_port, int dst_port, int count, int interval, int depth, void *function);
int BH_Perform(AS_context *ctx);
void AttacksClear(AS_context *ctx);
int BH_add_IP(AS_context *ctx, uint32_t ip);
int BH_del_IP(AS_context *ctx, uint32_t ip);
AS_attacks *AttackFind(AS_context *ctx, int id, char *source_ip, char *destination_ip, char *any_ip, int source_port, int destination_port, int any_port, int age);