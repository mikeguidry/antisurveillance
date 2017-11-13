

// details required for the new thread to understand its current parameters
typedef struct _gzip_thread_details {
    AS_attacks *aptr;
    char *client_body;
    int client_body_size;
    char *server_body;
    int server_body_size;
} GZIPDetails;

void AttackFreeStructures(AS_attacks *aptr);


int GZipAttack(AS_attacks *aptr, int *size, char **server_body);
void gzip_init();
int AS_session_queue(int id, uint32_t src, uint32_t dst, int src_port, int dst_port, int count, int interval, int depth, void *function);

