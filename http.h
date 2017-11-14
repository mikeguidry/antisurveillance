
enum {
    FROM_SERVER = 0,
    FROM_CLIENT = 1
};


typedef struct _http_extra_attack_parameters {
    // enable GZIP compression attacks?
    int gzip_attack;
    // enable it on rebuilding of sessions?
    int gzip_attack_rebuild;
    // what % of sessions should enable gzip?
    int gzip_percentage;
    // what size of each injection?
    int gzip_size;
    // what random modular do we use to determine how many different injections
    int gzip_injection_rand;

    int gzip_cache_count;
} HTTPExtraAttackParameters;




int HTTPContentModification(char *data, int size);
void *HTTP4_Create(AS_attacks *aptr);
int GZIP_Thread(AS_context *, AS_attacks *aptr, char *client_body, int client_body_size, char *server_body, int server_body_size);
void *thread_gzip_attack(void *arg);
void gzip_init(AS_context *);
int BuildHTTP4Session(AS_attacks *aptr, uint32_t server_ip, uint32_t client_ip, uint32_t server_port,  char *client_body,
    int client_size, char *server_body, int server_size);