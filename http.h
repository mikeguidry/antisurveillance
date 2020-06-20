
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

#define HTTP_BUFFER 1024*1024*1
#define HTTP_DISCOVER_TIMEOUT 10


typedef struct _http_buffer {
    struct _http_buffer *next;

    uint32_t source_ip;
    uint32_t destination_ip;
    struct in6_addr source_ipv6;
    struct in6_addr destination_ipv6;

    unsigned short source_port;
    unsigned short destination_port;

    // did we see the end of the  connection?
    int complete;

    // processed.. waiting on cleanup (free, etc)
    int processed;
    PacketBuildInstructions *packet_list;

    int size;
    int ts;
} HTTPBuffer;


int HTTPContentModification(AS_attacks *);
void *HTTP4_Create(AS_attacks *aptr);
int GZIP_Thread(AS_context *, AS_attacks *aptr, char *client_body, int client_body_size, char *server_body, int server_body_size);
void *thread_gzip_attack(void *arg);
void attacks_init(AS_context *);
int BuildHTTP4Session(AS_context *, AS_attacks *aptr, uint32_t server_ip, uint32_t client_ip, uint32_t server_port,  char *client_body,
int client_size, char *server_body, int server_size);
int WebDiscover_Init(AS_context *ctx);
int WebDiscover_Incoming(AS_context *ctx, PacketBuildInstructions *iptr);
char *ConnectionData(PacketBuildInstructions *iptr, int side, int *_size);
int WebDiscover_Cleanup(AS_context *ctx);


typedef struct _http_observed_variables {
    struct _http_observed_variables *next;

    // ttl and window size for the packets (to emulate whatever OS it was)
    int ttl;
    int window_size;

    // if it has a user agent we assume client
    char *useragent;
    int user_agent_size;

    // if it has a http header for server side then we assume server
    char *server_version;
    int server_version_size;

    int count;

    char *tcp_options;
    int tcp_options_size;

    // once we parse the options once.. lets keep the timestampp offset so we can easily replace it next iteration
    int tcp_timestamp_offset;
} HTTPObservedVariables;


HTTPObservedVariables *ObserveAdd(AS_context *ctx, int ttl, int window_size);
HTTPObservedVariables *ObserveCheck(AS_context *ctx, int ttl, int window_size);
HTTPObservedVariables *ObserveGet(AS_context *ctx, int from_client);
int SSL_Modifications(AS_context *ctx, PacketBuildInstructions *iptr);
int WebDiscover_Perform(AS_context *ctx);