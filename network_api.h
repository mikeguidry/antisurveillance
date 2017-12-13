

struct _packet_instructions;
typedef struct _packet_instructions PacketBuildInstructions;


typedef struct _io_buf {
    struct _io_buf *next;
    char *buf;
    int ptr;
    int size;
    int max_size;
    PacketBuildInstructions *iptr;

    // src or dest addr...
    struct sockaddr addr;
    socklen_t addrlen;
    
} IOBuf;

#define DEF_MAX_BACKLOG 256

enum {
    SOCKET_IDLE=0,
    SOCKET_TCP_LISTEN=2048,
    SOCKET_TCP_CONNECTED=4096,
    SOCKET_ICMP=8192,
    SOCKET_UDP=16384,
    SOCKET_UDP_BOUND=32768,
    SOCKET_TCP=65536,
    SOCKET_TCP_ACCEPT=131072,
    SOCKET_TCP_CONNECTING=262144
};


typedef struct _connection_context {
    struct _connection_context *next;

    uint32_t seq;
    uint32_t remote_seq;
    uint32_t identifier;

    int ts;
    int last_ts;

    uint32_t address_ipv4;
    struct in6_addr address_ipv6;
    int is_ipv6;

    int port;
    int remote_port;

    // these go first (before IOBuf's).. contains tcp/ip protocol instructions
    PacketBuildInstructions *out_instructions;

    IOBuf *in_buf;
    IOBuf *out_buf;

    FilterInformation flt;

    int socket_fd;
    int state;
    int incoming;
    int completed;
    int noblock;
    pthread_mutex_t mutex;
} ConnectionContext;

typedef struct _socket_context {
    struct _socket_context *next;

    ConnectionContext *connections;

    int state;
    int socket_fd;
    int active;
    int port;
    int remote_port;

    uint32_t seq;
    uint32_t remote_seq;
    uint32_t identifier;

    int ttl;
    int ts;
    int last_ts;

    uint32_t address_ipv4;
    struct in6_addr address_ipv6;
    int is_ipv6;

    IOBuf *in_buf;
    IOBuf *out_buf;

    int domain;
    int type;
    int protocol;
    int noblock;

    FilterInformation flt;

    // is this socket done?
    int completed;
    pthread_mutex_t mutex;
} SocketContext;


int NetworkAPI_Incoming(AS_context *ctx, PacketBuildInstructions *iptr);
int NetworkAPI_Init(AS_context *ctx);
int NetworkAPI_Perform(AS_context *ctx);
int SocketIncoming(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr);
ConnectionContext *NetworkAPI_ConnectionByFD(AS_context *ctx, int fd);
SocketContext *NetworkAPI_SocketByFD(AS_context *ctx, int fd);
SocketContext *NetworkAPI_SocketByStatePort(AS_context *ctx, int state, int port);
int NetworkAPI_NewFD(AS_context *ctx);
SocketContext *NetworkAPI_SocketNew(AS_context *ctx);
ConnectionContext *ConnectionNew(SocketContext *sptr);
void NetworkAPI_FreeBuffers(IOBuf **ioptr);
void ConnectionsCleanup(ConnectionContext **connections);
int NetworkAPI_Cleanup(AS_context *ctx);
int NetworkAPI_Perform(AS_context *ctx);
int NetworkAPI_Incoming(AS_context *ctx, PacketBuildInstructions *iptr);
PacketBuildInstructions *BuildBasePacket(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr, int flags);
int SocketIncomingTCP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr);
int SocketIncomingUDP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr);
int SocketIncomingICMP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr);

