

struct _packet_instructions;
typedef struct _packet_instructions PacketBuildInstructions;


typedef struct _io_buf {
    struct _io_buf *next;
    char *buf;
    int ptr;
    int size;
    int max_size;
    PacketBuildInstructions *iptr;

    // transmission time.. so we can retransmit if it doesnt get an ACK
    int transmit_ts;
    // and the sequence of it (so we can verify against the ACK)
    // and SACK perm code.. seq tells us if we have the packet already
    uint32_t seq;

    // did we verify it? (means its done and we can free)
    int verified;

    int retry;

    // src or dest addr...
    struct sockaddr_in addr;
    struct sockaddr_in6 addr_ipv6;
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
    SOCKET_TCP_CONNECTING=262144,
    SOCKET_TCP_CLOSING=524288
};


struct _socket_context;
typedef struct _socket_context SocketContext;


typedef struct _connection_context {
    struct _connection_context *next;

    uint32_t seq;
    uint32_t remote_seq;
    uint32_t identifier;

    int ts;
    int last_ts;

    uint32_t address_ipv4;
    struct in6_addr address_ipv6;

    uint32_t our_ipv4;
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

    SocketContext *socket;

    // mutex is for whenever apps are performing BLOCKING actions like connect()..
    // go figure.. non blocking is actually EASIER to support...
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

    int window_size;
    int ttl;
    int ts;
    int last_ts;

    uint32_t address_ipv4;
    struct in6_addr address_ipv6;

    uint32_t our_ipv4;
    struct in6_addr our_ipv6;
    
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
int NetworkAPI_SocketIncoming(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr);
ConnectionContext *NetworkAPI_ConnectionByFD(AS_context *ctx, int fd);
SocketContext *NetworkAPI_SocketByFD(AS_context *ctx, int fd);
SocketContext *NetworkAPI_SocketByStatePort(AS_context *ctx, int state, int port);
int NetworkAPI_NewFD(AS_context *ctx);
SocketContext *NetworkAPI_SocketNew(AS_context *ctx);
ConnectionContext *NetworkAPI_ConnectionNew(SocketContext *sptr);
void NetworkAPI_FreeBuffers(IOBuf **ioptr);
void NetworkAPI_ConnectionsCleanup(AS_context *, SocketContext *sptr);
int NetworkAPI_Cleanup(AS_context *ctx);
int NetworkAPI_Incoming(AS_context *ctx, PacketBuildInstructions *iptr);
PacketBuildInstructions *NetworkAPI_BuildBasePacket(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr, int flags);
int NetworkAPI_SocketIncomingTCP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr);
int NetworkAPI_SocketIncomingUDP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr);
int NetworkAPI_SocketIncomingICMP(AS_context *ctx, SocketContext *sptr, PacketBuildInstructions *iptr);

int NetworkAPI_Perform(AS_context *);


PacketBuildInstructions *NetworkAPI_GeneratePacket(AS_context *ctx, SocketContext *sptr, ConnectionContext *cptr, int flags);



ssize_t my_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t my_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t my_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t my_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t my_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int my_accept4(int sockfd, struct sockaddr *addr,socklen_t *addrlen, int flags);
int my_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int my_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
int my_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen);
int my_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int my_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

// ----
// done
int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int my_socket(int domain, int type, int protocol);
int my_listen(int sockfd, int backlog);
int my_close(int fd);
// ----
