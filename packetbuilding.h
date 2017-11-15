

//struct _as_attacks;
//typedef struct _as_attacks *AS_attacks;

// this is where the packet is held after the attack type's functin generates it.. so that function will be called only once
// per packetinfo depending on the count, and intervals...
// its possible to free the packet after from that structure after usage thus allowing it to get regenerated for continous use
// this allows threading by way of many different attack structures, thus seperate session structures
// wide scale manipulation of mass surveillance platforms ;)
typedef struct _pkt_info {
    struct _pkt_info *next;

    // for future (wifi raw, etc)
    //int layer;

    // ipv4 tcp/udp/icmp? ipv6...?
    int type;

    uint32_t dest_ip;
    uint16_t dest_port;

    char *buf;
    int size;

    // if we need to wait till a certain time for releasing this packet, then it goes here..
    // this is good for emulation of advanced protocols.. think SSH, telnet, etc anything
    // which is real time & has humans performing actions over a single connection
    int wait_time;
} PacketInfo;





// allows preparing full session, and then building the packets immediately..
// resulting in this linked list going directly into a function for addition
// into the queue....
// i cannot think of any better way at the moment considering there are so many varibles
// and soon there will be functions being built around generalization of traffic statistics
// to ensure these connections cannot be singled out
// this is one method which allows expanding easily..
typedef struct _tcp_packet_instructions {
    struct _tcp_packet_instructions *next;

    int type;
    
    int client;

    int session_id;
    
    int ttl;
    

    uint32_t header_identifier;
    
    uint32_t source_ip;
    int source_port;

    uint32_t destination_ip;
    int destination_port;

    int flags;

    char *options;
    int options_size;

    // this is for the 
    unsigned short tcp_window_size;

    // data goes here.. but it'd be nice to have it as an array..
    // so a function can fragment it which would cause even further processing
    // by surveillance platforms.. even bit counts across thousands/millions
    // of connections per second, or minute
    char *data;
    int data_size;

    // final packet will get returned inside of the structure as well..
    char *packet;
    int packet_size;

    // we should have a decent way of swapping these?
    // either builder function can loop again after using daata size, and 
    // flags.. or it can keep track initially using pointers to set this information
    uint32_t ack;
    uint32_t seq;

    // if all is welll?... if not.. every instruction with the same session id
    // will get disqualified
    int ok;

    AS_attacks *aptr;
} PacketBuildInstructions;


#define PSEUDOTCPHSIZE	12
// base ip header size (without options)
#define IPHSIZE		20



#pragma pack(push,1)
// pseudo structure for calculating checksum
struct pseudo_tcp4
{
	unsigned saddr, daddr;
	unsigned char mbz;
	unsigned char ptcl;
	unsigned short tcpl;
	struct tcphdr tcp;
};


//http://www.binarytides.com/raw-udp-sockets-c-linux/
struct pseudo_header_udp4
{
    u_int32_t source_address;
    u_int32_t destination_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t len;
};


// packet header.. options go after tcphdr.. i havent used iphdr so oh well
struct packet
{
	struct iphdr ip;
    struct tcphdr tcp;
};


struct packetudp4 {
    struct iphdr ip;
    struct udphdr udp;
};

#pragma pack(pop)

enum {
    TCP_TRANSFER=8,
    TCP_FLAG_NS=16,
    TCP_FLAG_CWR=32,
    TCP_FLAG_ECE=64,
    TCP_FLAG_URG=128,
    TCP_FLAG_ACK=256,
    TCP_FLAG_PSH=512,
    TCP_FLAG_RST=1024,
    TCP_FLAG_SYN=2048,
    TCP_FLAG_FIN=4096,
    TCP_OPTIONS_WINDOW=8192,
    TCP_OPTIONS_TIMESTAMP=16384,
    TCP_OPTIONS=32768
};

enum {
    ATTACK_SYN,
    ATTACK_SESSION,
    ATTACK_END
};


enum {
    PACKET_TYPE_TCP_4,
    PACKET_TYPE_UDP_4,
    PACKET_TYPE_ICMP_4,
    PACKET_TYPE_TCP_6,
    PACKET_TYPE_UDP_6,
    PACKET_TYPE_ICMP_6
};



// types of filtering we can perform..
// FAMILIAR means it will match client/server sides of the connection
enum {
    FILTER_CLIENT_IP=1,
    FILTER_SERVER_IP=2,
    FILTER_CLIENT_PORT=4,
    FILTER_SERVER_PORT=8,
    FILTER_PACKET_FLAGS=16,
    FILTER_PACKET_FAMILIAR=32
};

typedef struct _filter_information {
    int flags;
    int packet_flags;
    uint32_t source_ip;
    uint32_t destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    int init;
} FilterInformation;





void PacketQueue(AS_context *, AS_attacks *aptr);
void PacketsFree(PacketInfo **packets);
void BuildPackets(AS_attacks *aptr);
int PacketTCP4BuildOptions(AS_attacks *aptr, PacketBuildInstructions *iptr);
int BuildSingleTCP4Packet(PacketBuildInstructions *iptr);
int BuildSingleUDP4Packet(PacketBuildInstructions *iptr);
int BuildSingleICMP4Packet(PacketBuildInstructions *iptr);
unsigned short in_cksum(unsigned short *addr,int len);