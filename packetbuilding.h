#include <netinet/ip6.h>
#include <netinet/icmp6.h>


// PacketInfo is the first structure packets get prepared into being read either from the wire, or from a PCAP.
// It is also the last structure outgoing buffers will be contained within before being added to the final outgoing
// queue which flushes directly to the network.  It is also where you could save to a PCAP rather than flush to the network.
typedef struct _pkt_info {
    struct _pkt_info *next;

    // for future (wifi raw, etc)
    //int layer;

    // ipv4 tcp/udp/icmp? ipv6...?
    int type;


    uint32_t dest_ip;
    struct in6_addr dest_ipv6;
    uint16_t dest_port;
    uint16_t source_port;

    char *buf;
    int size;


    // if we need to wait till a certain time for releasing this packet, then it goes here..
    // this is good for emulation of advanced protocols.. think SSH, telnet, etc anything
    // which is real time & has humans performing actions over a single connection
    int wait_time;
} PacketInfo;


// This structure is used to contain analysis information after processing incoming PacketInfo packets.
// It is also kept around to allow easy modifications to attack structures packets to ensure that they
// are continously different, or have other adjustments.
typedef struct _packet_instructions {
    struct _packet_instructions *next;
    
    // What IP protocol? 4/6?  What type of packet? TCP/UDP/ICMP...
    int type;

    int ts;
    
    // Is this packet considered to be from the client side? (The system opening outgoing connection to a server)
    int client;

    // Packets time to live setting
    int ttl;

    // Packets identifier for the header
    uint32_t header_identifier;
    
    // how to hold the IP addresses?
    // IPv4
    uint32_t source_ip;
    uint32_t destination_ip;

    // IPv6
    struct in6_addr source_ipv6;
    struct in6_addr destination_ipv6;

    // Ports for this packet (TCP/UDP)
    int source_port;
    int destination_port;

    // Flags.. it gets converted into TCP/IP flags but could contain other things
    int flags;


    // data goes here.. but it'd be nice to have it as an array..
    // so a function can fragment it which would cause even further processing
    // by surveillance platforms.. even bit counts across thousands/millions
    // of connections per second, or minute
    char *data;
    int data_size;
    //int data_nofree;

    // final packet will get returned inside of the structure as well..
    char *packet;
    int packet_size;

        

    // if all is welll?... if not.. every instruction with the same session id
    // will get disqualified
    int ok;
    
    AS_attacks *aptr;


    // TCP header additional information
    char *options;
    int options_size;

    // we should have a decent way of swapping these?
    // either builder function can loop again after using daata size, and 
    // flags.. or it can keep track initially using pointers to set this information
    uint32_t ack;
    uint32_t seq;

    // Window size for the header (and controls amount of bytes for data flow each packet)
    unsigned short tcp_window_size;

    // information required to generate ICMP packets
    struct icmphdr icmp;
    struct icmp6_hdr icmp6;
    
} PacketBuildInstructions;



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

struct pseudo_tcp6
{
    
    struct in6_addr saddr;
    struct in6_addr daddr;
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

struct pseudo_header_udp6 {
    struct in6_addr source_address;
    struct in6_addr destination_address;
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

struct packeticmp4 {
    struct iphdr ip;
    struct icmphdr icmp;
};

struct packettcp6 {
    struct ip6_hdr ip;
    struct tcphdr tcp;
};

struct packetudp6 {
    struct ip6_hdr ip;
    struct udphdr udp;
};

struct packeticmp6 {
    struct ip6_hdr ip6;
    struct icmp6_hdr icmp6;
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
    ATTACK_SESSION,
    ATTACK_MULTI,
    ATTACK_END
};


// Packet types that are supported.  The order does matter because it is used in two different linked lists.  One is for
// building packets, and the other is for analysis of incoming packets.
enum {
    PACKET_TYPE_TCP_4=1,
    PACKET_TYPE_UDP_4=2,
    PACKET_TYPE_ICMP_4=4,
    PACKET_TYPE_TCP_6=8,
    PACKET_TYPE_UDP_6=16,
    PACKET_TYPE_ICMP_6=32,
    PACKET_TYPE_IPV4=64,
    PACKET_TYPE_IPV6=128,
    PACKET_TYPE_ICMP=256,
    PACKET_TYPE_UDP=512,
    PACKET_TYPE_TCP=1024

};



// The filter is used to load sessions from PCAP, or the raw network interface.  It allows you to easily
// find connections of interest.  The *_FAMILIAR flag is used to allow finding both sides of the connection
// within the same filter.
enum {
    FILTER_CLIENT_IP=1,
    FILTER_SERVER_IP=2,
    FILTER_CLIENT_PORT=4,
    FILTER_SERVER_PORT=8,
    FILTER_PACKET_FLAGS=16,
    FILTER_PACKET_FAMILIAR=32,
    FILTER_PACKET_TCP=64,
    FILTER_PACKET_UDP=128,
    FILTER_PACKET_ICMP=256,
    FILTER_PACKET_IPV4=512,
    FILTER_PACKET_IPV6=1024,
    FILTER_CLIENT_IPV6=2048,
    FILTER_SERVER_IPV6=4096,
    FILTER_OURS=8192
};

// This is the structure used to pass around filter information internally.
typedef struct _filter_information {
    int flags;
    int packet_flags;

    int is_source_ipv6;
    uint32_t source_ip;
    struct in6_addr source_ipv6;

    int is_destination_ipv6;
    uint32_t destination_ip;
    struct in6_addr destination_ipv6;

    uint16_t source_port;
    uint16_t destination_port;

    int init;
} FilterInformation;




void PacketLogic(AS_context *, AS_attacks *aptr, OutgoingPacketQueue **);
void PacketsFree(PacketInfo **packets);
void BuildPackets(AS_attacks *aptr);
int PacketTCPBuildOptions(PacketBuildInstructions *iptr);

int BuildSingleTCP4Packet(PacketBuildInstructions *iptr);
int BuildSingleUDP4Packet(PacketBuildInstructions *iptr);
int BuildSingleICMP4Packet(PacketBuildInstructions *iptr);
int BuildSingleTCP6Packet(PacketBuildInstructions *iptr);
int BuildSingleUDP6Packet(PacketBuildInstructions *iptr);
int BuildSingleICMP6Packet(PacketBuildInstructions *iptr);
int BuildPacketInstructions(PacketBuildInstructions *iptr);

unsigned short in_cksum(unsigned short *addr,int len);



int test_icmp4(AS_context *ctx);