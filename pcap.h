
struct _pkt_info;
typedef struct _pkt_info PacketInfo;

struct _outgoing_packet_queue;
typedef struct _outgoing_packet_queue OutgoingPacketQueue;

struct _filter_information;
typedef struct _filter_information FilterInformation;


#pragma pack(push, 1)
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;


typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

#pragma pack(pop)


typedef struct _pcap_operations {
    struct _pcap_operations *next;

    FilterInformation *flt;

    FILE *fd;
    char *filename;
} PCAPOperation;



int PCAPtoAttack(AS_context *, char *filename, int dest_port, int count, int interval, FilterInformation *pcap_flt);
PacketInfo *PcapLoad(char *filename);
int PcapSave(AS_context *, char *filename, OutgoingPacketQueue *packets, PacketInfo *iptr, int free_when_done);
int PCAP_Init(AS_context *ctx);
int PCAP_OperationAdd(AS_context *ctx, char *filename, FilterInformation *flt);
int PCAP_OperationRemove(AS_context *ctx, char *filename);