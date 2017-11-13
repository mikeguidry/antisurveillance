
struct _pkt_info;
typedef struct _pkt_info PacketInfo;

struct _attack_outgoing_queue;
typedef struct _attack_outgoing_queue AttackOutgoingQueue;


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



int PCAPtoAttack(char *filename, int dest_port, int count, int interval);
PacketInfo *PcapLoad(char *filename);
int PcapSave(char *filename, AttackOutgoingQueue *packets);