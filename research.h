
// one single dns record (response about a hostname, prepared to stay on record)
// it can be reused for preparing further attacks against the same sites, etc
// using different residential, or business ip addresses
typedef struct _dns_record {
    struct _dns_record *next;
    // raw response..
    unsigned char *response;
    int response_size;

    unsigned char type; // enums from before

    uint32_t ipv4;
    uint64_t ipv6;

    // ts of last lookup
    int ts;

    int country_id;
} DNSRecord;


typedef struct _lookup_queue {
    struct _lookup_queue *next;

    char *hostname;

    // spider would be for using different dns servers in different geos
    // it allows using geo ips which look more legit
    // one of the first responses to these attacks will be to filter the attacks out
    // using scenarios like this...
    struct _lookup_queue *spider;
    struct _lookup_queue *recursive;

    // is this queue complete? (it wouuld mean that all recursive/spider are completed as well)
    int comp