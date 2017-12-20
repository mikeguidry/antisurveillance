/*
development for a timing algorithm to determine by seq/source port whether or not by the current time
if we should generate two packets for some SYN/ACK packet we received from a webserver
the entire concept of whether or not we should process the packet BEFORE this should also be included
it shoold be a simplle 1-2 line checksum (as quick as possible).. it could simply eb by the source port...
anyways
ill develop this heere.

we do not want to use more  than 1 second timings... i dont want to rely on anyting too strange, or specific..
also the helper box will need the same exact time (maybe ntp) as the router/passive monitoring system

all packets can be pregenerated for future time slices thus making sure we can reach a certain amount in the window timme
im thinking a window of 1.5-2seconds should be fine. so maybe 2-3...
we will also ignore everything above our seq:1, and anything from remote side after its initial SYN/ACK... 
i really dont believev there will be any problems... only pure mass attack
anwyays

epoch  % 60 might be the best... its quick, simple.. allows us to prepare  by 2second slices
int epoch=time(0);
int minutes = epoch % 60;

*/
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct _seq_oracle {
    unsigned char a : 4;
    unsigned char b : 4;
    unsigned short c : 8;
    unsigned short d : 8;
    unsigned short e : 8;
} SequenceOracle;

typedef union {
    SequenceOracle a;
    uint32_t b;
} abc;


// if we ONLY monitor for SYN+ACK AND pass this... regardless of some time warp it shoould still function properly..
// a better version can be done but im just winging this to get it released quickly... it wont take long to redo
int packet_filter(uint32_t seq, uint32_t ip, int port, uint32_t ts) {
    abc xyz;
    int i = 0;

    xyz.b=0;
    xyz.a.c = ((ip%1024) & 0x000000ff);
    xyz.a.d = port & 0x000000ff;

    ts -= 3;
    for (i =0; i < 5; i++) {
        xyz.a.a = ((ts+i)/2)& 0x0000000f;
        xyz.a.b = ((ts+i)%2)& 0x0000000f;
        if (xyz.b == seq) {
            printf("match at %d\n", i);
            return 1;
        }
        
    }

    

    return 0;
}

int main(int argc, char *argv[]) {
    int epoch=time(0);
    int secs = epoch % 60;
    union {
        SequenceOracle a;
        uint32_t b;
    } abc;
    int i = 0;
    int t = 0;
    int r = 0;

    uint32_t seq = 0;
    unsigned char a = secs/2 & 0x0000000f;
    unsigned char b = secs%2 & 0x0000000f;
    unsigned short c = ((inet_addr("4.2.2.1") % 1024) & 0x000000ff);
    unsigned short d = 60000 & 0x000000ff; 
t = time(0);
    if (argc == 1) {
t+=2;
        for (i = 0; i < 30; i++) {
        abc.b = 0;



a = ((t+i)/2) &  0x0000000f;
b = ((t+i)%2) & 0x0000000f;
c = ((inet_addr("4.2.2.1") % 1024) & 0x000000ff);
d = 60000 & 0x000000ff; 

        abc.a.a = a;
        abc.a.b = b;
        abc.a.c = c;
        abc.a.d = d;


        printf("%08X i:%d t:%d\n", (uint32_t)abc.b, i, t);

        d = abc.a.d;
        c = abc.a.c;
        b = abc.a.b;
        a = abc.a.a;

        
    }
    exit(0);
    }

    sscanf(argv[3], "%08X", &seq);
    t = time(0);

        r = packet_filter(seq, inet_addr(argv[2]), atoi(argv[1]), t+i);
        if (r==1) {
        printf("seq %08X ret:%d  t:%d\n", seq, r,  t);
        }

exit(0);
}