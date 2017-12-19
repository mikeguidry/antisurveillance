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


int main(int argc, char *argv[]) {
int epoch=time(0);
int secs = epoch % 60;

uint32_t seq = 0xdeadABCD;
uint32_t a, b;
uint32_t c = inet_addr("8.8.8.8");
uint32_t c2 = inet_addr("")
uint32_t d = c % 1024;
uint32_t e = 0;
printf("e %d\nsecs %d\na %d b %d\n", epoch, secs, secs / 2, secs % 2);
a = secs / 2;
b = secs % 2;

seq = (a << 16) + ((b & 0x0000ffff) << 8); 
e = (a << 16) + ((b & 0x0000ffff) << 16) + ((c % 1024) << 8);
printf("%08x d %08x e %08x\n", seq, d, e);
4 bits = var 1 (secs/2)
4 bits = secs 5 2 (time slice in minute)
8 bits = ip modular (% 65535)
16 bits = source port+checksum

souurce port > 32000 (to cut 16 bits into 8)  (can swap between high/low every few minutes).. or can use % 2 (to mix up high/low in between)
src port > 0x0000ffff

checksum = a+b * src

// algorithm for seq (ver 1)
seq = [4 bits:var_1][4 bits:var_2][8 bits: ip % 0xffff][4:src - 0xffff0000][4: (var_1+var_2*(src&0x0000ffff))]
// todo ipv6 algo

// can precalculate all attack packets to initialize for full five minutes and verify timings to test


/*
byte 255 % 255 (too big)
unsigned short = 65535 ... 

*/

}