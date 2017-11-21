#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "network.h"
#include "antisurveillance.h"
#include "research.h"

/*

Research is everything related to stragegy choices.  For example, which sites do we wish to spend the majority
of our bandwidth falsifying connections towards?  It will perform DNS lookups, traceroutes, and BGP analysis to
determine the best IP 4/6 addresses to use for attacks.

For local attacks: NIDs, etc.. It will take the local IP addresses, and find the best ways of attacking
the platform to either hide in other packets, or attempt to force other issues such as Admin believing hacks
are taking place elsewhere.. etc

I'll try to require as little hard coded information as possible.  I'd like everything to work without requiring any updates -- ever.
*/


/*
typedef struct _points { int x; int y; int n} MPoints;
CPoints[] = {
    {00,11,1},{01,22,2},{21,31,3},{31,42,4},{41,53,5},{55,54,6},{54,53,7},{05,15,8},{14,22,9},{03,15,10},{24,35,11},{00,00,00}
};

int pdiff(int x, int y) {
    int ret = 0;
    int i = 0, a = 0, z = 0;
    MPoints points[16];

    while (CPoints[i].n != 0) {
        points[i].x = CPoints[i].x - x;
        if (points[i].x < 0) points[i].x ~= points[i].x;
        points[i].y = CPoints[i].y - y;
        if (points[i].y < 0) points[i].y ~= points[i].y; 

        i++;
    }

    for (a = 0; CPoints[a].id != 0; a++) {

    }

    return ret;
}

[00,11],[01,22],[21,31],[31,42],[41,53],[55,54],[54,53],[05,15],[14,22],[03,15],[24,35],[00,00]

0                       1                                  2                         3                          4                              5







1                     11                                  21                        31                         41                              51







2                      12                                  22                        32                         42                            52






3                     13                                   23                         33                         43                           53





4                      14                                  24                       34                            44                           54



5                     15                                25                            35                            45                          55



*/





// traceroutes are necessary to ensure a single nonde running this code can affect all mass surveillance programs worldwide
// it allows us to ensure we cover all places we expect them to be.. in the world today: if we expect it to be there.. then it
// probably is (for mass surveillance programs)
//https://www.information.dk/udland/2014/06/nsa-third-party-partners-tap-the-internet-backbone-in-global-surveillance-program
// we want to go through asa many routes as possible which means we are innjecting information into each surveillance tap along the way
// the other strategy will be using two nodes running this code which will be on diff parts of the world so we ca ensure eah side of the packets
// get processed correctly.. in the begininng (before they modify) it wont matter.. later once they attempt to filter out, and procecss
// it might matter but it'll make the entire job/technology that much more difficult
int Traceroute_Compare(TracerouteQueue *first, TracerouteQueue *second) {
    int ret = 0;

    // if there arent enough responses to compare.. then we are finished..
    // its not an error since it might just be queued with thousands of other sites/nodes
    if (!first->traceroute_responses_count_v4 || !second->traceroute_responses_count_v4)
        return ret;


    // we need to verify how close two nodes are in the world..
    // and if they go through the same fiber routers..
    // this will ensure that the taps get both sides of the connection
    // so we can be sure the attack is successful

    // need to know how many match, annd how close they are to the nodes themselves
    // if they are both within 1-2 of the nondes then we can assume same area, or DC

    // if they go through the same fiber taps in the middle its fine as well


    // we have other information such as leaks which will help us propagate the initial strategy
    end:;

    return ret;
}
