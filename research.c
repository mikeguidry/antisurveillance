
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

