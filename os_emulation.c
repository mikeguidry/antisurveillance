#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "network.h"
#include "antisurveillance.h"

/*
I want this information to get automatically populated using live pcaps, or wire.  It can monitor port 80, and pull this information
out of HTTP headers in real time.  It would mean there is no reason to update the technology for the future.  I want this entire
system to be completely automated forever.
*/
typedef struct _operating_system {
    int id;
    int ttl;
    int window_size;

    int residential;
    int commercial;

    int percentage_residential;
    int percentage_commercial;

    char *user_agent;
    int user_agent_size;
    
    void *custom_data;
    int custom_size;
} OperatingSystemParameters;
// parameters required for emulation of operating systems
struct _operating_system_emulation_parameters {
    int id;
    int ttl;
    int window_size;
    // for later when doing mass amounts (millions) of connections, then we should get as accurate as possible
    int percentage_residential;
    int percentage_commercial;
} EmulationParameters[] = {
    { 1,    64, 5840,   15, 30    },               //Linux
    { 2,    64, 5720,   0,  1     },               //Google Linux
    { 4,    64, 65535,  3,  5     },               // FreeBSD
    { 8,    128, 65535, 40, 55    },               // XP
    { 16,   128, 8192,  45, 35    },               // Windows 7/Vista/Server 2008
    { 32,   255, 4128,  1,  5     },                // Cisco
    { 0,      0,    0,  0,  0     }
};

enum {
    OS_LINUX=4,
    OS_GOOGLE_LINUX=8,
    OS_FREEBSD=16,
    OS_XP=32,
    OS_WIN7=64,
    OS_CISCO=128,
    OS_CLIENT=OS_XP|OS_WIN7,
    OS_SERVER=OS_LINUX|OS_FREEBSD
    
};


// to do add counting logic, and percentage choices
// !!! this code is terrible.. rewrite completely
void OsPick(int options, int *ttl, int *window_size) {
    int i = 0;
    int *list = NULL;
    int c = 0;
    int pick = 0;
    int a = 0;

    for (i = 0; EmulationParameters[i].id != 0; i++) {
        if (options & EmulationParameters[i].id) c++;
    }

    list = (int *)calloc(1,sizeof(int) * (c ));
    if (list == NULL) {
        pick = OS_XP;

        for (i = a = 0; EmulationParameters[i].id != 0; i++) {
            if (options & EmulationParameters[i].id)
                list[a] = EmulationParameters[i].id;
        }
        
        pick = list[rand()%c];
    }

    *ttl = EmulationParameters[pick].ttl;
    *window_size = EmulationParameters[pick].window_size;

    if (list != NULL) free(list);
    return;
}


// we would like to count the amount of clients, and servers on initialization so we can pick easily later
void os_init(AS_context *ctx) {

    return;
}