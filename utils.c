
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/time.h>
#include <stdint.h>
#include <netinet/in.h>
#include "network.h"
#include "antisurveillance.h"
#include "utils.h"  
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>

#define BUFFER_SIZE 4096


// count the amount of entries in a linked list
int L_count(LINK *ele) {
    int count = 0;
    
    while (ele != NULL) {
      count++;
      ele = ele->next;
    }
    
    return count;
  }

  
// finds the last element in a linked list
LINK *L_last(LINK *list) {
    if (list == NULL) return NULL;
    while (list->next != NULL) {
      list = list->next;
    }
    return list;
}


void L_link_unordered(LINK **list, LINK *ele) {
    ele->next = *list;
    *list = ele;
}

// Orderd linking (first in first out) which is required for packets
void L_link_ordered(LINK **list, LINK *ele) {
    LINK *_last = NULL;
    
    // if the list has no entries.. then this becomes its first element
    if (*list == NULL) {
      *list = ele;
      return;
    }

    // find the last element
    _last = L_last(*list);
    if (_last == NULL) {
        return;
    }
    // and append this to that one..
    _last->next = ele;
}

  // unlinks something from a list
void L_unlink(LINK **list, LINK *ptr) {
    LINK *lptr = *list, *lnext = NULL, *llast = NULL;

    while (lptr != NULL) {

        // if we found it
        if (lptr == ptr) {
            if (llast) {
                llast->next = ptr->next;
            } else {
                *list = ptr->next;
            }
            return;
        }

        lptr = lptr->next;
    }
}


// free a pointer after verifying it even exists
void PtrFree(char **ptr) {
    if (ptr == NULL) return;
    if (*ptr == NULL) return;
    
    free(*ptr);
    *ptr = NULL;
}


// allocates & copies data into a new pointer
int DataPrepare(char **data, char *ptr, int size) {
    char *buf = (char *)malloc(size );
    if (buf == NULL) return -1;

    memcpy(buf, ptr, size);
    *data = buf;

    return 1;
}


int PtrDuplicate(char *ptr, int size, char **dest, int *dest_size) {
    char *buf = NULL;
    
    if ((ptr == NULL) || (size <= 0)) {
        return 0;
    }

    if ((buf = (char *)malloc(size + 1)) == NULL) {
        return -1;
    }

    memcpy(buf, ptr, size);

    *dest = buf;
    *dest_size = size;

    return 1;
}



//https://www.linuxquestions.org/questions/programming-9/how-to-calculate-time-difference-in-milliseconds-in-c-c-711096/
int timeval_subtract (struct timeval *result, struct timeval  *x, struct timeval  *y) {
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;

        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }

    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;

        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    return x->tv_sec < y->tv_sec;
}


int FileWrite(char *filename, char *ptr, int size) {
    int ret = 0;
    int r = 0;
    FILE *fd = fopen(filename, "wb");
    if (fd == NULL) return -1;
    r = fwrite(ptr, 1, size, fd);
    fclose(fd);
    return (r == size);
}

// put a files contents into a memory buffer
char *FileContents(char *filename, int *size) {
    FILE *fd = fopen(filename,"rb");
    char *buf = NULL;
    struct stat stv;
    if (fd == NULL) return NULL;
    fstat(fileno(fd), &stv);
    buf = (char *)calloc(1,stv.st_size );

    if (buf != NULL) {
        fread(buf,stv.st_size,1,fd);
        *size = stv.st_size;
    }

    fclose(fd);

    return buf;
}



// copy an IPv6 address over.. simple although I wanted to SHOW IPv6 everywhere it was taking place instead of 'memcpy'
void CopyIPv6Address(void *dst, void *src) {
    // verify both parameters arent NULL..
    if (dst && src)
        memcpy(dst, src, sizeof(struct in6_addr));
}

// compare two IPv6 addresses.. allows NULL parameters on purpose
int CompareIPv6Addresses(struct in6_addr *first, struct in6_addr *second) {
    if (!first && !second)
        return 0;

    return (memcmp(first,second,sizeof(struct in6_addr)) == 0);
}



// Orderd linking (first in first out) which is required for packets
void L_link_ordered_offset(LINK **list, LINK *ele, int offset) {
    LINK *_last = NULL;
    void **ptr = NULL;
    void **ptr2 = NULL;

    // if the original pointer is empty... lets set it
    // we have to be careful and set here because the offset is for the 'next' only..
    //  the initial pointer is at 0.. not +offset
    if (*list == NULL) {
        *list = ele;
        return;
    }

    // use the offset that was passsed.. so we add it to THAT linked list.
    // its the 'next'
    ptr = (void *)((unsigned char *)(*list) + offset);
    
    // if 'next' is empty.. set and return
    if (*ptr == NULL) {
        *ptr = ele;

        return;
    }
    
    // if not NULL... then..
    while (*ptr != NULL) {

        // go into that next.. and look at ITS 'next'
        ptr2 = (void **)((unsigned char *)(*ptr) + offset);

        // if that 'next' is NULL.. we wanna use it
        if (*ptr2 == NULL) break;

        // ptr = ptr->'next'
        ptr = (void **)((unsigned char *)(*ptr2) + offset);

        // if its free...
        if (*ptr == NULL) {
            *ptr = (void *)ele;
            return;
        }
    }

    // set the last one's 'next' (using the offset of it) to this new element
    *ptr2 = (void *)ele;    
}


// L_count() which takes offset (instead of the LINK structure ->next)
// means itll work for multidimensional lists we use in research.c
int L_count_offset(LINK *lptr, int offset) {
    int count = 0;
    void **ptr = NULL, **ptr2 = NULL;

    // if we dont have any at all...
    if (lptr == NULL) return 0;

    do {
        count++;

        ptr = (void **)((unsigned char *)lptr + offset);

        // if the next element (using the offset instead of ->next, which is the real 'next') is NULL, then we're done
        // *** this is redundant.. the do {} while will get the same information
        if (*ptr == NULL) break;

        // otherwise lets move forward with  it
        lptr = *ptr;
    } while (lptr != NULL);

    return count;
}



// this prepares fabricated connections using either IPv4, or IPv6 addresses.. it detects IPv6 by the :
int IP_prepare(char *ascii_ip, uint32_t *ipv4_dest, struct in6_addr *ipv6_dest, int *_is_ipv6) {
    int is_ipv6 = 0;

    if (ascii_ip == NULL) return 0;

    is_ipv6 = strchr(ascii_ip, ':') ? 1 : 0;

    if (!is_ipv6) {
        if (ipv4_dest)
            *ipv4_dest = inet_addr(ascii_ip);

        if (_is_ipv6 != NULL)
            *_is_ipv6 = 0;
    } else {
        if (_is_ipv6 != NULL)
            *_is_ipv6 = 1;

        inet_pton(AF_INET6, ascii_ip, ipv6_dest);
    }

    return 1;   
}


// this prepares fabricated connections using either IPv4, or IPv6 addresses.. it detects IPv6 by the :
char *IP_prepare_ascii(uint32_t ipv4_dest, struct in6_addr *ipv6_src) {
    char final[50]; // its 45-46.. or 16.. whatever
    struct in_addr dst;
    char *buf = NULL;

    memset(final, 0, sizeof(final));

    if (ipv4_dest) {
        dst.s_addr = ipv4_dest;
        strncpy(final, inet_ntoa(dst), sizeof(final));
    } else if (ipv6_src != NULL) {
        buf = inet_ntop(AF_INET6, ipv6_src, &final, sizeof(final)); 
    }

    return strdup(final);
}



int file_exist(char *filename) {
    struct stat stv;
    return (stat(filename, &stv) == 0);
}



// https://gist.githubusercontent.com/javiermon/6272065/raw/f6456b6db893a8f020a2436f1043f0eb12ac57e1/gateway_netlink.c

char *getgatewayandiface() {
    int     received_bytes = 0, msg_len = 0, route_attribute_len = 0;
    int     sock = 0, msgseq = 0;
    struct  nlmsghdr *nlh, *nlmsg;
    struct  rtmsg *route_entry;
    // This struct contain route attributes (route type)
    struct  rtattr *route_attribute;
    char    gateway_address[INET_ADDRSTRLEN], interface[IF_NAMESIZE];
    char    msgbuf[BUFFER_SIZE], buffer[BUFFER_SIZE];
    char    *ptr = buffer;
    struct timeval tv;
    char *ret = NULL;

    if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) goto end;

    memset(msgbuf, 0, sizeof(msgbuf));
    memset(gateway_address, 0, sizeof(gateway_address));
    memset(interface, 0, sizeof(interface));
    memset(buffer, 0, sizeof(buffer));

    /* point the header and the msg structure pointers into the buffer */
    nlmsg = (struct nlmsghdr *)msgbuf;

    /* Fill in the nlmsg header*/
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlmsg->nlmsg_seq = msgseq++; // Sequence of the message packet.
    nlmsg->nlmsg_pid = getpid(); // PID of process sending the request.

    /* 1 Sec Timeout to avoid stall */
    tv.tv_sec = 1;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
    /* send msg */
    if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) goto end;

    /* receive response */
    do {
        received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);
        if (received_bytes < 0) goto end;

        nlh = (struct nlmsghdr *) ptr;

        /* Check if the header is valid */
        if((NLMSG_OK(nlmsg, received_bytes) == 0) ||
           (nlmsg->nlmsg_type == NLMSG_ERROR)) goto end;

        /* If we received all data break */
        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        else {
            ptr += received_bytes;
            msg_len += received_bytes;
        }

        /* Break if its not a multi part message */
        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
            break;
    } while ((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

    /* parse response */
    for ( ; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes)) {
        /* Get the route data */
        route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

        /* We are just interested in main routing table */
        if (route_entry->rtm_table != RT_TABLE_MAIN)
            continue;

        route_attribute = (struct rtattr *) RTM_RTA(route_entry);
        route_attribute_len = RTM_PAYLOAD(nlh);

        /* Loop through all attributes */
        for ( ; RTA_OK(route_attribute, route_attribute_len);
              route_attribute = RTA_NEXT(route_attribute, route_attribute_len)) {
            switch(route_attribute->rta_type) {
            case RTA_OIF:
                if_indextoname(*(int *)RTA_DATA(route_attribute), interface);
                break;
            case RTA_GATEWAY:
                inet_ntop(AF_INET, RTA_DATA(route_attribute),
                          gateway_address, sizeof(gateway_address));
                break;
            default:
                break;
            }
        }

        if (*interface) ret = strdup(interface);

        if ((*gateway_address) && (*interface))
            break;
    }

    

end:;
    if (sock) close(sock);
    return ret;
}



// on routers if the free memory is extremely low then we dont want to hold all outgoing packets in our memory (IoT routers wouldnt handle it properly)
// especially with large attack structures, and attempting to filter out our own packets
int FreeMemoryMB() {
    FILE *fd;
    char buf[1024];
    int i = 0;
    unsigned long long ret = 0;
    unsigned long long value = 0;
    char type[32];
    char *sptr = NULL;
    char wanted[] = "MemFree";

    if ((fd = fopen("/proc/meminfo", "r")) == NULL) return 0;

    while (fgets(buf,1024,fd)) {
        //if ((sptr = strchr(buf, '\r')) != NULL) *sptr = 0;
        //if ((sptr = strchr(buf, '\n')) != NULL) *sptr = 0;
        sscanf(buf, "%32s %llu", type, &value);
        if ((sptr = strchr(type, ':')) != NULL) *sptr = 0;
        if (strcmp(type, wanted)==0) {
            ret = value;
            break;
        }
    }

    fclose(fd);

    if (ret) ret /= (1024);
    
    return ret;
}


// allows us to use various IPv4 addresses which we receieve data for
// this needs to obviously be redone.. 
uint32_t get_source_ipv4() {
    char ip[16];
    int r = 1+rand()%250;
    
    sprintf(ip, "192.168.72.%d",r);

    return inet_addr(ip);
}

// allows us to use random/various IPv6 addresses which we receive packets for
// this needs to obviously be redone..
void get_source_ipv6(struct in6_addr *addr6) {
    struct in6_addr our_ipv6;
    get_local_ipv6(&our_ipv6);
    // now for here to modify IPv6 if we are performing massive attacks
    // mangle the IP, etc... but ensure its within our ranges

}