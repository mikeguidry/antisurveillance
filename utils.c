
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

  

// free a pointer after verifying it even exists
void PtrFree(char **ptr) {
    if (ptr == NULL) return;
    if (*ptr == NULL) return;
    
    free(*ptr);
    *ptr = NULL;
}


// allocates & copies data into a new pointer
int DataPrepare(char **data, char *ptr, int size) {
    char *buf = (char *)calloc(1, size );
    if (buf == NULL) return -1;

    memcpy(buf, ptr, size);
    *data = buf;

    return 1;
}


int PtrDuplicate(char *ptr, int size, char **dest, int *dest_size) {
    char *buf = NULL;
    
    if ((ptr == NULL) || (size <= 0)) {
        printf("ERR pptr %p size %d\n", ptr, size);
        return 0;
    }

    if ((buf = (char *)malloc(size )) == NULL) {
        printf("ERR couldnt allocate!\n");
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






void CopyIPv6Address(void *dst, void *src) {
    // verify both parameters arent NULL..
    if (dst && src)
        memcpy(dst, src, sizeof(struct in6_addr));
}

int CompareIPv6Addresses(struct in6_addr *first, struct in6_addr *second) {
    if (!first && !second) return 0;
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
        *ipv4_dest = inet_addr(ascii_ip);
        if (_is_ipv6 != NULL) *_is_ipv6 = 0;
    } else {
        if (_is_ipv6 != NULL) *_is_ipv6 = 1;
        inet_pton(AF_INET6, ascii_ip, ipv6_dest);
    }

    return 1;   
}


// this prepares fabricated connections using either IPv4, or IPv6 addresses.. it detects IPv6 by the :
char *IP_prepare_ascii(uint32_t *ipv4_dest, struct in6_addr *ipv6_src) {
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