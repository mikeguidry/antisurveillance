
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
    
    if ((ptr == NULL) || (size <= 0))
        return 0;

    if ((buf = (char *)malloc(size )) == NULL)
        return -1;

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