



// generic linked list structure which will always work for any structure type with 'next' as its first element
// you just need to cast to (LINK *<*>)
typedef struct _link { struct _link *next; } LINK;


char *FileContents(char *filename, int *size);
int timeval_subtract (struct timeval *result, struct timeval  *x, struct timeval  *y);
int PtrDuplicate(char *ptr, int size, char **dest, int *dest_size);
int DataPrepare(char **data, char *ptr, int size);
void PtrFree(char **ptr);
void L_link_ordered(LINK **list, LINK *ele);
LINK *L_last(LINK *list);
int L_count(LINK *ele);

void md5hash(char *data, int size);
void CopyIPv6Address(void *dst, void *src);
int CompareIPv6Addresses(struct in6_addr *first, struct in6_addr *second);