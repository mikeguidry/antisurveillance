



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
void L_link_ordered_offset(LINK **list, LINK *ele, int offset);
int L_count_offset(LINK *lptr, int offset);
int IP_prepare(char *ascii_ip, uint32_t *ipv4_dest, struct in6_addr *ipv6_dest, int *_is_ipv6);
void L_link_unordered(LINK **list, LINK *ele);