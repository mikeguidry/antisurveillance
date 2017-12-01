


typedef struct _identities {
    struct _identities *next;

    char *first_name;
    char  *middle_name;
    char *last_name;
    char *email;

    int count;

    int language;
    int country;
} Identities;