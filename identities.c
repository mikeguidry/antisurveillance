/*

This file will contain structures, etc relating to identities.  Macros and identities will be paired together to replace
client, and server bodies for fabricating HTTP sessions.  It can allow automation of chaining identities together.

example:
make the president of USA, or other country seem like a friend to a single person, or a lot of people...
possibly filter yourself from certain activities of these platforms, etc.. i wrote a paper on it.. so i wont
get far into it now...
its in the why/ directory

invisible_friends*.pdf


*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>




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