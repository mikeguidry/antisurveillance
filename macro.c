#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>



// this function will replace a MACRO within a string with other data.. so you can do
// macro_replace("http://url.com/%AFFILIATE_ID%/banner.js", "%AFFILIATE_ID%", "1") for instance...
char *macro_replace(char *original, char *macro, char *data, int *ret_len) {
    char *ptr=NULL;
    char *sptr=NULL, *sptr2=NULL;
    char *buf=NULL;
    int len=0;
    int original_len=0;
    int data_len=0;
    int macro_len=0;
    
    //sanity
    if ((original==NULL) || (macro == NULL) || (data == NULL)) return NULL;
    
    // find lenghts of parameters
    macro_len = strlen(macro);
    data_len = strlen(data);
    original_len = strlen(original);
    
    // check if the macro is inside of the string
    if ((sptr = strstr(original, macro)) == NULL) {
        return NULL;
    }
    
    // find the end of the macro
    sptr2 = (char *)(sptr + macro_len);
    
    // maximum length of possible output scenario... (not perfect calculation but doesnt matter since heaps are usually allocated in pages.. as long its bigger :) )
    len = original_len + macro_len + data_len;
    if ((buf = malloc(len + 2)) == NULL) return NULL;
    memset(buf, 0, len + 1);
    
    ptr = buf;
    // copy original buffer until the macro placement into the final buffer
    memcpy(buf, original, (sptr - original));
    ptr += (sptr - original);
    // copy the replacement data after the memory copied above
    memcpy(buf+(sptr-original), data, data_len);
    ptr += data_len;
    // copy the rest of the string behind the macro into the final buffer
    memcpy(buf+(sptr-original)+data_len, sptr2, original_len - (sptr2 - original));
    ptr += (original_len - (sptr2 - original));
    // set the pointer to the location after all of this..
    // make it NULL (which is why we +2 earlier)
    *ptr++ = 0;
    
    *ret_len = strlen(buf);
    // return the final buffer to the calling function
    return buf;
}