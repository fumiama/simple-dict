#include <stdio.h>
#include <string.h>
#include <simple_protobuf.h>
#include <sys/types.h>

#include "dict.h"

static struct dict_t d;
static uint8_t buf[8+DICTSZ];

#define has_next(fp, ch) ((ch=getc(fp)),(feof(fp)?0:(ungetc(ch,fp),1)))

int main(int argc, char** argv) {
    if(argc == 2) {
        uint32_t* items_len = align_struct(DICTSZ, 2, d.key, d.data);
        FILE* f = fopen(argv[1], "rb");
        if(f) {
            int ch;

            while(has_next(f, ch)) {
                simple_pb_t* spb = read_pb_into(f, (simple_pb_t*)buf);
                struct dict_t* d;
                if(!spb) {
                    fputs("Bad spb file", stderr);
                    exit(EXIT_FAILURE);
                }
                dict_t* dd = (dict_t*)spb->target;
                printf("%s\t\t%s\n", dd->key, dd->data);
            }
            fclose(f);
        } else puts("Open file error.");
    } else puts("Usage: <dict.sp>");
}
