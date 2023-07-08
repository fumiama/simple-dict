#include <stdio.h>
#include <string.h>
#include <simple_protobuf.h>
#include <sys/types.h>

#define DICTKEYSZOLD 64
#define DICTDATSZOLD 64
#define DICTKEYSZNEW 127
#define DICTDATSZNEW 127

typedef struct {
    char key[DICTKEYSZOLD];
    char data[DICTDATSZOLD];
} DICTOLD;

typedef struct {
    char key[DICTKEYSZNEW];
    char data[DICTDATSZNEW];
} DICTNEW;

DICTNEW nd;

#define has_next(fp, ch) ((ch=getc(fp)),(feof(fp)?0:(ungetc(ch,fp),1)))

int main(int argc, char** argv) {
    if(argc == 3) {
        uint32_t* items_len_new = align_struct(sizeof(DICTNEW), 2, nd.key, nd.data);
        FILE* old = fopen(argv[1], "rb");
        FILE* new = fopen(argv[2], "wb");
        if(old && new) {
            int ch;

            while(has_next(old, ch)) {
                simple_pb_t* spb = get_pb(old);
                DICTNEW* d;
                switch(spb->struct_len) {
                    case sizeof(DICTOLD):
                        d = &nd;
                        memset(d, 0, sizeof(DICTNEW));
                        memcpy(nd.key, ((DICTOLD*)spb->target)->key, DICTKEYSZOLD);
                        memcpy(nd.data, ((DICTOLD*)spb->target)->data, DICTDATSZOLD);
                    break;
                    case sizeof(DICTNEW):
                        d = spb->target;
                    break;
                    default: continue; break;
                }
                set_pb(new, items_len_new, sizeof(DICTNEW), d);
                free(spb);
            }
            fclose(old);
            fclose(new);
        } else puts("Open file error.");
    } else puts("Usage: <old_dict> <new_dict>");
}
