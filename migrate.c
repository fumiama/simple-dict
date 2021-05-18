#include <stdio.h>
#include <string.h>
#include <simple_protobuf.h>
#include "dict.h"
#include "old_dict.h"

DICTBLK dict;
DICT d;

int main(int argc, char** argv) {
    if(argc == 3) {
        uint32_t* items_len = align_struct(sizeof(DICT), 2, d.key, d.data);
        FILE* old = fopen(argv[1], "rb");
        FILE* new = fopen(argv[2], "wb");
        if(old && new) {
            while(fread(&dict, DICTBLKSZ, 1, old) > 0) {
                uint8_t ks = dict.keysize;
                dict.key[ks] = 0;
                uint8_t ds = dict.datasize;
                dict.data[ds] = 0;
                memset(&d, 0, sizeof(DICT));
                memcpy(d.key, dict.key, ks);
                memcpy(d.data, dict.data, ds);
                set_pb(new, items_len, sizeof(DICT), &d);
            }
            fclose(old);
            fclose(new);
        } else puts("Open file error.");
    } else puts("Usage: <old_dict> <new_dict>");
}
