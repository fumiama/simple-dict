#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>
#include <simplecrypto.h>
#include <types.h>
#include "server.h"

void init_crypto();
void reset_seq(int index);
char* raw_encrypt(const char* buf, off_t* len, int index, const char pwd[64]);
char* raw_decrypt(const char* buf, off_t* len, int index, const char pwd[64]);
void cmdpacket_encrypt(CMDPACKET* p, int index, const char pwd[64]);
int  cmdpacket_decrypt(CMDPACKET* p, int index, const char pwd[64]);

#endif /* _CRYPTO_H_ */
