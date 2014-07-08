#ifndef _ADLER32_H
#define _ADLER32_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t adler32(uint32_t adler, uint8_t *buf, size_t len);
uint32_t adler32_last8(uint32_t adler, uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif