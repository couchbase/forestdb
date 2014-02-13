/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_HASH_FUNCTIONS_H
#define _JSAHN_HASH_FUNCTIONS_H

uint32_t hash_djb2(void *value, int len);
uint32_t hash_djb2_last8(void *value, int len);
uint32_t hash_uint_modular(uint64_t value, uint64_t mod);
uint32_t hash_shuffle_2uint(uint64_t a, uint64_t b);

#endif
