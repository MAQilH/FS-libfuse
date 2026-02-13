#ifndef BITMAP_H
#define BITMAP_H

#include "types.h"

// Bitmap manipulation functions
uint32_t block_to_bitnum(uint32_t block_addr);
uint32_t bitnum_to_block(uint32_t bitnum);
int get_bit(uint32_t bitnum);
void set_bit(uint32_t bitnum, int value);
void mark_block_used(uint32_t block_addr);
void mark_block_free(uint32_t block_addr);
int is_block_free(uint32_t block_addr);

#endif // BITMAP_H
