#include "bitmap.h"

uint32_t block_to_bitnum(uint32_t block_addr) {
	return (block_addr / BLOCK_SIZE);
}

uint32_t bitnum_to_block(uint32_t bitnum) {
	return bitnum * BLOCK_SIZE;
}

int get_bit(uint32_t bitnum) {
	uint32_t byte_offset = bitnum / 8;
	uint32_t bit_offset = bitnum % 8;
	uint32_t bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + byte_offset;
	
	uint8_t byte;
	fseek(disk, bitmap_offset, SEEK_SET);
	fread(&byte, 1, 1, disk);
	return (byte >> bit_offset) & 1;
}

void set_bit(uint32_t bitnum, int value) {
	uint32_t byte_offset = bitnum / 8;
	uint32_t bit_offset = bitnum % 8;
	uint32_t bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + byte_offset;
	
	uint8_t byte;
	fseek(disk, bitmap_offset, SEEK_SET);
	fread(&byte, 1, 1, disk);
	
	if (value) {
		byte |= (1 << bit_offset);
	} else {
		byte &= ~(1 << bit_offset);
	}
	
	fseek(disk, bitmap_offset, SEEK_SET);
	fwrite(&byte, 1, 1, disk);
	fflush(disk);
}

void mark_block_used(uint32_t block_addr) {
	uint32_t bitnum = block_to_bitnum(block_addr);
	set_bit(bitnum, 1);
}

void mark_block_free(uint32_t block_addr) {
	uint32_t bitnum = block_to_bitnum(block_addr);
	set_bit(bitnum, 0);
}

int is_block_free(uint32_t block_addr) {
	uint32_t bitnum = block_to_bitnum(block_addr);
	return get_bit(bitnum) == 0;
}
