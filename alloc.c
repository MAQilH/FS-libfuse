#include "alloc.h"

uint32_t alloc(uint32_t size, int verbose) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("alloc");
	
	if (size == 0) { PROFILE_FUNC_STOP("alloc"); PROFILE_FUNC_END(); return 0; }
	
	uint32_t blocks_needed = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	
	uint32_t start_bit = DATA_START_BLOCK;
	uint32_t consecutive_free = 0;
	uint32_t found_start_bit = 0;
	
	PROFILE_ZONE_N(bitmap_scan);
	for (uint32_t bitnum = start_bit; bitnum < TOTAL_BLOCKS; bitnum++) {
		uint32_t byte_offset = bitnum / 8;
		uint32_t bit_offset = bitnum % 8;
		uint32_t bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + byte_offset;
		
		uint8_t byte;
		fseek(disk, bitmap_offset, SEEK_SET);
		fread(&byte, 1, 1, disk);
		int is_free = ((byte >> bit_offset) & 1) == 0;
		
		if (is_free) {
			if (consecutive_free == 0) {
				found_start_bit = bitnum;
			}
			consecutive_free++;
			
			if (consecutive_free >= blocks_needed) {
				PROFILE_ZONE_END_N(bitmap_scan);
				
				uint32_t allocated_start = bitnum_to_block(found_start_bit);
				
				PROFILE_ZONE_N(mark_blocks);
				for (uint32_t i = 0; i < blocks_needed; i++) {
					uint32_t mark_bitnum = found_start_bit + i;
					uint32_t mark_byte_offset = mark_bitnum / 8;
					uint32_t mark_bit_offset = mark_bitnum % 8;
					uint32_t mark_bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + mark_byte_offset;
					
					uint8_t mark_byte;
					fseek(disk, mark_bitmap_offset, SEEK_SET);
					fread(&mark_byte, 1, 1, disk);
					mark_byte |= (1 << mark_bit_offset);
					fseek(disk, mark_bitmap_offset, SEEK_SET);
					fwrite(&mark_byte, 1, 1, disk);
				}
				PROFILE_ZONE_END_N(mark_blocks);
				
				fflush(disk);
				PROFILE_FUNC_STOP("alloc");
				PROFILE_FUNC_END();
				return allocated_start;
			}
		} else {
			consecutive_free = 0;
		}
	}
	PROFILE_ZONE_END_N(bitmap_scan);
	
	if (verbose) printf("Error: Out of space\n");
	PROFILE_FUNC_STOP("alloc");
	PROFILE_FUNC_END();
	return 0;
}

void fs_free(uint32_t start, uint32_t size) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("fs_free");
	
	if (size == 0) { PROFILE_FUNC_STOP("fs_free"); PROFILE_FUNC_END(); return; }
	
	uint32_t blocks_used = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	uint32_t start_bitnum = block_to_bitnum(start);
	
	for (uint32_t i = 0; i < blocks_used; i++) {
		uint32_t bitnum = start_bitnum + i;
		uint32_t byte_offset = bitnum / 8;
		uint32_t bit_offset = bitnum % 8;
		uint32_t bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + byte_offset;
		
		uint8_t byte;
		fseek(disk, bitmap_offset, SEEK_SET);
		fread(&byte, 1, 1, disk);
		byte &= ~(1 << bit_offset);
		fseek(disk, bitmap_offset, SEEK_SET);
		fwrite(&byte, 1, 1, disk);
	}
	
	fflush(disk);
	PROFILE_FUNC_STOP("fs_free");
	PROFILE_FUNC_END();
}

void freelist_add(uint32_t first, uint32_t last) {
	FreeBlock fb;
	fb.first_block = first;
	fb.last_block = last;
	fb.next = 0;
	
	uint32_t offset = meta.last_block;
	fseek(disk, offset, SEEK_SET);
	fwrite(&fb, sizeof(FreeBlock), 1, disk);
	
	fb.next = meta.freelist_head;
	meta.freelist_head = offset;
	meta.last_block += sizeof(FreeBlock);
	write_metadata();
}

void freelist_remove(uint32_t offset) {
	if (meta.freelist_head == offset) {
		FreeBlock fb;
		fseek(disk, offset, SEEK_SET);
		fread(&fb, sizeof(FreeBlock), 1, disk);
		meta.freelist_head = fb.next;
		write_metadata();
	} else {
		uint32_t ptr = meta.freelist_head;
		while (ptr != 0) {
			FreeBlock fb;
			fseek(disk, ptr, SEEK_SET);
			fread(&fb, sizeof(FreeBlock), 1, disk);
			
			if (fb.next == offset) {
				FreeBlock to_remove;
				fseek(disk, offset, SEEK_SET);
				fread(&to_remove, sizeof(FreeBlock), 1, disk);
				
				fb.next = to_remove.next;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&fb, sizeof(FreeBlock), 1, disk);
				break;
			}
			
			ptr = fb.next;
		}
	}
}

void freelist_print(void) {
	printf("Bitmask Freelist Statistics:\n");
	
	uint32_t total_blocks = TOTAL_BLOCKS;
	uint32_t free_blocks = 0;
	uint32_t used_blocks = 0;
	uint32_t free_ranges = 0;
	uint32_t in_range = 0;
	
	for (uint32_t bitnum = 0; bitnum < total_blocks; bitnum++) {
		if (is_block_free(bitnum_to_block(bitnum))) {
			free_blocks++;
			if (!in_range) {
				free_ranges++;
				in_range = 1;
			}
		} else {
			used_blocks++;
			in_range = 0;
		}
	}
	
	printf("  Total blocks: %u\n", total_blocks);
	printf("  Free blocks: %u (%.2f%%)\n", free_blocks, (free_blocks * 100.0) / total_blocks);
	printf("  Used blocks: %u (%.2f%%)\n", used_blocks, (used_blocks * 100.0) / total_blocks);
	printf("  Free block ranges: %u\n", free_ranges);
	printf("  Block size: %u bytes\n", BLOCK_SIZE);
	printf("  Bitmap location: Block %u\n", BITMAP_BLOCK);
	printf("  Data starts at: Block %u\n", DATA_START_BLOCK);
}
