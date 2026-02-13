#include "metadata.h"
#include "alloc.h"

void read_metadata(void) {
	fs_lock();
	fseek(disk, 0, SEEK_SET);
	fread(&meta, sizeof(Metadata), 1, disk);

	if (meta.magic != MAGIC_NUMBER) {
		printf("No valid filesystem found. Creating new one...\n");
		meta.magic = MAGIC_NUMBER;
		meta.version = 1;
		meta.last_block = sizeof(Metadata);
		meta.data_start = DATA_START_BLOCK * BLOCK_SIZE;
		meta.files_head = 0;
		meta.users_head = 0;
		meta.groups_head = 0;
		meta.next_uid = 1;
		meta.next_gid = 1;
		meta.freelist_head = 0;
		
		uint8_t zero = 0;
		uint32_t bitmap_start = BITMAP_BLOCK * BLOCK_SIZE;
		for (uint32_t i = 0; i < BITMAP_SIZE; i++) {
			fseek(disk, bitmap_start + i, SEEK_SET);
			fwrite(&zero, 1, 1, disk);
		}
		
		mark_block_used(0);
		mark_block_used(BITMAP_BLOCK * BLOCK_SIZE);
		
		fseek(disk, 0, SEEK_SET);
		fwrite(&meta, sizeof(Metadata), 1, disk);
		fflush(disk);
	}
	
	if (meta.users_head == 0 && meta.groups_head == 0) {
		meta.files_head = 0;
		meta.users_head = 0;
		meta.groups_head = 0;
		meta.next_uid = 1;
		meta.next_gid = 1;
		fseek(disk, 0, SEEK_SET);
		fwrite(&meta, sizeof(Metadata), 1, disk);
		fflush(disk);
	}
	fs_unlock();
}

void write_metadata(void) {
	fs_lock();
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	fs_unlock();
}
