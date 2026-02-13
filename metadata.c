#include "metadata.h"
#include "alloc.h"
#include "files.h"
#include "users.h"
#include "permissions.h"

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
		meta.root_dirent_offset = 0;
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
	
	// Initialize root dirent if it doesn't exist
	if (meta.root_dirent_offset == 0) {
		// Create root dirent
		FileEntry root_entry = {0};
		strncpy(root_entry.name, "/", 31);
		root_entry.size = sizeof(DirentData);
		root_entry.start = alloc(BLOCK_SIZE, 0);
		if (root_entry.start == 0) {
			printf("Error: Failed to allocate space for root dirent.\n");
			fs_unlock();
			return;
		}
		root_entry.type = FILE_TYPE_DIRENT;
		root_entry.owner_uid = 0;  // Root user
		root_entry.owner_gid = 0;
		root_entry.permission = parse_permissions("r-xr-xr-x");  // Read-only
		
		// Allocate space for FileEntry
		uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
		
		if (offset_in_block + sizeof(FileEntry) > BLOCK_SIZE) {
			uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
			if (new_meta_block == 0) {
				fs_free(root_entry.start, BLOCK_SIZE);
				printf("Error: Failed to allocate space for root dirent entry.\n");
				fs_unlock();
				return;
			}
			meta.last_block = new_meta_block;
		}
		
		uint32_t root_offset = meta.last_block;
		meta.last_block += sizeof(FileEntry);
		
		// Write root FileEntry
		fseek(disk, root_offset, SEEK_SET);
		fwrite(&root_entry, sizeof(FileEntry), 1, disk);
		
		// Initialize DirentData
		DirentData root_data = {0};
		fseek(disk, root_entry.start, SEEK_SET);
		fwrite(&root_data, sizeof(DirentData), 1, disk);
		
		// Update metadata
		meta.root_dirent_offset = root_offset;
		fseek(disk, 0, SEEK_SET);
		fwrite(&meta, sizeof(Metadata), 1, disk);
		fflush(disk);
		
		// Migrate existing files from linked list to root dirent if needed
		if (meta.files_head != 0) {
			uint32_t ptr = meta.files_head;
			while (ptr != 0) {
				FileEntry e;
				fseek(disk, ptr, SEEK_SET);
				fread(&e, sizeof(FileEntry), 1, disk);
				
				// Add to root dirent
				dirent_add_child(root_offset, ptr);
				
				uint32_t next = e.next;
				e.next = 0;  // Clear next pointer
				fseek(disk, ptr, SEEK_SET);
				fwrite(&e, sizeof(FileEntry), 1, disk);
				
				ptr = next;
			}
			meta.files_head = 0;  // Clear old linked list
			fseek(disk, 0, SEEK_SET);
			fwrite(&meta, sizeof(Metadata), 1, disk);
			fflush(disk);
		}
	}
	
	if (meta.users_head == 0 && meta.groups_head == 0) {
		meta.files_head = 0;
		meta.users_head = 0;
		meta.groups_head = 0;
		meta.next_uid = 1;
		meta.next_gid = 1;
		if (meta.root_dirent_offset == 0) {
			meta.root_dirent_offset = 0;  // Will be initialized above
		}
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
