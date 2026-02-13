#include "stats.h"
#include "files.h"

void fs_stats(void) {
	uint32_t metadata_used = meta.last_block;
	
	uint32_t data_used = 0;
	int count = 0;
	uint32_t ptr = meta.files_head;

	while (ptr != 0 && ptr < FS_SIZE) {
		fseek(disk, ptr, SEEK_SET);
		FileEntry e;
		size_t read_count = fread(&e, sizeof(FileEntry), 1, disk);
		
		if (read_count != 1) break;
		
		data_used += e.size;
		count++;
		ptr = e.next;
	}

	uint32_t used_memory = metadata_used + data_used;
	uint32_t free_memory = FS_SIZE - used_memory;

	printf("FS Stats:\n");
	printf("  Total Size : %d bytes\n", FS_SIZE);
	printf("  Used       : %u bytes (Metadata: %u, Data: %u)\n", used_memory, metadata_used, data_used);
	printf("  Free       : %u bytes\n", free_memory);
	printf("  Files      : %d\n", count);
}

void get_file_stat(void) {
	if (!current_handle.open) {
		printf("No file is currently open.\n");
		return;
	}

	FileEntry *e = &current_handle.entry;
	printf("File: %s\n", e->name);
	printf("  Size: %u bytes\n", e->size);
	printf("  Start: %u\n", e->start);
}
