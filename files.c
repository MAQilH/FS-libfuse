#include "files.h"

int find_file(const char *name, FileEntry *out, uint32_t *offset_out) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("find_file");
	
	uint32_t ptr = meta.files_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		FileEntry e;
		fread(&e, sizeof(FileEntry), 1, disk);

		if (strcmp(e.name, name) == 0) {
			if (out) *out = e;
			if (offset_out) *offset_out = ptr;
			PROFILE_FUNC_STOP("find_file");
			PROFILE_FUNC_END();
			return 1;
		}

		ptr = e.next;
	}
	PROFILE_FUNC_STOP("find_file");
	PROFILE_FUNC_END();
	return 0;
}

uint32_t append_file_entry(FileEntry *e) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("append_file_entry");
	
	uint32_t current_block = meta.last_block / BLOCK_SIZE;
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(FileEntry) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			printf("Error: Out of space for metadata\n");
			return 0;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t offset = meta.last_block;

	if (meta.files_head == 0) {
		meta.files_head = offset;
	} else {
		PROFILE_ZONE_N(list_traversal);
		uint32_t ptr = meta.files_head;
		while (ptr != 0) {
			FileEntry current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(FileEntry), 1, disk);

			if (current.next == 0) {
				current.next = offset;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(FileEntry), 1, disk);
				fflush(disk);
				break;
			}

			ptr = current.next;
		}
		PROFILE_ZONE_END_N(list_traversal);
	}

	e->next = 0;
	fseek(disk, offset, SEEK_SET);
	fwrite(e, sizeof(FileEntry), 1, disk);

	meta.last_block += sizeof(FileEntry);
	
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	PROFILE_FUNC_STOP("append_file_entry");
	PROFILE_FUNC_END();
	return offset;
}

FSHandle fs_open(const char *name, int flags, int verbose) {
	PROFILE_FUNC_START("fs_open");
	// Use write lock since we may modify filesystem (create file)
	if (fs_lock() != 0) {
		FSHandle h = {0};
		if (verbose) printf("Error: Failed to acquire lock.\n");
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}
	
	FSHandle h;
	h.open = 0;

	if (!session.logged_in) {
		if (verbose) printf("Permission denied: Not logged in.\n");
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}

	FileEntry e;
	uint32_t offset;

	if (find_file(name, &e, &offset)) {
		if (!check_permission(&e, 'r')) {
			if (verbose) printf("Permission denied: No read permission for file '%s'.\n", name);
			fs_unlock();
			PROFILE_FUNC_STOP("fs_open");
			return h;
		}
		
		if ((flags & WRITE) && !check_permission(&e, 'w')) {
			if (verbose) printf("Permission denied: No write permission for file '%s'.\n", name);
			fs_unlock();
			PROFILE_FUNC_STOP("fs_open");
			return h;
		}
		
		h.entry = e;
		h.can_write = (flags & WRITE);
		h.offset_in_fs = offset;
		h.open = 1;
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}

	if (!(flags & CREATE)) {
		if (verbose) printf("File not found and CREATE flag not passed.\n");
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}

	FileEntry newf = {0};
	strncpy(newf.name, name, 31);
	newf.size = 0;
	newf.start = alloc(BLOCK_SIZE, 0);
	newf.next = 0;
	newf.owner_uid = get_current_uid();
	newf.owner_gid = 0;
	newf.permission = parse_permissions("rw-rw-r--");

	User u;
	if (find_user_by_uid(get_current_uid(), &u)) {
		newf.owner_gid = u.gid;
	}

	uint32_t new_offset = append_file_entry(&newf);

	h.entry = newf;
	h.can_write = (flags & WRITE);
	h.offset_in_fs = new_offset;
	h.open = 1;
	fs_unlock();
	PROFILE_FUNC_STOP("fs_open");
	return h;
}

void update_file_entry(FSHandle *h) {
	fseek(disk, h->offset_in_fs, SEEK_SET);
	fwrite(&h->entry, sizeof(FileEntry), 1, disk);
	fflush(disk);
}

int fs_read(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose) {
	PROFILE_FUNC_START("fs_read");
	if (!h->open) { PROFILE_FUNC_STOP("fs_read"); return -1; }
	
	// Use read lock instead of write lock for read operations
	if (fs_lock_read() != 0) {
		if (verbose) printf("Error: Failed to acquire read lock.\n");
		PROFILE_FUNC_STOP("fs_read");
		return -1;
	}
	
	fseek(disk, h->offset_in_fs, SEEK_SET);
	fread(&h->entry, sizeof(FileEntry), 1, disk);
	
	if (!check_permission(&h->entry, 'r')) {
		fs_unlock_read();
		if (verbose) printf("Permission denied: No read permission.\n");
		PROFILE_FUNC_STOP("fs_read");
		return -1;
	}
	
	if (pos >= h->entry.size) {
		fs_unlock_read();
		PROFILE_FUNC_STOP("fs_read");
		return 0;
	}

	uint32_t can_read = h->entry.size - pos;
	if (n > can_read) n = can_read;

	fseek(disk, h->entry.start + pos, SEEK_SET);
	fread(buffer, 1, n, disk);
	
	fs_unlock_read();
	PROFILE_FUNC_STOP("fs_read");
	return n;
}

int fs_write(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose) {
	PROFILE_FUNC_START("fs_write");
	if (!h->open || !h->can_write) { PROFILE_FUNC_STOP("fs_write"); return -1; }
	
	if (fs_lock() != 0) {
		if (verbose) printf("Error: Failed to acquire write lock.\n");
		PROFILE_FUNC_STOP("fs_write");
		return -1;
	}
	
	fseek(disk, h->offset_in_fs, SEEK_SET);
	fread(&h->entry, sizeof(FileEntry), 1, disk);
	
	if (!check_permission(&h->entry, 'w')) {
		fs_unlock();
		if (verbose) printf("Permission denied: No write permission.\n");
		PROFILE_FUNC_STOP("fs_write");
		return -1;
	}

	uint32_t end_pos = pos + n;

	if (h->entry.start < DATA_START_BLOCK * BLOCK_SIZE) {
		fs_unlock();
		if (verbose) printf("Error: File data overlaps with metadata/bitmap (start=%u). File may be corrupted.\n", h->entry.start);
		return -1;
	}

	if (end_pos > h->entry.size) {
		uint32_t old_blocks = (h->entry.size + BLOCK_SIZE - 1) / BLOCK_SIZE;
		if (h->entry.size == 0) old_blocks = 1;
		uint32_t new_blocks = (end_pos + BLOCK_SIZE - 1) / BLOCK_SIZE;
		
		if (new_blocks > old_blocks) {
			uint32_t blocks_needed = new_blocks - old_blocks;
			uint32_t expansion_start_block = block_to_bitnum(h->entry.start) + old_blocks;
			
			int can_expand_in_place = 1;
			for (uint32_t i = 0; i < blocks_needed; i++) {
				if (!is_block_free(bitnum_to_block(expansion_start_block + i))) {
					can_expand_in_place = 0;
					break;
				}
			}
			
			if (can_expand_in_place) {
				for (uint32_t i = 0; i < blocks_needed; i++) {
					mark_block_used(bitnum_to_block(expansion_start_block + i));
				}
				fflush(disk);
			} else {
				uint32_t old_start = h->entry.start;
				uint32_t old_size = h->entry.size > 0 ? h->entry.size : BLOCK_SIZE;
				uint32_t new_start = alloc(end_pos, 0);
				
				if (new_start == 0) {
					fs_unlock();
					if (verbose) printf("Error: Failed to allocate space\n");
					return -1;
				}
				
				if (h->entry.size > 0) {
					uint8_t *temp_buffer = malloc(h->entry.size);
					fseek(disk, old_start, SEEK_SET);
					fread(temp_buffer, 1, h->entry.size, disk);
					fseek(disk, new_start, SEEK_SET);
					fwrite(temp_buffer, 1, h->entry.size, disk);
					free(temp_buffer);
				}
				
				fs_free(old_start, old_size);
				h->entry.start = new_start;
			}
		}
		
		h->entry.size = end_pos;
		update_file_entry(h);
	}

	fseek(disk, h->entry.start + pos, SEEK_SET);
	
	fwrite(buffer, 1, n, disk);
	fflush(disk);
	
	fs_unlock();
	PROFILE_FUNC_STOP("fs_write");
	return n;
}

void fs_shrink(FSHandle *h, uint32_t new_size, int verbose) {
	if (!h->open || !h->can_write) return;
	
	// FIXED: Acquire lock before modifying file (was missing!)
	if (fs_lock() != 0) {
		if (verbose) printf("Error: Failed to acquire lock for shrink operation.\n");
		return;
	}
	
	fseek(disk, h->offset_in_fs, SEEK_SET);
	fread(&h->entry, sizeof(FileEntry), 1, disk);
	
	if (!check_permission(&h->entry, 'w')) {
		fs_unlock();
		if (verbose) printf("Permission denied: No write permission.\n");
		return;
	}

	if (new_size < h->entry.size) {
		uint32_t old_blocks = (h->entry.size + BLOCK_SIZE - 1) / BLOCK_SIZE;
		uint32_t new_blocks = (new_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
		if (new_size == 0) new_blocks = 1;
		
		if (new_blocks < old_blocks) {
			uint32_t freed_start = h->entry.start + (new_blocks * BLOCK_SIZE);
			uint32_t freed_size = (old_blocks - new_blocks) * BLOCK_SIZE;
			fs_free(freed_start, freed_size);
		}
		
		h->entry.size = new_size;
		update_file_entry(h);
	}
	
	fs_unlock();
}

void fs_rm(const char *name, int verbose) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("fs_rm");
	
	if (fs_lock() != 0) {
		if (verbose) printf("Error: Failed to acquire lock for delete operation.\n");
		PROFILE_FUNC_STOP("fs_rm");
		PROFILE_FUNC_END();
		return;
	}
	
	if (!session.logged_in) {
		fs_unlock();
		if (verbose) printf("Permission denied: Not logged in.\n");
		PROFILE_FUNC_STOP("fs_rm");
		PROFILE_FUNC_END();
		return;
	}
	
	uint32_t ptr = meta.files_head;
	uint32_t prev = 0;

	PROFILE_ZONE_N(find_and_unlink);
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		FileEntry e;
		fread(&e, sizeof(FileEntry), 1, disk);

		if (strcmp(e.name, name) == 0) {
			PROFILE_ZONE_END_N(find_and_unlink);
			
			int can_delete = is_root() || (e.owner_uid == get_current_uid());
			
			if (!can_delete) {
				fs_unlock();
				if (verbose) printf("Permission denied: You are not the owner of file '%s'.\n", name);
				PROFILE_FUNC_STOP("fs_rm");
				PROFILE_FUNC_END();
				return;
			}
			
			if (prev == 0) {
				meta.files_head = e.next;
			} else {
				FileEntry prevE;
				fseek(disk, prev, SEEK_SET);
				fread(&prevE, sizeof(FileEntry), 1, disk);
				prevE.next = e.next;
				fseek(disk, prev, SEEK_SET);
				fwrite(&prevE, sizeof(FileEntry), 1, disk);
				fflush(disk);
			}
			
			fseek(disk, 0, SEEK_SET);
			fwrite(&meta, sizeof(Metadata), 1, disk);
			fflush(disk);
			
			uint32_t size = e.size > 0 ? e.size : BLOCK_SIZE;
			fs_free(e.start, size);
			
			fs_unlock();
			if (verbose) printf("Deleted file '%s' and freed %u bytes\n", name, size);
			PROFILE_FUNC_STOP("fs_rm");
			PROFILE_FUNC_END();
			return;
		}

		prev = ptr;
		ptr = e.next;
	}
	PROFILE_ZONE_END_N(find_and_unlink);
	
	fs_unlock();
	if (verbose) printf("File '%s' not found.\n", name);
	PROFILE_FUNC_STOP("fs_rm");
	PROFILE_FUNC_END();
}

void fs_close(FSHandle *h) {
	h->open = 0;
}

// Wrapper functions for compatibility
FSHandle fs_open_impl(const char *name, int flags, int verbose) { 
	return fs_open(name, flags, verbose); 
}

int fs_read_impl(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose) { 
	return fs_read(h, pos, n, buffer, verbose); 
}

int fs_write_impl(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose) { 
	return fs_write(h, pos, n, buffer, verbose); 
}

void fs_rm_impl(const char *name, int verbose) { 
	fs_rm(name, verbose); 
}

void fs_shrink_impl(FSHandle *h, uint32_t new_size, int verbose) { 
	fs_shrink(h, new_size, verbose); 
}
