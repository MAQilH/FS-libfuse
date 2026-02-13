#include "files.h"

int find_file(const char *name, FileEntry *out, uint32_t *offset_out) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("find_file");
	
	// Use path resolution for backward compatibility with tests
	// Simple filenames are treated as relative paths from root
	extern uint32_t cwd_offset;
	uint32_t search_cwd = (cwd_offset != 0) ? cwd_offset : meta.root_dirent_offset;
	
	// If name contains '/', treat as path, otherwise treat as filename in root
	if (strchr(name, '/') != NULL) {
		// It's a path, use path resolution
		uint32_t offset;
		FileEntry entry;
		if (resolve_path(name, search_cwd, &offset, &entry, NULL)) {
			if (out) *out = entry;
			if (offset_out) *offset_out = offset;
			PROFILE_FUNC_STOP("find_file");
			PROFILE_FUNC_END();
			return 1;
		}
	} else {
		// Simple filename - search in root dirent
		if (meta.root_dirent_offset == 0) {
			PROFILE_FUNC_STOP("find_file");
			PROFILE_FUNC_END();
			return 0;
		}
		
		DirentData root_data;
		if (read_dirent(meta.root_dirent_offset, &root_data)) {
			for (uint32_t i = 0; i < root_data.child_count; i++) {
				FileEntry e;
				fseek(disk, root_data.children[i], SEEK_SET);
				fread(&e, sizeof(FileEntry), 1, disk);
				
				if (strcmp(e.name, name) == 0) {
					if (out) *out = e;
					if (offset_out) *offset_out = root_data.children[i];
					PROFILE_FUNC_STOP("find_file");
					PROFILE_FUNC_END();
					return 1;
				}
			}
		}
	}
	
	PROFILE_FUNC_STOP("find_file");
	PROFILE_FUNC_END();
	return 0;
}

uint32_t append_file_entry(FileEntry *e) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("append_file_entry");
	
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

	// Use cwd_offset from global (will be set in main.c)
	extern uint32_t cwd_offset;
	uint32_t current_cwd = cwd_offset;
	if (current_cwd == 0) {
		current_cwd = meta.root_dirent_offset;
	}

	FileEntry e;
	uint32_t offset;
	uint32_t parent_offset;

	// Try to resolve path
	if (resolve_path(name, current_cwd, &offset, &e, &parent_offset)) {
		// Check if it's a dirent (read-only)
		if (is_dirent(&e)) {
			if (flags & WRITE) {
				if (verbose) printf("Error: Dirents are read-only.\n");
				fs_unlock();
				PROFILE_FUNC_STOP("fs_open");
				return h;
			}
		}
		
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

	// Extract filename from path
	const char *filename = name;
	const char *last_slash = strrchr(name, '/');
	if (last_slash != NULL) {
		filename = last_slash + 1;
	}
	
	// Resolve parent directory
	// resolve_path will set parent_offset even if file doesn't exist (when component not found)
	parent_offset = 0;
	if (!resolve_path(name, current_cwd, NULL, NULL, &parent_offset)) {
		// Path doesn't exist - check if parent_offset was set by resolve_path
		if (parent_offset == 0) {
			// Parent not set, try to resolve parent manually
			char parent_path[256];
			strncpy(parent_path, name, 255);
			parent_path[255] = '\0';
			char *last_slash2 = strrchr(parent_path, '/');
			if (last_slash2 != NULL) {
				*last_slash2 = '\0';
				if (strlen(parent_path) == 0) {
					parent_path[0] = '/';
					parent_path[1] = '\0';
				}
				if (!resolve_path(parent_path, current_cwd, NULL, NULL, &parent_offset)) {
					if (verbose) printf("Error: Parent directory not found.\n");
					fs_unlock();
					PROFILE_FUNC_STOP("fs_open");
					return h;
				}
			} else {
				// No slash, use cwd as parent
				parent_offset = current_cwd;
			}
		}
		// else: parent_offset was already set by resolve_path when component not found
	} else {
		// File exists - extract parent from path for creation case
		// (This shouldn't happen if CREATE flag is set, but handle it)
		char parent_path[256];
		strncpy(parent_path, name, 255);
		parent_path[255] = '\0';
		char *last_slash2 = strrchr(parent_path, '/');
		if (last_slash2 != NULL) {
			*last_slash2 = '\0';
			if (strlen(parent_path) == 0) {
				parent_path[0] = '/';
				parent_path[1] = '\0';
			}
			if (!resolve_path(parent_path, current_cwd, NULL, NULL, &parent_offset)) {
				parent_offset = current_cwd;  // Fallback to cwd
			}
		} else {
			parent_offset = current_cwd;
		}
	}
	
	// Verify parent is a dirent
	FileEntry parent_entry;
	fseek(disk, parent_offset, SEEK_SET);
	fread(&parent_entry, sizeof(FileEntry), 1, disk);
	if (!is_dirent(&parent_entry)) {
		if (verbose) printf("Error: Parent is not a directory.\n");
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}

	FileEntry newf = {0};
	strncpy(newf.name, filename, 31);
	newf.size = 0;
	newf.start = alloc(BLOCK_SIZE, 0);
	if (newf.start == 0) {
		if (verbose) printf("Error: Failed to allocate space.\n");
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}
	newf.type = FILE_TYPE_REGULAR;
	newf.next = 0;  // Not used anymore, but keep for compatibility
	newf.owner_uid = get_current_uid();
	newf.owner_gid = 0;
	newf.permission = parse_permissions("rw-rw-r--");

	User u;
	if (find_user_by_uid(get_current_uid(), &u)) {
		newf.owner_gid = u.gid;
	}

	// Allocate space for FileEntry
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(FileEntry) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			fs_free(newf.start, BLOCK_SIZE);
			if (verbose) printf("Error: Out of space for metadata\n");
			fs_unlock();
			PROFILE_FUNC_STOP("fs_open");
			return h;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t new_offset = meta.last_block;
	meta.last_block += sizeof(FileEntry);
	
	// Write FileEntry
	fseek(disk, new_offset, SEEK_SET);
	fwrite(&newf, sizeof(FileEntry), 1, disk);
	
	// Update metadata
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	// Add to parent dirent
	if (!dirent_add_child(parent_offset, new_offset)) {
		if (verbose) printf("Error: Failed to add file to directory.\n");
		fs_free(newf.start, BLOCK_SIZE);
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}

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
	
	// Prevent writes to dirents
	if (is_dirent(&h->entry)) {
		fs_unlock();
		if (verbose) printf("Error: Dirents are read-only.\n");
		PROFILE_FUNC_STOP("fs_write");
		return -1;
	}
	
	if (!check_permission(&h->entry, 'w')) {
		fs_unlock();
		if (verbose) printf("Permission denied: No write permission.\n");
		PROFILE_FUNC_STOP("fs_write");
		return -1;
	}

	uint32_t end_pos = pos + n;

	// Validate that the write doesn't cause overflow
	if (end_pos < pos) {
		fs_unlock();
		if (verbose) printf("Error: Write position (%u) + size (%u) causes integer overflow.\n", pos, n);
		PROFILE_FUNC_STOP("fs_write");
		return -1;
	}

	if (h->entry.start < DATA_START_BLOCK * BLOCK_SIZE) {
		fs_unlock();
		if (verbose) printf("Error: File data overlaps with metadata/bitmap (start=%u). File may be corrupted.\n", h->entry.start);
		return -1;
	}

	if (end_pos > h->entry.size) {
		uint32_t old_blocks = (h->entry.size + BLOCK_SIZE - 1) / BLOCK_SIZE;
		if (h->entry.size == 0) old_blocks = 1;
		uint32_t new_blocks = (end_pos + BLOCK_SIZE - 1) / BLOCK_SIZE;
		
		// Check if the required blocks exceed available space
		uint32_t max_available_blocks = (FS_SIZE - DATA_START_BLOCK * BLOCK_SIZE) / BLOCK_SIZE;
		if (new_blocks > max_available_blocks) {
			fs_unlock();
			if (verbose) printf("Error: File size would exceed filesystem capacity. Requested: %u blocks, Available: %u blocks.\n", 
				new_blocks, max_available_blocks);
			PROFILE_FUNC_STOP("fs_write");
			return -1;
		}
		
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
				uint32_t old_allocated_size = old_blocks * BLOCK_SIZE;
				uint32_t new_allocated_size = new_blocks * BLOCK_SIZE;
				uint32_t new_start = alloc(new_allocated_size, 0);
				
				if (new_start == 0) {
					fs_unlock();
					if (verbose) printf("Error: Failed to allocate %u bytes (%u blocks)\n", new_allocated_size, new_blocks);
					return -1;
				}
				
				// Copy existing data
				if (h->entry.size > 0) {
					uint8_t *temp_buffer = malloc(h->entry.size);
					if (temp_buffer == NULL) {
						fs_free(new_start, new_allocated_size);
						fs_unlock();
						if (verbose) printf("Error: Failed to allocate memory for copy\n");
						return -1;
					}
					fseek(disk, old_start, SEEK_SET);
					fread(temp_buffer, 1, h->entry.size, disk);
					fseek(disk, new_start, SEEK_SET);
					fwrite(temp_buffer, 1, h->entry.size, disk);
					free(temp_buffer);
				}
				
				// Free old allocation (all blocks that were allocated)
				fs_free(old_start, old_allocated_size);
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
	
	// Prevent writes to dirents
	if (is_dirent(&h->entry)) {
		fs_unlock();
		if (verbose) printf("Error: Dirents are read-only.\n");
		return;
	}
	
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
	
	// Use cwd_offset from global
	extern uint32_t cwd_offset;
	uint32_t current_cwd = cwd_offset;
	if (current_cwd == 0) {
		current_cwd = meta.root_dirent_offset;
	}
	
	FileEntry e;
	uint32_t offset;
	uint32_t parent_offset;
	
	PROFILE_ZONE_N(find_and_unlink);
	if (!resolve_path(name, current_cwd, &offset, &e, &parent_offset)) {
		PROFILE_ZONE_END_N(find_and_unlink);
		fs_unlock();
		if (verbose) printf("File '%s' not found.\n", name);
		PROFILE_FUNC_STOP("fs_rm");
		PROFILE_FUNC_END();
		return;
	}
	PROFILE_ZONE_END_N(find_and_unlink);
	
	// Check if it's a dirent and if it's empty
	if (is_dirent(&e)) {
		DirentData data;
		if (read_dirent(offset, &data) && data.child_count > 0) {
			fs_unlock();
			if (verbose) printf("Error: Cannot delete non-empty directory '%s'.\n", name);
			PROFILE_FUNC_STOP("fs_rm");
			PROFILE_FUNC_END();
			return;
		}
	}
	
	int can_delete = is_root() || (e.owner_uid == get_current_uid());
	
	if (!can_delete) {
		fs_unlock();
		if (verbose) printf("Permission denied: You are not the owner of file '%s'.\n", name);
		PROFILE_FUNC_STOP("fs_rm");
		PROFILE_FUNC_END();
		return;
	}
	
	// Remove from parent dirent
	if (parent_offset != 0) {
		if (!dirent_remove_child(parent_offset, offset)) {
			fs_unlock();
			if (verbose) printf("Error: Failed to remove file from directory.\n");
			PROFILE_FUNC_STOP("fs_rm");
			PROFILE_FUNC_END();
			return;
		}
	}
	
	// Free file data
	uint32_t size = e.size > 0 ? e.size : BLOCK_SIZE;
	if (is_dirent(&e)) {
		// For dirents, free the DirentData block
		fs_free(e.start, BLOCK_SIZE);
	} else {
		fs_free(e.start, size);
	}
	
	fs_unlock();
	if (verbose) printf("Deleted file '%s' and freed %u bytes\n", name, size);
	PROFILE_FUNC_STOP("fs_rm");
	PROFILE_FUNC_END();
}

void fs_close(FSHandle *h) {
	h->open = 0;
}

// Dirent operations
int is_dirent(FileEntry *e) {
	return e->type == FILE_TYPE_DIRENT;
}

int read_dirent(uint32_t dirent_offset, DirentData *out) {
	FileEntry e;
	fseek(disk, dirent_offset, SEEK_SET);
	fread(&e, sizeof(FileEntry), 1, disk);
	
	if (!is_dirent(&e)) {
		return 0;
	}
	
	fseek(disk, e.start, SEEK_SET);
	fread(out, sizeof(DirentData), 1, disk);
	return 1;
}

int dirent_add_child(uint32_t dirent_offset, uint32_t child_offset) {
	FileEntry e;
	fseek(disk, dirent_offset, SEEK_SET);
	fread(&e, sizeof(FileEntry), 1, disk);
	
	if (!is_dirent(&e)) {
		return 0;
	}
	
	DirentData data;
	fseek(disk, e.start, SEEK_SET);
	fread(&data, sizeof(DirentData), 1, disk);
	
	if (data.child_count >= MAX_DIRENT_CHILDREN) {
		return 0;  // Dirent is full
	}
	
	// Check if child already exists
	for (uint32_t i = 0; i < data.child_count; i++) {
		if (data.children[i] == child_offset) {
			return 0;  // Already exists
		}
	}
	
	data.children[data.child_count] = child_offset;
	data.child_count++;
	
	fseek(disk, e.start, SEEK_SET);
	fwrite(&data, sizeof(DirentData), 1, disk);
	fflush(disk);
	return 1;
}

int dirent_remove_child(uint32_t dirent_offset, uint32_t child_offset) {
	FileEntry e;
	fseek(disk, dirent_offset, SEEK_SET);
	fread(&e, sizeof(FileEntry), 1, disk);
	
	if (!is_dirent(&e)) {
		return 0;
	}
	
	DirentData data;
	fseek(disk, e.start, SEEK_SET);
	fread(&data, sizeof(DirentData), 1, disk);
	
	int found = 0;
	for (uint32_t i = 0; i < data.child_count; i++) {
		if (data.children[i] == child_offset) {
			// Shift remaining children left
			for (uint32_t j = i; j < data.child_count - 1; j++) {
				data.children[j] = data.children[j + 1];
			}
			data.child_count--;
			found = 1;
			break;
		}
	}
	
	if (!found) {
		return 0;
	}
	
	fseek(disk, e.start, SEEK_SET);
	fwrite(&data, sizeof(DirentData), 1, disk);
	fflush(disk);
	return 1;
}

uint32_t create_dirent(const char *name, uint32_t parent_offset) {
	FileEntry new_dirent = {0};
	strncpy(new_dirent.name, name, 31);
	new_dirent.size = sizeof(DirentData);
	new_dirent.start = alloc(BLOCK_SIZE, 0);
	if (new_dirent.start == 0) {
		return 0;
	}
	new_dirent.type = FILE_TYPE_DIRENT;
	new_dirent.owner_uid = get_current_uid();
	new_dirent.owner_gid = 0;
	new_dirent.permission = parse_permissions("r-xr-xr-x");  // Read-only for dirents
	
	User u;
	if (find_user_by_uid(get_current_uid(), &u)) {
		new_dirent.owner_gid = u.gid;
	}
	
	// Allocate space for FileEntry
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(FileEntry) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			fs_free(new_dirent.start, BLOCK_SIZE);
			return 0;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t dirent_entry_offset = meta.last_block;
	meta.last_block += sizeof(FileEntry);
	
	// Write FileEntry
	fseek(disk, dirent_entry_offset, SEEK_SET);
	fwrite(&new_dirent, sizeof(FileEntry), 1, disk);
	
	// Initialize DirentData
	DirentData data = {0};
	fseek(disk, new_dirent.start, SEEK_SET);
	fwrite(&data, sizeof(DirentData), 1, disk);
	
	// Update metadata
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	// Add to parent dirent
	if (parent_offset != 0) {
		dirent_add_child(parent_offset, dirent_entry_offset);
	}
	
	return dirent_entry_offset;
}

// Forward declaration
static uint32_t find_parent_dirent(uint32_t child_offset);

// Path resolution functions
int resolve_absolute_path(const char *path, uint32_t *out_offset, FileEntry *out_entry, uint32_t *parent_offset) {
	if (path[0] != '/') {
		return 0;  // Not an absolute path
	}
	
	if (meta.root_dirent_offset == 0) {
		return 0;  // Root not initialized
	}
	
	// Handle root path "/"
	if (strlen(path) == 1 || (strlen(path) == 2 && path[1] == '\0')) {
		fseek(disk, meta.root_dirent_offset, SEEK_SET);
		fread(out_entry, sizeof(FileEntry), 1, disk);
		if (out_offset) *out_offset = meta.root_dirent_offset;
		if (parent_offset) *parent_offset = 0;  // Root has no parent
		return 1;
	}
	
	// Start from root
	uint32_t current_offset = meta.root_dirent_offset;
	FileEntry current;
	fseek(disk, current_offset, SEEK_SET);
	fread(&current, sizeof(FileEntry), 1, disk);
	
	uint32_t prev_offset = 0;  // Root's parent is 0
	
	// Skip leading '/'
	const char *component = path + 1;
	char path_copy[256];
	strncpy(path_copy, component, 255);
	path_copy[255] = '\0';
	
	// Split path into components
	char *saveptr;
	char *token = strtok_r(path_copy, "/", &saveptr);
	
	while (token != NULL) {
		if (strcmp(token, ".") == 0) {
			// Stay in current directory
			token = strtok_r(NULL, "/", &saveptr);
			continue;
		}
		
		if (strcmp(token, "..") == 0) {
			// Go up one level
			if (current_offset == meta.root_dirent_offset) {
				// Already at root, stay at root
				token = strtok_r(NULL, "/", &saveptr);
				continue;
			}
			current_offset = prev_offset;
			if (current_offset == 0) {
				current_offset = meta.root_dirent_offset;
			}
			fseek(disk, current_offset, SEEK_SET);
			fread(&current, sizeof(FileEntry), 1, disk);
			prev_offset = find_parent_dirent(current_offset);
			token = strtok_r(NULL, "/", &saveptr);
			continue;
		}
		
		if (!is_dirent(&current)) {
			return 0;  // Not a directory
		}
		
		DirentData data;
		if (!read_dirent(current_offset, &data)) {
			return 0;
		}
		
		// Search for component in current dirent
		uint32_t found = 0;
		for (uint32_t i = 0; i < data.child_count; i++) {
			FileEntry child;
			fseek(disk, data.children[i], SEEK_SET);
			fread(&child, sizeof(FileEntry), 1, disk);
			
			if (strcmp(child.name, token) == 0) {
				prev_offset = current_offset;
				current_offset = data.children[i];
				current = child;
				found = 1;
				break;
			}
		}
		
		if (!found) {
			// Component not found - return parent if requested
			if (parent_offset) {
				*parent_offset = current_offset;
			}
			return 0;
		}
		
		token = strtok_r(NULL, "/", &saveptr);
	}
	
	// Found the target
	if (out_offset) *out_offset = current_offset;
	if (out_entry) *out_entry = current;
	if (parent_offset) *parent_offset = prev_offset;
	
	return 1;
}

// Helper function to find parent of a dirent by searching all dirents
static uint32_t find_parent_dirent(uint32_t child_offset) {
	if (child_offset == meta.root_dirent_offset) {
		return 0;  // Root has no parent
	}
	
	// Search all dirents for one that contains this child
	// Start from root and traverse recursively
	uint32_t stack[64];
	uint32_t stack_ptr = 0;
	stack[stack_ptr++] = meta.root_dirent_offset;
	
	while (stack_ptr > 0) {
		uint32_t current = stack[--stack_ptr];
		DirentData data;
		if (!read_dirent(current, &data)) continue;
		
		for (uint32_t i = 0; i < data.child_count; i++) {
			if (data.children[i] == child_offset) {
				return current;
			}
			// Check if child is a dirent and add to stack
			FileEntry child;
			fseek(disk, data.children[i], SEEK_SET);
			fread(&child, sizeof(FileEntry), 1, disk);
			if (is_dirent(&child) && stack_ptr < 64) {
				stack[stack_ptr++] = data.children[i];
			}
		}
	}
	
	return 0;
}

int resolve_relative_path(const char *path, uint32_t cwd_offset, uint32_t *out_offset, FileEntry *out_entry, uint32_t *parent_offset) {
	if (path[0] == '/') {
		return resolve_absolute_path(path, out_offset, out_entry, parent_offset);
	}
	
	if (cwd_offset == 0) {
		cwd_offset = meta.root_dirent_offset;
	}
	
	FileEntry cwd;
	fseek(disk, cwd_offset, SEEK_SET);
	fread(&cwd, sizeof(FileEntry), 1, disk);
	
	if (!is_dirent(&cwd)) {
		return 0;
	}
	
	// Handle "." and ".."
	if (strcmp(path, ".") == 0) {
		if (out_offset) *out_offset = cwd_offset;
		if (out_entry) *out_entry = cwd;
		if (parent_offset) *parent_offset = find_parent_dirent(cwd_offset);
		return 1;
	}
	
	if (strcmp(path, "..") == 0) {
		uint32_t parent = find_parent_dirent(cwd_offset);
		if (parent == 0) {
			// Already at root
			if (out_offset) *out_offset = meta.root_dirent_offset;
			fseek(disk, meta.root_dirent_offset, SEEK_SET);
			fread(out_entry, sizeof(FileEntry), 1, disk);
			if (parent_offset) *parent_offset = 0;
			return 1;
		}
		FileEntry parent_entry;
		fseek(disk, parent, SEEK_SET);
		fread(&parent_entry, sizeof(FileEntry), 1, disk);
		if (out_offset) *out_offset = parent;
		if (out_entry) *out_entry = parent_entry;
		if (parent_offset) *parent_offset = find_parent_dirent(parent);
		return 1;
	}
	
	// Handle multi-component paths
	char path_copy[256];
	strncpy(path_copy, path, 255);
	path_copy[255] = '\0';
	
	char *saveptr;
	char *token = strtok_r(path_copy, "/", &saveptr);
	
	uint32_t current_offset = cwd_offset;
	FileEntry current = cwd;
	uint32_t prev_offset = cwd_offset;
	
	while (token != NULL) {
		if (strcmp(token, ".") == 0) {
			// Stay in current directory
			token = strtok_r(NULL, "/", &saveptr);
			continue;
		}
		
		if (strcmp(token, "..") == 0) {
			// Go up one level
			prev_offset = current_offset;
			current_offset = find_parent_dirent(current_offset);
			if (current_offset == 0) {
				current_offset = meta.root_dirent_offset;
			}
			fseek(disk, current_offset, SEEK_SET);
			fread(&current, sizeof(FileEntry), 1, disk);
			token = strtok_r(NULL, "/", &saveptr);
			continue;
		}
		
		if (!is_dirent(&current)) {
			return 0;  // Not a directory
		}
		
		DirentData data;
		if (!read_dirent(current_offset, &data)) {
			return 0;
		}
		
		// Search for component in current dirent
		uint32_t found = 0;
		for (uint32_t i = 0; i < data.child_count; i++) {
			FileEntry child;
			fseek(disk, data.children[i], SEEK_SET);
			fread(&child, sizeof(FileEntry), 1, disk);
			
			if (strcmp(child.name, token) == 0) {
				prev_offset = current_offset;
				current_offset = data.children[i];
				current = child;
				found = 1;
				break;
			}
		}
		
		if (!found) {
			// Component not found - return parent if this is for creation
			if (parent_offset) {
				*parent_offset = current_offset;
			}
			return 0;
		}
		
		token = strtok_r(NULL, "/", &saveptr);
	}
	
	// Found the target
	if (out_offset) *out_offset = current_offset;
	if (out_entry) *out_entry = current;
	if (parent_offset) *parent_offset = prev_offset;
	
	return 1;
}

int resolve_path(const char *path, uint32_t cwd_offset, uint32_t *out_offset, FileEntry *out_entry, uint32_t *parent_offset) {
	if (path[0] == '/') {
		return resolve_absolute_path(path, out_offset, out_entry, parent_offset);
	} else {
		return resolve_relative_path(path, cwd_offset, out_offset, out_entry, parent_offset);
	}
}

int find_file_by_path(const char *path, uint32_t cwd_offset, FileEntry *out, uint32_t *offset_out) {
	uint32_t offset;
	FileEntry entry;
	
	if (resolve_path(path, cwd_offset, &offset, &entry, NULL)) {
		if (out) *out = entry;
		if (offset_out) *offset_out = offset;
		return 1;
	}
	
	return 0;
}

int fs_cp(const char *src_path, const char *dst_path, uint32_t cwd_offset, int verbose) {
	if (fs_lock() != 0) {
		if (verbose) printf("Error: Failed to acquire lock.\n");
		return 0;
	}
	
	if (!session.logged_in) {
		fs_unlock();
		if (verbose) printf("Permission denied: Not logged in.\n");
		return 0;
	}
	
	// Resolve source file
	FileEntry src_entry;
	uint32_t src_offset;
	uint32_t src_parent;
	
	if (!resolve_path(src_path, cwd_offset, &src_offset, &src_entry, &src_parent)) {
		fs_unlock();
		if (verbose) printf("Error: Source file '%s' not found.\n", src_path);
		return 0;
	}
	
	// Cannot copy dirents
	if (is_dirent(&src_entry)) {
		fs_unlock();
		if (verbose) printf("Error: Cannot copy directories.\n");
		return 0;
	}
	
	// Check read permission
	if (!check_permission(&src_entry, 'r')) {
		fs_unlock();
		if (verbose) printf("Permission denied: No read permission for source file.\n");
		return 0;
	}
	
	// Resolve destination
	FileEntry dst_entry;
	uint32_t dst_offset;
	uint32_t dst_parent;
	const char *dst_filename;
	
	// Check if destination exists
	if (resolve_path(dst_path, cwd_offset, &dst_offset, &dst_entry, &dst_parent)) {
		if (is_dirent(&dst_entry)) {
			// Destination is a directory, use source filename
			const char *last_slash = strrchr(src_path, '/');
			dst_filename = last_slash ? last_slash + 1 : src_path;
			dst_parent = dst_offset;
		} else {
			// Destination is a file, overwrite it
			const char *last_slash = strrchr(dst_path, '/');
			dst_filename = last_slash ? last_slash + 1 : dst_path;
			// dst_parent is already set by resolve_path
			// Remove existing file first
			if (dst_parent != 0) {
				dirent_remove_child(dst_parent, dst_offset);
			}
			fs_free(dst_entry.start, dst_entry.size > 0 ? dst_entry.size : BLOCK_SIZE);
		}
	} else {
		// Destination doesn't exist, extract parent and filename
		const char *last_slash = strrchr(dst_path, '/');
		if (last_slash != NULL) {
			char parent_path[256];
			strncpy(parent_path, dst_path, last_slash - dst_path);
			parent_path[last_slash - dst_path] = '\0';
			if (strlen(parent_path) == 0) {
				parent_path[0] = '/';
				parent_path[1] = '\0';
			}
			if (!resolve_path(parent_path, cwd_offset, &dst_parent, &dst_entry, NULL)) {
				fs_unlock();
				if (verbose) printf("Error: Destination directory not found.\n");
				return 0;
			}
			if (!is_dirent(&dst_entry)) {
				fs_unlock();
				if (verbose) printf("Error: Destination parent is not a directory.\n");
				return 0;
			}
			dst_filename = last_slash + 1;
		} else {
			// No slash, use cwd as parent
			dst_parent = cwd_offset;
			dst_filename = dst_path;
		}
	}
	
	// Read source file data
	uint8_t *src_data = malloc(src_entry.size);
	if (src_entry.size > 0) {
		fseek(disk, src_entry.start, SEEK_SET);
		fread(src_data, 1, src_entry.size, disk);
	}
	
	// Create new file
	FileEntry new_file = {0};
	strncpy(new_file.name, dst_filename, 31);
	new_file.size = src_entry.size;
	// Allocate enough blocks to hold the file
	uint32_t blocks_needed = (src_entry.size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	if (blocks_needed == 0) blocks_needed = 1;
	uint32_t alloc_size = blocks_needed * BLOCK_SIZE;
	new_file.start = alloc(alloc_size, 0);
	if (new_file.start == 0) {
		free(src_data);
		fs_unlock();
		if (verbose) printf("Error: Failed to allocate space for copy.\n");
		return 0;
	}
	new_file.type = FILE_TYPE_REGULAR;
	new_file.owner_uid = get_current_uid();
	new_file.owner_gid = src_entry.owner_gid;
	new_file.permission = src_entry.permission;
	
	User u;
	if (find_user_by_uid(get_current_uid(), &u)) {
		new_file.owner_gid = u.gid;
	}
	
	// Allocate space for FileEntry
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(FileEntry) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			fs_free(new_file.start, new_file.size > 0 ? new_file.size : BLOCK_SIZE);
			free(src_data);
			fs_unlock();
			if (verbose) printf("Error: Out of space for metadata\n");
			return 0;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t new_offset = meta.last_block;
	meta.last_block += sizeof(FileEntry);
	
	// Write FileEntry
	fseek(disk, new_offset, SEEK_SET);
	fwrite(&new_file, sizeof(FileEntry), 1, disk);
	
	// Write file data
	if (src_entry.size > 0) {
		fseek(disk, new_file.start, SEEK_SET);
		fwrite(src_data, 1, src_entry.size, disk);
	}
	
	free(src_data);
	
	// Update metadata
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	// Add to destination dirent
	if (!dirent_add_child(dst_parent, new_offset)) {
		fs_free(new_file.start, new_file.size > 0 ? new_file.size : BLOCK_SIZE);
		fs_unlock();
		if (verbose) printf("Error: Failed to add file to destination directory.\n");
		return 0;
	}
	
	fs_unlock();
	if (verbose) printf("Copied '%s' to '%s'\n", src_path, dst_path);
	return 1;
}

int fs_mv(const char *src_path, const char *dst_path, uint32_t cwd_offset, int verbose) {
	if (fs_lock() != 0) {
		if (verbose) printf("Error: Failed to acquire lock.\n");
		return 0;
	}
	
	if (!session.logged_in) {
		fs_unlock();
		if (verbose) printf("Permission denied: Not logged in.\n");
		return 0;
	}
	
	// Resolve source file
	FileEntry src_entry;
	uint32_t src_offset;
	uint32_t src_parent;
	
	if (!resolve_path(src_path, cwd_offset, &src_offset, &src_entry, &src_parent)) {
		fs_unlock();
		if (verbose) printf("Error: Source file '%s' not found.\n", src_path);
		return 0;
	}
	
	// Check permissions
	int can_move = is_root() || (src_entry.owner_uid == get_current_uid());
	if (!can_move) {
		fs_unlock();
		if (verbose) printf("Permission denied: You are not the owner of source file.\n");
		return 0;
	}
	
	// Resolve destination
	FileEntry dst_entry;
	uint32_t dst_offset;
	uint32_t dst_parent;
	const char *dst_filename;
	
	// Check if destination exists
	if (resolve_path(dst_path, cwd_offset, &dst_offset, &dst_entry, &dst_parent)) {
		if (is_dirent(&dst_entry)) {
			// Destination is a directory, use source filename
			const char *last_slash = strrchr(src_path, '/');
			dst_filename = last_slash ? last_slash + 1 : src_path;
			dst_parent = dst_offset;
		} else {
			// Destination is a file, cannot overwrite (or remove it first)
			fs_unlock();
			if (verbose) printf("Error: Destination file already exists.\n");
			return 0;
		}
	} else {
		// Destination doesn't exist, extract parent and filename
		const char *last_slash = strrchr(dst_path, '/');
		if (last_slash != NULL) {
			char parent_path[256];
			strncpy(parent_path, dst_path, last_slash - dst_path);
			parent_path[last_slash - dst_path] = '\0';
			if (strlen(parent_path) == 0) {
				parent_path[0] = '/';
				parent_path[1] = '\0';
			}
			if (!resolve_path(parent_path, cwd_offset, &dst_parent, &dst_entry, NULL)) {
				fs_unlock();
				if (verbose) printf("Error: Destination directory not found.\n");
				return 0;
			}
			if (!is_dirent(&dst_entry)) {
				fs_unlock();
				if (verbose) printf("Error: Destination parent is not a directory.\n");
				return 0;
			}
			dst_filename = last_slash + 1;
		} else {
			// No slash, use cwd as parent
			dst_parent = cwd_offset;
			dst_filename = dst_path;
		}
	}
	
	// If moving to same parent, just rename
	if (src_parent == dst_parent) {
		// Update filename in FileEntry
		strncpy(src_entry.name, dst_filename, 31);
		fseek(disk, src_offset, SEEK_SET);
		fwrite(&src_entry, sizeof(FileEntry), 1, disk);
		fflush(disk);
		fs_unlock();
		if (verbose) printf("Renamed '%s' to '%s'\n", src_path, dst_path);
		return 1;
	}
	
	// Remove from source dirent
	if (src_parent != 0) {
		if (!dirent_remove_child(src_parent, src_offset)) {
			fs_unlock();
			if (verbose) printf("Error: Failed to remove file from source directory.\n");
			return 0;
		}
	}
	
	// Update filename
	strncpy(src_entry.name, dst_filename, 31);
	fseek(disk, src_offset, SEEK_SET);
	fwrite(&src_entry, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	// Add to destination dirent
	if (!dirent_add_child(dst_parent, src_offset)) {
		// Rollback: add back to source
		if (src_parent != 0) {
			dirent_add_child(src_parent, src_offset);
		}
		fs_unlock();
		if (verbose) printf("Error: Failed to add file to destination directory.\n");
		return 0;
	}
	
	fs_unlock();
	if (verbose) printf("Moved '%s' to '%s'\n", src_path, dst_path);
	return 1;
}

void get_current_directory_path(uint32_t cwd_offset, char *path, size_t path_size) {
	if (cwd_offset == 0 || cwd_offset == meta.root_dirent_offset) {
		strncpy(path, "/", path_size);
		path[path_size - 1] = '\0';
		return;
	}
	
	// Build path by traversing from cwd to root
	char components[64][32];  // Max 64 directory levels, 32 chars each
	int component_count = 0;
	
	uint32_t current = cwd_offset;
	
	// Traverse up to root
	while (current != 0 && current != meta.root_dirent_offset && component_count < 64) {
		FileEntry e;
		fseek(disk, current, SEEK_SET);
		fread(&e, sizeof(FileEntry), 1, disk);
		
		strncpy(components[component_count], e.name, 31);
		components[component_count][31] = '\0';
		component_count++;
		
		current = find_parent_dirent(current);
		if (current == 0) {
			current = meta.root_dirent_offset;
		}
	}
	
	// Build path string (reverse order)
	path[0] = '/';
	int pos = 1;
	
	for (int i = component_count - 1; i >= 0 && pos < (int)path_size - 1; i--) {
		int len = strlen(components[i]);
		if (pos + len + 1 < (int)path_size) {
			if (pos > 1) {
				path[pos++] = '/';
			}
			strncpy(path + pos, components[i], path_size - pos - 1);
			pos += len;
		}
	}
	
	path[pos] = '\0';
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
