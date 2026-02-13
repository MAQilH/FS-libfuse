#include "command_helpers.h"

int check_logged_in(void) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return 0;
	}
	return 1;
}

int check_root_required(void) {
	if (!is_root()) {
		printf("Permission denied: Only root can perform this operation.\n");
		return 0;
	}
	return 1;
}

int find_file_with_validation(const char *path, FileEntry *out, uint32_t *offset_out) {
	if (!check_logged_in()) return 0;
	
	if (!find_file(path, out, offset_out)) {
		printf("File '%s' not found.\n", path);
		return 0;
	}
	return 1;
}

int check_file_ownership(const FileEntry *e, const char *path) {
	if (!is_root() && e->owner_uid != get_current_uid()) {
		printf("Permission denied: You are not the owner of file '%s'.\n", path);
		return 0;
	}
	return 1;
}

void update_file_entry_at_offset(uint32_t offset, const FileEntry *e) {
	fseek(disk, offset, SEEK_SET);
	fwrite(e, sizeof(FileEntry), 1, disk);
	fflush(disk);
}

int user_owns_files(uint32_t uid) {
	uint32_t ptr = meta.files_head;
	while (ptr != 0) {
		FileEntry e;
		fseek(disk, ptr, SEEK_SET);
		fread(&e, sizeof(FileEntry), 1, disk);
		
		if (e.owner_uid == uid) {
			return 1;
		}
		
		ptr = e.next;
	}
	return 0;
}

void remove_user_from_all_groups(uint32_t uid) {
	uint32_t gptr = meta.groups_head;
	while (gptr != 0) {
		Group g;
		fseek(disk, gptr, SEEK_SET);
		fread(&g, sizeof(Group), 1, disk);
		
		for (uint32_t i = 0; i < g.member_count; i++) {
			if (g.members[i] == uid) {
				for (uint32_t j = i; j < g.member_count - 1; j++) {
					g.members[j] = g.members[j + 1];
				}
				g.member_count--;
				fseek(disk, gptr, SEEK_SET);
				fwrite(&g, sizeof(Group), 1, disk);
				fflush(disk);
				break;
			}
		}
		
		gptr = g.next;
	}
}

void remove_from_user_list(uint32_t offset) {
	User u;
	fseek(disk, offset, SEEK_SET);
	fread(&u, sizeof(User), 1, disk);
	
	if (meta.users_head == offset) {
		meta.users_head = u.next;
		write_metadata();
	} else {
		uint32_t ptr = meta.users_head;
		while (ptr != 0) {
			User current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(User), 1, disk);
			
			if (current.next == offset) {
				current.next = u.next;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(User), 1, disk);
				fflush(disk);
				break;
			}
			
			ptr = current.next;
		}
	}
}

void remove_from_group_list(uint32_t offset) {
	Group g;
	fseek(disk, offset, SEEK_SET);
	fread(&g, sizeof(Group), 1, disk);
	
	if (meta.groups_head == offset) {
		meta.groups_head = g.next;
		write_metadata();
	} else {
		uint32_t ptr = meta.groups_head;
		while (ptr != 0) {
			Group current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(Group), 1, disk);
			
			if (current.next == offset) {
				current.next = g.next;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(Group), 1, disk);
				fflush(disk);
				break;
			}
			
			ptr = current.next;
		}
	}
}
