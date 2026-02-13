#include "commands.h"
#include "users.h"
#include "files.h"
#include "permissions.h"
#include "metadata.h"

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

void cmd_chmod(const char *path, const char *mode) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	FileEntry e;
	uint32_t offset;
	if (!find_file(path, &e, &offset)) {
		printf("File '%s' not found.\n", path);
		return;
	}
	
	if (!is_root() && e.owner_uid != get_current_uid()) {
		printf("Permission denied: You are not the owner of file '%s'.\n", path);
		return;
	}
	
	uint32_t perm = parse_permissions(mode);
	if (perm == 0) {
		printf("Invalid permission format. Use format like 'rwxrwxrwx' or 'rw-r--r--'.\n");
		return;
	}
	
	e.permission = perm;
	fseek(disk, offset, SEEK_SET);
	fwrite(&e, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	printf("Changed permissions of '%s' to %s\n", path, mode);
}

void cmd_chown(const char *path, const char *user_group) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can change file ownership.\n");
		return;
	}
	
	FileEntry e;
	uint32_t offset;
	if (!find_file(path, &e, &offset)) {
		printf("File '%s' not found.\n", path);
		return;
	}
	
	char user_part[32] = {0};
	char group_part[32] = {0};
	
	char *colon = strchr(user_group, ':');
	if (colon) {
		strncpy(user_part, user_group, colon - user_group);
		strncpy(group_part, colon + 1, 31);
	} else {
		strncpy(user_part, user_group, 31);
	}
	
	if (user_part[0] != '\0') {
		User u;
		if (!find_user(user_part, &u, NULL)) {
			printf("User '%s' not found.\n", user_part);
			return;
		}
		e.owner_uid = u.uid;
		e.owner_gid = u.gid;
	}
	
	if (group_part[0] != '\0') {
		Group g;
		if (!find_group(group_part, &g, NULL)) {
			printf("Group '%s' not found.\n", group_part);
			return;
		}
		e.owner_gid = g.gid;
	}
	
	fseek(disk, offset, SEEK_SET);
	fwrite(&e, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	printf("Changed ownership of '%s'\n", path);
}

void cmd_chgrp(const char *path, const char *groupname) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	FileEntry e;
	uint32_t offset;
	if (!find_file(path, &e, &offset)) {
		printf("File '%s' not found.\n", path);
		return;
	}
	
	if (!is_root() && e.owner_uid != get_current_uid()) {
		Group g;
		if (!find_group(groupname, &g, NULL)) {
			printf("Group '%s' not found.\n", groupname);
			return;
		}
		if (!user_in_group(get_current_uid(), g.gid)) {
			printf("Permission denied: You must be the owner or root, or be a member of the target group.\n");
			return;
		}
	}
	
	Group g;
	if (!find_group(groupname, &g, NULL)) {
		printf("Group '%s' not found.\n", groupname);
		return;
	}
	
	e.owner_gid = g.gid;
	fseek(disk, offset, SEEK_SET);
	fwrite(&e, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	printf("Changed group of '%s' to '%s'\n", path, groupname);
}

void cmd_getfacl(const char *path) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	FileEntry e;
	if (!find_file(path, &e, NULL)) {
		printf("File '%s' not found.\n", path);
		return;
	}
	
	User owner;
	Group group;
	char owner_name[32] = "unknown";
	char group_name[32] = "unknown";
	
	if (find_user_by_uid(e.owner_uid, &owner)) {
		strncpy(owner_name, owner.username, 31);
	}
	if (find_group_by_gid(e.owner_gid, &group)) {
		strncpy(group_name, group.groupname, 31);
	}
	
	char perm_str[10];
	format_permissions(e.permission, perm_str);
	
	printf("File: %s\n", path);
	printf("  Owner: %s (uid: %u)\n", owner_name, e.owner_uid);
	printf("  Group: %s (gid: %u)\n", group_name, e.owner_gid);
	printf("  Permissions: %s\n", perm_str);
}

void cmd_useradd(const char *username) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can add users.\n");
		return;
	}
	
	if (find_user(username, NULL, NULL)) {
		printf("User '%s' already exists.\n", username);
		return;
	}
	
	User new_user = {0};
	strncpy(new_user.username, username, 31);
	strncpy(new_user.password, username, 31);
	new_user.uid = meta.next_uid++;
	new_user.gid = 0;
	
	append_user(&new_user);
	printf("User '%s' added with uid %u\n", username, new_user.uid);
}

void cmd_userdel(const char *username) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can delete users.\n");
		return;
	}
	
	if (strcmp(username, "root") == 0) {
		printf("Cannot delete root user.\n");
		return;
	}
	
	User u;
	uint32_t offset;
	if (!find_user(username, &u, &offset)) {
		printf("User '%s' not found.\n", username);
		return;
	}
	
	uint32_t ptr = meta.files_head;
	int has_files = 0;
	while (ptr != 0) {
		FileEntry e;
		fseek(disk, ptr, SEEK_SET);
		fread(&e, sizeof(FileEntry), 1, disk);
		
		if (e.owner_uid == u.uid) {
			has_files = 1;
			break;
		}
		
		ptr = e.next;
	}
	
	if (has_files) {
		printf("Cannot delete user '%s': user owns files.\n", username);
		return;
	}
	
	uint32_t gptr = meta.groups_head;
	while (gptr != 0) {
		Group g;
		fseek(disk, gptr, SEEK_SET);
		fread(&g, sizeof(Group), 1, disk);
		
		for (uint32_t i = 0; i < g.member_count; i++) {
			if (g.members[i] == u.uid) {
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
	
	printf("User '%s' deleted.\n", username);
}

void cmd_groupadd(const char *groupname) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can add groups.\n");
		return;
	}
	
	if (find_group(groupname, NULL, NULL)) {
		printf("Group '%s' already exists.\n", groupname);
		return;
	}
	
	Group new_group = {0};
	strncpy(new_group.groupname, groupname, 31);
	new_group.gid = meta.next_gid++;
	new_group.member_count = 0;
	
	append_group(&new_group);
	printf("Group '%s' added with gid %u\n", groupname, new_group.gid);
}

void cmd_groupdel(const char *groupname) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can delete groups.\n");
		return;
	}
	
	if (strcmp(groupname, "root") == 0) {
		printf("Cannot delete root group.\n");
		return;
	}
	
	Group g;
	uint32_t offset;
	if (!find_group(groupname, &g, &offset)) {
		printf("Group '%s' not found.\n", groupname);
		return;
	}
	
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
	
	printf("Group '%s' deleted.\n", groupname);
}

void cmd_usermod(const char *username, const char *groupname) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can modify users.\n");
		return;
	}
	
	User u;
	uint32_t u_offset;
	if (!find_user(username, &u, &u_offset)) {
		printf("User '%s' not found.\n", username);
		return;
	}
	
	Group g;
	if (!find_group(groupname, &g, NULL)) {
		printf("Group '%s' not found.\n", groupname);
		return;
	}
	
	if (user_in_group(u.uid, g.gid)) {
		printf("User '%s' is already in group '%s'.\n", username, groupname);
		return;
	}
	
	if (g.member_count >= MAX_GROUP_MEMBERS) {
		printf("Group '%s' is full.\n", groupname);
		return;
	}
	
	uint32_t g_offset;
	find_group(groupname, &g, &g_offset);
	
	g.members[g.member_count++] = u.uid;
	fseek(disk, g_offset, SEEK_SET);
	fwrite(&g, sizeof(Group), 1, disk);
	fflush(disk);
	
	printf("Added user '%s' to group '%s'\n", username, groupname);
}

void cmd_stressTest(void) {
	printf("Starting stress test...\n");
	clock_t start_time = clock();
	
	if (disk) {
		fclose(disk);
		disk = NULL;
	}
	
	unlink(FS_FILENAME);
	
	disk = fopen(FS_FILENAME, "w+b");
	if (!disk) {
		printf("Error: Failed to create filesystem for stress test\n");
		return;
	}
	ftruncate(fileno(disk), FS_SIZE);
	
	read_metadata();
	initialize_root_user();
	
	if (!login_user("root", "root")) {
		printf("Error: Failed to login as root\n");
		fclose(disk);
		return;
	}
	
	printf("Creating %d files...\n", STRESS_TEST_NUM_FILES);
	char filename[64];
	for (int i = 0; i < STRESS_TEST_NUM_FILES; i++) {
		snprintf(filename, sizeof(filename), "stress_file_%d.txt", i);
		FSHandle f = fs_open(filename, CREATE | WRITE, 0);
		if (!f.open) {
			continue;
		}
		char data[32];
		snprintf(data, sizeof(data), "Data for file %d", i);
		fs_write(&f, 0, strlen(data), (uint8_t*)data, 0);
		fs_close(&f);
	}
	
	printf("Performing %d random operations...\n", STRESS_TEST_NUM_OPERATIONS);
	srand(time(NULL));
	
	for (int op = 0; op < STRESS_TEST_NUM_OPERATIONS; op++) {
		int operation = rand() % 4;
		
		switch (operation) {
			case 0: {
				int file_idx = rand() % STRESS_TEST_NUM_FILES;
				snprintf(filename, sizeof(filename), "stress_file_%d.txt", file_idx);
				FSHandle f = fs_open(filename, 0, 0);
				if (f.open) {
					uint8_t buffer[64];
					fs_read(&f, 0, 32, buffer, 0);
					fs_close(&f);
				}
				break;
			}
			case 1: {
				int file_idx = rand() % STRESS_TEST_NUM_FILES;
				snprintf(filename, sizeof(filename), "stress_file_%d.txt", file_idx);
				FSHandle f = fs_open(filename, WRITE, 0);
				if (f.open) {
					char new_data[64];
					snprintf(new_data, sizeof(new_data), "Updated data %d", op % STRESS_TEST_NUM_FILES);
					fs_write(&f, 0, strlen(new_data), (uint8_t*)new_data, 0);
					fs_close(&f);
				}
				break;
			}
			case 2: {
				snprintf(filename, sizeof(filename), "stress_new_%d.txt", op % STRESS_TEST_NUM_FILES);
				FSHandle f = fs_open(filename, CREATE | WRITE, 0);
				if (f.open) {
					char data[32];
					snprintf(data, sizeof(data), "New file %d", op);
					fs_write(&f, 0, strlen(data), (uint8_t*)data, 0);
					fs_close(&f);
				}
				break;
			}
			case 3: {
				int file_idx = rand() % STRESS_TEST_NUM_FILES;
				snprintf(filename, sizeof(filename), "stress_file_%d.txt", file_idx);
				fs_rm(filename, 0);
				break;
			}
		}
	}
	
	clock_t end_time = clock();
	double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	
	printf("Stress test completed in %.2f seconds\n", elapsed);
	printf("Operations: %d file creations + %d random operations\n", STRESS_TEST_NUM_FILES, STRESS_TEST_NUM_OPERATIONS);
}
