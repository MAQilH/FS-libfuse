#include "users.h"

int find_user(const char *username, User *out, uint32_t *offset_out) {
	uint32_t ptr = meta.users_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		User u;
		fread(&u, sizeof(User), 1, disk);
		
		if (strcmp(u.username, username) == 0) {
			if (out) *out = u;
			if (offset_out) *offset_out = ptr;
			return 1;
		}
		
		ptr = u.next;
	}
	return 0;
}

int find_user_by_uid(uint32_t uid, User *out) {
	uint32_t ptr = meta.users_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		User u;
		fread(&u, sizeof(User), 1, disk);
		
		if (u.uid == uid) {
			if (out) *out = u;
			return 1;
		}
		
		ptr = u.next;
	}
	return 0;
}

int find_group(const char *groupname, Group *out, uint32_t *offset_out) {
	uint32_t ptr = meta.groups_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		Group g;
		fread(&g, sizeof(Group), 1, disk);
		
		if (strcmp(g.groupname, groupname) == 0) {
			if (out) *out = g;
			if (offset_out) *offset_out = ptr;
			return 1;
		}
		
		ptr = g.next;
	}
	return 0;
}

int find_group_by_gid(uint32_t gid, Group *out) {
	uint32_t ptr = meta.groups_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		Group g;
		fread(&g, sizeof(Group), 1, disk);
		
		if (g.gid == gid) {
			if (out) *out = g;
			return 1;
		}
		
		ptr = g.next;
	}
	return 0;
}

uint32_t append_user(User *u) {
	uint32_t current_block = meta.last_block / BLOCK_SIZE;
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(User) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			printf("Error: Out of space for metadata\n");
			return 0;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t offset = meta.last_block;
	
	if (meta.users_head == 0) {
		meta.users_head = offset;
	} else {
		uint32_t ptr = meta.users_head;
		while (ptr != 0) {
			User current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(User), 1, disk);
			
			if (current.next == 0) {
				current.next = offset;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(User), 1, disk);
				fflush(disk);
				break;
			}
			
			ptr = current.next;
		}
	}
	
	u->next = 0;
	fseek(disk, offset, SEEK_SET);
	fwrite(u, sizeof(User), 1, disk);
	
	meta.last_block += sizeof(User);
	
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	return offset;
}

uint32_t append_group(Group *g) {
	uint32_t current_block = meta.last_block / BLOCK_SIZE;
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(Group) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			printf("Error: Out of space for metadata\n");
			return 0;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t offset = meta.last_block;
	
	if (meta.groups_head == 0) {
		meta.groups_head = offset;
	} else {
		uint32_t ptr = meta.groups_head;
		while (ptr != 0) {
			Group current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(Group), 1, disk);
			
			if (current.next == 0) {
				current.next = offset;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(Group), 1, disk);
				fflush(disk);
				break;
			}
			
			ptr = current.next;
		}
	}
	
	g->next = 0;
	fseek(disk, offset, SEEK_SET);
	fwrite(g, sizeof(Group), 1, disk);
	
	meta.last_block += sizeof(Group);
	
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	return offset;
}

void initialize_root_user(void) {
	User root_user;
	if (find_user("root", NULL, NULL)) {
		return;
	}
	
	strncpy(root_user.username, "root", 31);
	strncpy(root_user.password, "root", 31);
	root_user.uid = 0;
	root_user.gid = 0;
	
	append_user(&root_user);
	
	Group root_group;
	if (!find_group("root", NULL, NULL)) {
		strncpy(root_group.groupname, "root", 31);
		root_group.gid = 0;
		root_group.member_count = 1;
		root_group.members[0] = 0;
		append_group(&root_group);
	}
}

int user_in_group(uint32_t uid, uint32_t gid) {
	if (uid == 0) return 1;
	
	Group g;
	if (!find_group_by_gid(gid, &g)) {
		return 0;
	}
	
	for (uint32_t i = 0; i < g.member_count; i++) {
		if (g.members[i] == uid) {
			return 1;
		}
	}
	
	User u;
	if (find_user_by_uid(uid, &u) && u.gid == gid) {
		return 1;
	}
	
	return 0;
}

int authenticate_user(const char *username, const char *password) {
	User u;
	if (!find_user(username, &u, NULL)) {
		return -1;
	}
	
	if (strcmp(u.password, password) == 0) {
		return u.uid;
	}
	return -1;
}

int login_user(const char *username, const char *password) {
	fs_lock();
	int uid = authenticate_user(username, password);
	if (uid >= 0) {
		session.current_uid = uid;
		strncpy(session.current_username, username, 31);
		session.logged_in = 1;
		fs_unlock();
		return 1;
	}
	fs_unlock();
	return 0;
}

int su_user(const char *username) {
	if (session.current_uid == 0) {
		User u;
		if (find_user(username, &u, NULL)) {
			session.current_uid = u.uid;
			strncpy(session.current_username, username, 31);
			return 1;
		}
		return 0;
	}
	
	char password[32];
	printf("Password: ");
	fgets(password, 32, stdin);
	password[strcspn(password, "\n")] = 0;
	
	return login_user(username, password);
}

uint32_t get_current_uid(void) {
	return session.current_uid;
}

int is_root(void) {
	return session.current_uid == 0;
}
