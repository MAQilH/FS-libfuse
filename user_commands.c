#include "user_commands.h"
#include "command_helpers.h"
#include "users.h"
#include "files.h"
#include "metadata.h"

void cmd_useradd(const char *username) {
	if (!check_logged_in()) return;
	
	if (!check_root_required()) return;
	
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
	if (!check_logged_in()) return;
	
	if (!check_root_required()) return;
	
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
	
	if (user_owns_files(u.uid)) {
		printf("Cannot delete user '%s': user owns files.\n", username);
		return;
	}
	
	remove_user_from_all_groups(u.uid);
	remove_from_user_list(offset);
	
	printf("User '%s' deleted.\n", username);
}

void cmd_usermod(const char *username, const char *groupname) {
	if (!check_logged_in()) return;
	
	if (!check_root_required()) return;
	
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
