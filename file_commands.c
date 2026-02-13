#include "file_commands.h"
#include "command_helpers.h"
#include "files.h"
#include "permissions.h"
#include "users.h"

void cmd_chmod(const char *path, const char *mode) {
	FileEntry e;
	uint32_t offset;
	
	if (!find_file_with_validation(path, &e, &offset)) return;
	
	if (!check_file_ownership(&e, path)) return;
	
	uint32_t perm = parse_permissions(mode);
	if (perm == 0) {
		printf("Invalid permission format. Use format like 'rwxrwxrwx' or 'rw-r--r--'.\n");
		return;
	}
	
	e.permission = perm;
	update_file_entry_at_offset(offset, &e);
	printf("Changed permissions of '%s' to %s\n", path, mode);
}

void cmd_chown(const char *path, const char *user_group) {
	if (!check_logged_in()) return;
	
	if (!check_root_required()) return;
	
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
	
	update_file_entry_at_offset(offset, &e);
	printf("Changed ownership of '%s'\n", path);
}

void cmd_chgrp(const char *path, const char *groupname) {
	FileEntry e;
	uint32_t offset;
	
	if (!find_file_with_validation(path, &e, &offset)) return;
	
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
	update_file_entry_at_offset(offset, &e);
	printf("Changed group of '%s' to '%s'\n", path, groupname);
}

void cmd_getfacl(const char *path) {
	FileEntry e;
	
	if (!check_logged_in()) return;
	
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
