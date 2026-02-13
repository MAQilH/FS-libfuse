#include "group_commands.h"
#include "command_helpers.h"
#include "users.h"
#include "metadata.h"

void cmd_groupadd(const char *groupname) {
	if (!check_logged_in()) return;
	
	if (!check_root_required()) return;
	
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
	if (!check_logged_in()) return;
	
	if (!check_root_required()) return;
	
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
	
	remove_from_group_list(offset);
	printf("Group '%s' deleted.\n", groupname);
}
