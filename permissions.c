#include "permissions.h"

int check_permission(FileEntry *entry, char operation) {
	if (is_root()) {
		return 1;
	}
	
	uint32_t uid = get_current_uid();
	uint32_t perm = entry->permission;
	
	int bit_offset;
	
	if (entry->owner_uid == uid) {
		bit_offset = 6;
	} else if (user_in_group(uid, entry->owner_gid)) {
		bit_offset = 3;
	} else {
		bit_offset = 0;
	}
	
	int perm_bit = 0;
	switch (operation) {
		case 'r':
			perm_bit = bit_offset + 2;
			break;
		case 'w':
			perm_bit = bit_offset + 1;
			break;
		case 'x':
			perm_bit = bit_offset;
			break;
		default:
			return 0;
	}
	
	return (perm >> perm_bit) & 1;
}

uint32_t parse_permissions(const char *mode) {
	uint32_t perm = 0;
    
	if (strlen(mode) != 9) {
		return 0;
	}
	
	if (mode[0] == 'r') perm |= (1 << 8);
	if (mode[1] == 'w') perm |= (1 << 7);
	if (mode[2] == 'x') perm |= (1 << 6);
	
	if (mode[3] == 'r') perm |= (1 << 5);
	if (mode[4] == 'w') perm |= (1 << 4);
	if (mode[5] == 'x') perm |= (1 << 3);
	
	if (mode[6] == 'r') perm |= (1 << 2);
	if (mode[7] == 'w') perm |= (1 << 1);
	if (mode[8] == 'x') perm |= (1 << 0);
	
	return perm;
}

void format_permissions(uint32_t perm, char *output) {
	output[0] = (perm & (1 << 8)) ? 'r' : '-';
	output[1] = (perm & (1 << 7)) ? 'w' : '-';
	output[2] = (perm & (1 << 6)) ? 'x' : '-';
	output[3] = (perm & (1 << 5)) ? 'r' : '-';
	output[4] = (perm & (1 << 4)) ? 'w' : '-';
	output[5] = (perm & (1 << 3)) ? 'x' : '-';
	output[6] = (perm & (1 << 2)) ? 'r' : '-';
	output[7] = (perm & (1 << 1)) ? 'w' : '-';
	output[8] = (perm & (1 << 0)) ? 'x' : '-';
	output[9] = '\0';
}
