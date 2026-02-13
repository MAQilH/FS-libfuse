#include "types.h"
#include "locks.h"
#include "metadata.h"
#include "users.h"
#include "files.h"
#include "commands.h"
#include "alloc.h"

// Global variable definitions
Metadata meta;
FILE *disk = NULL;
FSHandle current_handle = {0};
UserSession session = {0};

#ifndef EXCLUDE_MAIN
int main() {
	disk = fopen(FS_FILENAME, "r+b");
	if (!disk) {
		disk = fopen(FS_FILENAME, "w+b");
		ftruncate(fileno(disk), FS_SIZE);
	}

	read_metadata();
	initialize_root_user();

	printf("File System Ready.\n");
	printf("Please login.\n");
	
	while (!session.logged_in) {
		char username[32];
		char password[32];
		
		printf("Username: ");
		if (!fgets(username, 32, stdin)) break;
		username[strcspn(username, "\n")] = 0;
		
		if (strlen(username) == 0) continue;
		
		printf("Password: ");
		if (!fgets(password, 32, stdin)) break;
		password[strcspn(password, "\n")] = 0;
		
		if (login_user(username, password)) {
			printf("Logged in as %s\n", username);
		} else {
			printf("Login failed. Please try again.\n");
		}
	}

	while(1){
		char* command = malloc(256);
		printf("%s@filesystem$ ", session.current_username);
		fgets(command, 256, stdin);
		command[strcspn(command, "\n")] = 0;
		
		if(strncmp(command, "get_fs_stats", 12) == 0){
			fs_stats();
		} else if(strncmp(command, "rm ", 3) == 0){
			char filename[32];
			sscanf(command + 3, "%31s", filename);
			fs_rm(filename, 1);
		} else if (strncmp(command, "login ", 6) == 0) {
			char username[32];
			sscanf(command + 6, "%31s", username);
			char password[32];
			printf("Password: ");
			if (fgets(password, 32, stdin)) {
				password[strcspn(password, "\n")] = 0;
				if (login_user(username, password)) {
					printf("Logged in as %s\n", username);
				} else {
					printf("Login failed.\n");
				}
			}
		} else if (strncmp(command, "su ", 3) == 0) {
			char username[32];
			sscanf(command + 3, "%31s", username);
			if (su_user(username)) {
				printf("Switched to user %s\n", username);
			} else {
				printf("Failed to switch user.\n");
			}
		} else if (strncmp(command, "whoami", 6) == 0) {
			printf("%s (uid: %u)\n", session.current_username, session.current_uid);
		} else if (strncmp(command, "logout", 6) == 0) {
			session.logged_in = 0;
			printf("Logged out.\n");
			while (!session.logged_in) {
				char username[32];
				char password[32];
				
				printf("Username: ");
				if (!fgets(username, 32, stdin)) break;
				username[strcspn(username, "\n")] = 0;
				
				if (strlen(username) == 0) continue;
				
				printf("Password: ");
				if (!fgets(password, 32, stdin)) break;
				password[strcspn(password, "\n")] = 0;
				
				if (login_user(username, password)) {
					printf("Logged in as %s\n", username);
				} else {
					printf("Login failed. Please try again.\n");
				}
			}
		} else if (strncmp(command, "useradd ", 8) == 0) {
			char username[32];
			sscanf(command + 8, "%31s", username);
			cmd_useradd(username);
		} else if (strncmp(command, "userdel ", 8) == 0) {
			char username[32];
			sscanf(command + 8, "%31s", username);
			cmd_userdel(username);
		} else if (strncmp(command, "groupadd ", 9) == 0) {
			char groupname[32];
			sscanf(command + 9, "%31s", groupname);
			cmd_groupadd(groupname);
		} else if (strncmp(command, "groupdel ", 9) == 0) {
			char groupname[32];
			sscanf(command + 9, "%31s", groupname);
			cmd_groupdel(groupname);
		} else if (strncmp(command, "usermod ", 8) == 0) {
			char username[32], groupname[32];
			if (sscanf(command + 8, "%31s -aG %31s", username, groupname) == 2) {
				cmd_usermod(username, groupname);
			} else {
				printf("Usage: usermod <user> -aG <group>\n");
			}
		} else if (strncmp(command, "chmod ", 6) == 0) {
			char path[32], mode[10];
			if (sscanf(command + 6, "%31s %9s", path, mode) == 2) {
				cmd_chmod(path, mode);
			} else {
				printf("Usage: chmod <path> <mode>\n");
			}
		} else if (strncmp(command, "chown ", 6) == 0) {
			char path[32], user_group[64];
			if (sscanf(command + 6, "%31s %63s", path, user_group) == 2) {
				cmd_chown(path, user_group);
			} else {
				printf("Usage: chown <path> <user>:<group> or chown <path> <user>\n");
			}
		} else if (strncmp(command, "chgrp ", 6) == 0) {
			char path[32], groupname[32];
			if (sscanf(command + 6, "%31s %31s", path, groupname) == 2) {
				cmd_chgrp(path, groupname);
			} else {
				printf("Usage: chgrp <path> <group>\n");
			}
		} else if (strncmp(command, "getfacl ", 8) == 0) {
			char path[32];
			sscanf(command + 8, "%31s", path);
			cmd_getfacl(path);
		} else if (strncmp(command, "open ", 5) == 0) {
			if (current_handle.open) {
				printf("A file is already open. Please close it first.\n");
				continue;
			}
			char filename[32];
			char mode[8];
			sscanf(command + 5, "%31s %7s", filename, mode);
			int flags = 0;
			if (strchr(mode, 'c')) flags |= CREATE;
			if (strchr(mode, 'w')) flags |= WRITE;
			current_handle = fs_open(filename, flags, 1);
			if (current_handle.open) {
				printf("Opened file '%s' successfully.\n", filename);
			} else {
				printf("Failed to open file '%s'.\n", filename);
			}
		} else if (strncmp(command, "close", 5) == 0) {
			if (!current_handle.open) {
				printf("No file is currently open.\n");
			} else {
				fs_close(&current_handle);
				printf("Closed the currently open file.\n");
			}
		} else if (strncmp(command, "write ", 6) == 0) {
			if (!current_handle.open) {
				printf("No file is currently open.\n");
				continue;
			}
			if (!current_handle.can_write) {
				printf("File is not opened with write permissions. Use 'w' flag when opening.\n");
				continue;
			}
			uint32_t pos;
			char data[256];
			sscanf(command + 6, "%u %[^\"]", &pos, data);
			int written = fs_write(&current_handle, pos, strlen(data) - 1, (uint8_t *)data, 1);
			if (written > 0) {
				printf("Wrote %d bytes.\n", written);
			} else {
				printf("Failed to write to the file.\n");
			}
		} else if (strncmp(command, "read ", 5) == 0) {
			if (!current_handle.open) {
				printf("No file is currently open.\n");
				continue;
			}

			uint32_t pos, n;
			sscanf(command + 5, "%u %u", &pos, &n);
			uint8_t *buffer = malloc(n + 1);
			int read_bytes = fs_read(&current_handle, pos, n, buffer, 1);
			if (read_bytes > 0) {
				buffer[read_bytes] = '\0';
				for(int i = 0 ; i < read_bytes ; i++)
					if(buffer[i] == '\0') buffer[i] = ' ';
				printf("Read %d bytes: %s\n", read_bytes, buffer);
			} else {
				printf("Failed to read from the file.\n");
			}
			free(buffer);
		} else if (strncmp(command, "shrink ", 7) == 0) {
			if (!current_handle.open) {
				printf("No file is currently open.\n");
				continue;
			}

			uint32_t new_size;
			sscanf(command + 7, "%u", &new_size);
			fs_shrink(&current_handle, new_size, 1);
			printf("Shrunk the file to %u bytes.\n", new_size);
		} else if (strncmp(command, "get_file_stat", 13) == 0) {
			get_file_stat();
		} else if(strncmp(command, "exit", 4) == 0){
			free(command);
			break;
		} else if(strncmp(command, "stressTest", 10) == 0){
			cmd_stressTest();
		} else if(strncmp(command, "viz" , 3) == 0){
			freelist_print();
		} else {
			printf("Unknown command.\n");
		}
		free(command);
	}
	return 0;
}
#endif
