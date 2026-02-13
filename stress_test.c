#include "stress_test.h"
#include "files.h"
#include "users.h"
#include "metadata.h"

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
