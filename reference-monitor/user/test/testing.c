#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include "../lib/include/utils.h"

#define flush(stdin) while(getchar() != '\n')

int main(int argc, char const *argv[])
{	

	char *file_path, *dir, *dest_dir;
	char cur_dir[1024], cmd[1024], cwd[PATH_MAX];
	char options[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
	char op;
	long res;
	int ret, fd;

	while(true){

		printf("\033[2J\033[H");
		printf("\n\t**** REFERENCE MONITOR TESTER ****\n\n");
		printf("\t1) Open file\n");
		printf("\t2) Delete file\n");
		printf("\t3) Create directory\n");
		printf("\t4) Delete directory\n");
		printf("\t5) Move file/directory\n");
		printf("\t6) Copy file\n");
		printf("\t7) Copy directory\n");
		printf("\t8) Quit\n\n");

		op = multiChoice("-> Select an option", options, 8);

		switch(op){

			case '1':

				memset(cur_dir, 0, 1024);
				strncpy(cur_dir, getcwd(cwd, sizeof(cwd)), 1024);

				if (chdir(cur_dir) == -1) {
			        printf("chdir error\n");
			        return -1;
			    }

reinsert_open:	
				printf("\nFile path: ");

				ret = scanf("%ms", &file_path);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}


				fd = open(file_path, O_WRONLY);
				if(fd == -1){
					if(errno == EACCES){
						perror("open");
						fflush(stdout);
						flush(stdin);
						free(file_path);
						break;
					}
					printf("\nError while opening the file...");
					fflush(stdout);
					flush(stdin);
					free(file_path);
					goto reinsert_open;
				}
			
				printf("\nFile successfully OPENED!");
				fflush(stdout);
				flush(stdin);
				close(fd);
				free(file_path);

				break;

			case '2':
				
				memset(cur_dir, 0, 1024);
				strncpy(cur_dir, getcwd(cwd, sizeof(cwd)), 1024);

				if (chdir(cur_dir) == -1) {
			        printf("\nchdir error\n");
			        return -1;
			    }

reinsert_unlink:
				printf("\nFile path: ");

				ret = scanf("%ms", &file_path);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				ret = unlink(file_path);
				if(ret != 0){
					printf("\nError while deleting the file...");
					fflush(stdout);
					flush(stdin);
					free(file_path);
					goto reinsert_unlink;
				}

				printf("\nFile successfully REMOVED!");
				fflush(stdout);
				flush(stdin);
				free(file_path);

				break;

			case '3':

reinsert_mkdir:	
				memset(cur_dir, 0, 1024);
				strcat(cur_dir, getenv("HOME"));
				printf("\nDestination directory: ");

				ret = scanf("%ms", &dest_dir);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				strcat(cur_dir, dest_dir);
				if (chdir(cur_dir) == -1) {
			        printf("\nError while executing cd...");
			        fflush(stdout);
					flush(stdin);
					memset(cur_dir, 0, 1024);
					free(dest_dir);
			        goto reinsert_mkdir;
			    }

				printf("\nDirectory name to create: ");

				ret = scanf("%ms", &dir);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				res = syscall(SYS_mkdir, dir, 0777);
				if(res != 0){
					printf("\nError while executing mkdir...");
					fflush(stdout);
					flush(stdin);
					memset(cur_dir, 0, 1024);
					free(dest_dir);
					free(dir);
					goto reinsert_mkdir;
				}
			

				printf("\nDirectory successfully CREATED!");
				fflush(stdout);
				flush(stdin);
				memset(cur_dir, 0, 1024);
				free(dest_dir);
				free(dir);

				break;
				
			case '4':

				
reinsert_rmdir:	
				memset(cur_dir, 0, 1024);
				strcat(cur_dir, getenv("HOME"));

				printf("\nDestination directory: ");

				ret = scanf("%ms", &dest_dir);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				strcat(cur_dir, dest_dir);

				if (chdir(cur_dir) == -1) {
			        printf("\nError while executing cd...");
			        fflush(stdout);
					flush(stdin);
					memset(cur_dir, 0, 1024);
					free(dest_dir);
			        goto reinsert_rmdir;
			    }

				printf("\nDirectory name to remove: ");

				ret = scanf("%ms", &dir);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				res = syscall(SYS_rmdir, dir);
				if(res != 0){
					printf("\nError while executing rmdir...");
					fflush(stdout);
					flush(stdin);
					memset(cur_dir, 0, 1024);
					free(dest_dir);
					free(dir);
					goto reinsert_rmdir;
				}
			

				printf("\nDirectory successfully REMOVED!");
				fflush(stdout);
				flush(stdin);
				memset(cur_dir, 0, 1024);
				free(dest_dir);
				free(dir);

				break;

			case '5':
				
				memset(cur_dir, 0, 1024);
				strncpy(cur_dir, getcwd(cwd, sizeof(cwd)), 1024);

				if (chdir(cur_dir) == -1) {
			        printf("\nchdir error\n");
			        return -1;
			    }

reinsert_rename:
				printf("\nFile path: ");

				ret = scanf("%ms", &file_path);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				printf("\nDestination directory: ");

				ret = scanf("%ms", &dest_dir);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				sprintf(cmd, "mv %s %s", file_path, dest_dir);
				ret = system(cmd);
				if(ret != 0){
					printf("\nError while executing mv...");
					fflush(stdout);
					flush(stdin);
					memset(cmd, 0, 1024);
					free(file_path);
					free(dest_dir);
					break;
				}

				printf("\nFile successfully MOVED!");
				fflush(stdout);
				flush(stdin);
				memset(cmd, 0, 1024);
				free(file_path);
				free(dest_dir);

				break;

			case '6':
				
				memset(cur_dir, 0, 1024);
				strncpy(cur_dir, getcwd(cwd, sizeof(cwd)), 1024);

				if (chdir(cur_dir) == -1) {
			        printf("\nchdir error\n");
			        return -1;
			    }

				printf("\nFile path: ");

				ret = scanf("%ms", &file_path);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				printf("\nDestination directory: ");

				ret = scanf("%ms", &dest_dir);
				if(ret < 0){
					printf("\nscanf error\n");
					return -1;
				}

				sprintf(cmd, "cp %s %s", file_path, dest_dir);
				ret = system(cmd);
				if(ret != 0){
					printf("\nError while executing cp...");
					fflush(stdout);
					flush(stdin);
					memset(cmd, 0, 1024);
					free(file_path);
					free(dest_dir);
					break;
				}

				printf("\nFile successfully COPIED!");
				fflush(stdout);
				flush(stdin);
				memset(cmd, 0, 1024);
				free(file_path);
				free(dest_dir);


				break;

			case '7':
				
				memset(cur_dir, 0, 1024);
				strncpy(cur_dir, getcwd(cwd, sizeof(cwd)), 1024);

				if (chdir(cur_dir) == -1) {
			        printf("\nchdir error");
			        return -1;
			    }

				printf("\nDirectory path: ");

				ret = scanf("%ms", &file_path);
				if(ret < 0){
					printf("\nscanf error");
					return -1;
				}

				printf("\nDestination directory: ");

				ret = scanf("%ms", &dest_dir);
				if(ret < 0){
					printf("scanf error\n");
					return -1;
				}

				sprintf(cmd, "cp -r %s %s", file_path, dest_dir);
				ret = system(cmd);
				if(ret != 0){
					printf("\nError while executing cp...");
					fflush(stdout);
					flush(stdin);
					memset(cmd, 0, 1024);
					free(file_path);
					free(dest_dir);
					break;
				}

				printf("\nDirectory successfully COPIED!");
				fflush(stdout);
				flush(stdin);
				memset(cmd, 0, 1024);
				free(file_path);
				free(dest_dir);

				break;

			case '8':
				return 1;
				
			default:
				fprintf(stderr, "Invalid condition at %s: %d\n", __FILE__, __LINE__);
				abort();
		}

		printf("\n\nPress ENTER to continue...\n");
		getchar();
	}
	
}