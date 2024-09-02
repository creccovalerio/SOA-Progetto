#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "lib/include/syscall.h"
#include "lib/include/utils.h"

#define flush(stdin) while(getchar() != '\n')

int main(int argc, char** argv){

	char password[128];
	char new_password[128];
	char path[128];
	char options[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
	char op;
	int ret;

	while(true){

		printf("\033[2J\033[H");
		printf("\n\t************* REFERENCE MONITOR **************\n\n");
		printf("\t1) Change reference monitor status to ON\n");
		printf("\t2) Change reference monitor status to OFF\n");
		printf("\t3) Change reference monitor status to REC-ON\n");
		printf("\t4) Change reference monitor status to REC-OFF\n\n");
		printf("\t5) Add new path to the blacklist\n");
		printf("\t6) Remove path from the blacklist\n\n");
		printf("\t7) Change current password\n\n");
		printf("\t8) Quit\n\n");

		op = multiChoice("-> Select an option", options, 8);

		switch(op){

			case '1':

retry_on:
				printf("\nPassword: ");
				getInput(128, password, true);
				
				if((ret = set_on(password)) < 0){
					printf("\nOperation rejected, please retry...");
					fflush(stdout);
					goto retry_on;
				}	

				printf("\nReference monitor status correctly set to ON!");
				fflush(stdout);

				break;

			case '2':

retry_off:
				printf("\nPassword: ");
				getInput(128, password, true);

				if((ret = set_off(password)) < 0){
					printf("\nOperation rejected, please retry...");
					fflush(stdout);
					goto retry_off;
				}		

				printf("\nReference monitor status correctly set to OFF!");
				fflush(stdout);

				break;

			case '3':
	
retry_recon:			
				printf("\nPassword: ");
				getInput(128, password, true);

				if((ret = set_rec_on(password)) < 0){
					printf("\nOperation rejected, please retry...");
					fflush(stdout);
					goto retry_recon;
				}		

				printf("\nReference monitor status correctly set to REC-ON!");
				fflush(stdout);
				
				break;
				
			case '4':

retry_recoff:
				printf("\nPassword: ");
				getInput(128, password, true);

				if((ret = set_rec_off(password)) < 0){
					printf("\nOperation rejected, please retry...");
					fflush(stdout);
					goto retry_recoff;
				}		

				printf("\nReference monitor status correctly set to REC-OFF!");
				fflush(stdout);
				
				break;

			case '5':
			
retry_addpath:			
				printf("\nPassword: ");
				getInput(128, password, true);

				printf("Path to add: ");
				getInput(128, path, false);
				
				ret = add_path(path, password);
				if(ret == -1){
					printf("\nOperation rejected, please retry...");
					fflush(stdout);
					goto retry_addpath;
				}else if(ret == 0){
					printf("\nPath already in blacklist...");
					fflush(stdout);
					break;	
				}
				else if(ret == 2){
					printf("\nOperation denied...");
					goto exit_add;
				}	

				printf("\nPath correctly added in the blacklist!");

exit_add:
				fflush(stdout);
				
				break;
				
			case '6':
				
retry_rmpath:			
				printf("\nPassword: ");
				getInput(128, password, true);
		
				printf("Path to remove: ");
				getInput(128, path, false);
				
				ret = remove_path(path, password);
				if(ret == -1){
					printf("\nOperation rejected, please retry...");
					fflush(stdout);
					goto retry_rmpath;
				}else if(ret == 0){
					printf("\nPath NOT found in the blacklist...");
					fflush(stdout);
					break;
				}	else if(ret == 2){
					printf("\nOperation denied...");
					goto exit_rm;
				}	

				printf("\nPath correctly removed from the blacklist!");

exit_rm:
				fflush(stdout);
				
				break;
			
			case '7':
				
retry_updatepass:

				printf("\nPassword: ");
				getInput(128, password, true);
				
				printf("New password: ");
				getInput(128, new_password, true);
				
				if((ret = change_password(new_password, password)) < 0){
					printf("\nOperation rejected, please retry...");
					fflush(stdout);
					goto retry_updatepass;
				}		

				printf("\nPassword correctly updated!");
				fflush(stdout);
				
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
