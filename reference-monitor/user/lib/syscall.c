#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <unistd.h>

#define LIBNAME "RMSYSCALLS"

int retrieve_syscall_no(char *cmd){
		
    char path[1024];
    int sys_no;
    int status;
    FILE *fp;
 
    // Execute the command "cat file" and open a pipe to read the output
    fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Error while executing command\n");
        return 1;
    }
 
    while (fgets(path, sizeof(path), fp) != NULL) {
        sys_no = atoi(path);
    }
 
    status = pclose(fp);
    if (status == -1) {
        perror("pclose error");
        return 1;
    }
 
    return sys_no;
}

long set_on(char *password){
	return syscall(retrieve_syscall_no("cat \"/sys/module/the_reference_monitor/parameters/syscall0\""), password);
}

long set_off(char *password){
	return syscall(retrieve_syscall_no("cat \"/sys/module/the_reference_monitor/parameters/syscall1\""), password);
}

long set_rec_on(char *password){
	return syscall(retrieve_syscall_no("cat \"/sys/module/the_reference_monitor/parameters/syscall2\""), password);
}

long set_rec_off(char *password){
	return syscall(retrieve_syscall_no("cat \"/sys/module/the_reference_monitor/parameters/syscall3\""), password);
}

long add_path(char *path, char *password){
	return syscall(retrieve_syscall_no("cat \"/sys/module/the_reference_monitor/parameters/syscall4\""), path, password);
}

long remove_path(char *path, char *password){
	return syscall(retrieve_syscall_no("cat \"/sys/module/the_reference_monitor/parameters/syscall5\""), path, password);
}

long change_password(char *new_password, char *old_password){
	return syscall(retrieve_syscall_no("cat \"/sys/module/the_reference_monitor/parameters/syscall6\""), new_password, old_password);
}
