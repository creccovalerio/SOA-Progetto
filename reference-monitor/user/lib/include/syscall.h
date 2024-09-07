#ifndef _RMSYSCALLS_

#define _RMSYSCALLS_

int  retrieve_syscall_no(char *cmd);
long set_on(char *password);
long set_off(char *password);
long set_rec_on(char *password);
long set_rec_off(char *password);
long add_path(char *path, char *password);
long remove_path(char *path, char *password);
long change_password(char *new_password, char *old_password);

#endif 
