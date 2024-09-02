#ifndef _UTILS_

#define _UTILS_

char *get_abs_path(const char *rel_path);
char *retrieve_dir(char *path);
char *retrieve_exe_path(struct path path_struct);
char *retrieve_pwd(void);
char *cipher_password(char *password, char *salt);
char* cipher_file_content(const char *data, unsigned int data_len, unsigned char *hash);

#endif