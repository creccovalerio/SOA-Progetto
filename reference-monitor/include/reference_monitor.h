#define MODNAME "Reference Monitor"
#define MAXSIZE 256
#define BUFFER_SIZE 4096
#define ENC_SIZE 32
#define SIZE 1024

/* Possible statuses of the reference monitor*/ 
enum {
	ON, 
	OFF, 
	RECON, 
	RECOFF
};

/* Reference monitor struct informations */
typedef struct reference_monitor {
	int           status;
	char         *path[MAXSIZE];
	int           size;
	char 	      password[65];
	char          salt[ENC_SIZE];
	spinlock_t    lock;
	struct file  *file;
} monitor;

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

/* Deferred work struct informations */
typedef struct _packed_work{
        pid_t tgid;
        pid_t pid;
        uid_t uid;
        uid_t euid;
        char cmd_path[128];
        char cmd[64];
        struct work_struct the_work;
} packed_work;

