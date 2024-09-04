/**		      Copyright (C) 2014-2015 HPDCS Group
*		       http://www.dis.uniroma1.it/~hpdcs
* 
* This is free software; 
* You can redistribute it and/or modify this file under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* This file is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* 
* @brief This is a simple Linux Kernel Module which implements
*	 a mandatory policy for the execve service, closing it to the root user for a 
*	 black list of executables
*
* @author Valerio Crecco
*
* @date May 23, 2024
*
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>
#include <linux/path.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include "include/reference_monitor.h"
#include "lib/include/utils.h"
#include "lib/include/scth.h"

#define AUDIT if(1)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Valerio Crecco");
MODULE_DESCRIPTION("Reference monitor for file protection");

unsigned long the_syscall_table = 0x0;
unsigned long the_ni_syscall;
unsigned long new_sys_call_array[7];
int syscall0 = 0;
int syscall1 = 0;
int syscall2 = 0;
int syscall3 = 0;
int syscall4 = 0;
int syscall5 = 0;
int syscall6 = 0;

#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};
char def_password[32] = "password\0";
char *the_file;
monitor ref_monitor;

module_param(the_syscall_table, ulong, 0660);
module_param(the_file, charp, 0660);
module_param(syscall0, int, 0660);
module_param(syscall1, int, 0660);
module_param(syscall2, int, 0660);
module_param(syscall3, int, 0660);
module_param(syscall4, int, 0660);
module_param(syscall5, int, 0660);
module_param(syscall6, int, 0660);


void write_on_logfile(unsigned long input){

	packed_work *deferred_infos = (void*)container_of((void*)input,packed_work,the_work);
	struct file *out_file = NULL;
	struct file *in_file = NULL;
	ssize_t n_bytes;
	char *str = kzalloc(4096, GFP_KERNEL);
	char *buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	char *encpryped_info;
	unsigned char enc[ENC_SIZE];

	if(deferred_infos->cmd_path == NULL)  return;
	
	in_file = filp_open(deferred_infos->cmd_path, O_RDONLY , 0);
	printk("%s: Opened file %s\n", MODNAME, deferred_infos->cmd_path);
	if (IS_ERR(in_file)) {
	    printk("%s Deferred Work: Impossible to open the executable file\n", MODNAME);
    	    return;
	}

	out_file = filp_open(the_file, O_WRONLY, 0);
	if (IS_ERR(out_file)) {
	    printk("%s Deferred Work: Impossible to open Log-file\n", MODNAME);
    	    goto close_input;
	}

	if(buffer == NULL || str == NULL) goto close_output;

	sprintf(str, "\n------------------------------------------------------------------------------------\n TGID: %d\n PID: %d\n UID: %d\n EUID: %d\n Program path-name: %s\n Hash program file content: ", 
		deferred_infos->tgid, deferred_infos->pid, deferred_infos->uid, deferred_infos->euid, deferred_infos->cmd_path);
	
	while ((n_bytes = kernel_read(in_file, buffer, BUFFER_SIZE, &in_file->f_pos)) > 0) {
	    encpryped_info = cipher_file_content(buffer, n_bytes, enc);
	    if (encpryped_info == NULL) {
	        printk("Failed to cipher infos\n");
	        goto free_buffer;
	    }

	    printk("\n Deferred Work - computed hash: %s\n", encpryped_info);
	    sprintf(str+strlen(str),"%s", encpryped_info);
		
	}
    
    	sprintf(str+strlen(str),"\n");
	
	kernel_write(out_file, str, strlen(str), &out_file->f_pos);
	
	printk("%s Deferred Work: File written\n", MODNAME);

free_buffer: 
	kfree(buffer);
	kfree(str);

close_output:
	filp_close(out_file, NULL);

close_input:
	filp_close(in_file, NULL);

	return;
	
}

static void set_deferred_infos(void){

	packed_work *the_task;
	char *exe_path;
	
	the_task = kzalloc(sizeof(packed_work),GFP_KERNEL);
	if(the_task == NULL){
	    printk("%s: kzalloc error\n", MODNAME);
	    return;
	}

	the_task->tgid = current->tgid;
	the_task->pid = current->pid;
	the_task->uid = current->cred->uid.val;
	the_task->euid = current->cred->euid.val;
	exe_path = retrieve_exe_path(current->mm->exe_file->f_path);
	strncpy(the_task->cmd_path, exe_path, strlen(exe_path));
	strncpy(the_task->cmd, current->comm, strlen(current->comm));

	__INIT_WORK(&(the_task->the_work),(void*)write_on_logfile, (unsigned long)(&(the_task->the_work)));

	schedule_work(&the_task->the_work);

}

static int check_into_blacklist(int open_op, char *path){

	int i;

	spin_lock(&ref_monitor.lock);

	if(open_op){
	    for(i=0; i<ref_monitor.size; i++){
		if(strstr(path, ref_monitor.path[i]) != NULL && strncmp(path, ref_monitor.path[i], strlen(ref_monitor.path[i])) == 0){	
		    spin_unlock(&ref_monitor.lock);
		    return 1;
		}
	    }
	    
	}else{
	    for(i=0; i<ref_monitor.size; i++){
		if(strstr(path, ref_monitor.path[i]) != NULL){
		    spin_unlock(&ref_monitor.lock);
		    return 1;
		}
	    }
	}

	spin_unlock(&ref_monitor.lock);
	return 0;
}

static int return_open_kretprobes_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
	
	struct handler_infos *hi;

	hi = (struct handler_infos *)ri->data;
	pr_info("%s: %s", MODNAME, hi->message);

	set_deferred_infos();

	regs->ax = -EACCES;

	kfree(hi->message);

	return 0;
		
}


static int entry_open_file_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){
		
	char *path;
	char *dir;
	char *prev_dir;
	int cp_op = 0;

	struct handler_infos *hi;
	char msg[512];
	
	const __user char *pathname = ((struct filename *)(regs->si))->uptr; //arg1
	const struct open_flags *op_flag = (struct open_flags *)(regs->dx); //arg2
	
	const char *real_path = ((struct filename *)(regs->si))->name;
	int flags = op_flag->open_flag;

	//avoiding to check over files and directories under /run (it contains temporary and runtime stuff, thus decreasing performances of the reference monitor)
	char run_dir[5]; 
	strncpy(run_dir, real_path, 4);
	run_dir[4]='\0';
	if(strcmp(run_dir, "/run") == 0) return 1;

	//checking if file is open in write mode
	if(!(flags & O_WRONLY) && !(flags & O_RDWR) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL))){
	    if(strcmp(current->comm, "cp\0") != 0) return 1;
	    printk("%s:cp operation in read mode intercepted\n", MODNAME);
	    cp_op = 1;  
	}
	
	if(strcmp(current->comm,"cp\0") == 0) cp_op = 1;

	if(pathname == NULL){
	    // se real_path è assoluto -> pathname è NULL
	    if(real_path == NULL) return 1;
	    path = (char *)real_path;
	}else{
            path = get_abs_path(pathname);	
            if(path == NULL){
            	if(cp_op != 1){
            	    return 1;
            	}else{
	            path = (char *)real_path;
	        }
            }

	}

	/* check if path is empty */
	if(strcmp(path, "") == 0 || strcmp(path, " ") == 0) return 0;

	/* retrieving parent path directory */
	prev_dir = retrieve_dir(path);
	dir = get_abs_path(prev_dir);
	if(strcmp(dir, "") == 0) dir = retrieve_pwd();

	printk("%s: open in write mode intercepted: file (with flags %d) is %s - prev_dir is %s, cmd is %s\n",MODNAME, flags, path, dir, current->comm);

    	if(check_into_blacklist(1, path)){
    	    hi = (struct handler_infos *)ri->data;
    	    sprintf(msg, "File %s cannot be opened in write mode. Open rejected!", path);
    	    hi->message = kstrdup(msg, GFP_ATOMIC);

    	    return 0;
        }

        if(check_into_blacklist(1, dir)){
            hi = (struct handler_infos *)ri->data;
    	    sprintf(msg, "File/Directory %s cannot be copied. Copy rejected!", dir);
    	    hi->message = kstrdup(msg, GFP_ATOMIC);

    	    if(cp_op){
    	    	printk("%s: File/Directory %s cannot be copied. Copy rejected!", MODNAME, dir);
    	    
    	    	set_deferred_infos();

    	    	regs->di = -1;
	        regs->si = (unsigned long)NULL;

	        return 1;
    	    }

    	    return 0;
        }

	return 1;	
}

static struct kretprobe kp_open_file = {
        .kp.symbol_name = "do_filp_open",
        .handler = return_open_kretprobes_handler,
        .entry_handler = entry_open_file_wrapper,
        .data_size = sizeof(struct handler_infos),
};

static int entry_delete_file_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){
	
	char *path;
	
	struct filename *name = (struct filename *)(regs->si);
	const __user char *pathname = name->uptr; 
	const char *real_path = name->name;
	
	if(pathname == NULL){
	    path = (char *)real_path;
	}else{
	    path = get_abs_path(pathname);
	    if(path == NULL) path = (char *)real_path;
	}
	
	printk("%s: rm intercepted: file to delete is %s\n",MODNAME, path);
	
	if(check_into_blacklist(0, path) == 1){
    	    printk("%s: File %s cannot be deleted. Delete rejected", MODNAME, path);
    	    set_deferred_infos();
    	    regs->si = (unsigned long)NULL;

    	    return 0;
	}
	
	return 1;

}

static struct kretprobe kp_delete_file = {
        .kp.symbol_name = "do_unlinkat",
        .entry_handler = entry_delete_file_wrapper,
        .data_size = sizeof(struct handler_infos),
};

static int entry_create_dir_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){
	
	char *path;
	char *dir;
	char *prev_dir;

	struct filename *name = (struct filename *)(regs->si); //arg1
	const __user char *pathname = name->uptr; 
	const char *real_path = name->name;
	
	if(pathname == NULL){
	    path = (char *)real_path;
	}else{
	    path = get_abs_path(pathname);
	    if(path == NULL) path = (char *)real_path;
	}
	
	prev_dir = retrieve_dir(path);
	dir = get_abs_path(prev_dir);
	if(strcmp(dir, "") ==0) dir = retrieve_pwd();

	printk("%s: mkdir intercepted: directory to create is %s, prev dir is %s\n",MODNAME, path, dir);

	if(check_into_blacklist(0, dir)){
	    printk("%s: Directory %s cannot be created. Mkdir rejected!", MODNAME, dir);
    	    set_deferred_infos();
    	    regs->si = (unsigned long)NULL;

    	    return 0;
	}
		
	return 1;

}

static struct kretprobe kp_create_dir = {
        .kp.symbol_name = "do_mkdirat",
        .entry_handler = entry_create_dir_wrapper,
        .data_size = sizeof(struct handler_infos),

};

static int entry_remove_dir_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){
	
	char *path;
	
	struct filename *name = (struct filename *)(regs->si); //arg1
	const __user char *pathname = name->uptr; 
	const char *real_path = name->name;
	
	if(pathname == NULL){
	    path = (char *)real_path;
	}else{
	    path = get_abs_path(pathname);
	    if(path == NULL) path = (char *)real_path;
	}
	
	printk("%s: rmdir intercepted: directory to remove is %s\n",MODNAME, path);

	if(check_into_blacklist(0, path) == 1){
	    printk("%s: Directory %s cannot be removed. Rmdir rejected!", MODNAME, path);
    	    set_deferred_infos();
    	    regs->si = (unsigned long)NULL;

    	    return 0;
	}
	
	return 1;

}

static struct kretprobe kp_remove_dir = {
        .kp.symbol_name = "do_rmdir",
        .entry_handler = entry_remove_dir_wrapper,
        .data_size = sizeof(struct handler_infos),
};

static int entry_move_wrapper(struct kretprobe_instance *ri, struct pt_regs *regs){
	
	char *source_path;
	char *dest_path;
	
	struct filename *from = (struct filename *)(regs->si);
	const __user char *from_path = from->uptr; 
	const char *real_from_path = from->name;

	struct filename *to = (struct filename *)(regs->cx);
	const __user char *to_path = to->uptr; 
	const char *real_to_path = to->name;

	if(from_path == NULL) source_path = (char *)real_from_path;
	else{
	    source_path = get_abs_path(from_path);
	    if(source_path == NULL) source_path = (char *)real_from_path;
	}

	if(to_path == NULL) dest_path = (char *)real_to_path;
	else{
	    dest_path = get_abs_path(to_path);
	    if(dest_path == NULL) dest_path = (char *)real_to_path;
	}

	printk("%s: mv operation intercepted with directory %s as source and directory %s as destination\n",MODNAME, source_path, dest_path);
	
	if(check_into_blacklist(0, dest_path) == 1){
	    printk("%s: File/Directory %s cannot be moved. Move rejected!", MODNAME, dest_path);
    	    set_deferred_infos();
    	    regs->si = (unsigned long)NULL;

    	    return 0;
	}

	if(check_into_blacklist(0, source_path) == 1){
	    printk("%s: File/Directory %s cannot be moved. Move rejected!", MODNAME, source_path);
    	    set_deferred_infos();
    	    regs->si = (unsigned long)NULL;

    	    return 0;
	}	
	
	return 1;

}

static struct kretprobe kp_move = {
        .kp.symbol_name = "do_renameat2",
        .entry_handler = entry_move_wrapper,
        .data_size = sizeof(struct handler_infos),
};


/*
* sys_set_status_on set the reference monitor STATUS to ON
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _set_status_on, char *, password){
#else
asmlinkage long sys_set_status_on(char *password){
#endif

	char *encrypted_password;
	char *tmp_password;

	printk("%s: Asked to set Reference Monitor status to ON\n", MODNAME);
	
	if((tmp_password = kmalloc(SIZE, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    return -1;
	}

	if((copy_from_user(tmp_password, password, strnlen_user(password, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");
	    kfree(tmp_password);
	    return -1;
	}

	spin_lock(&ref_monitor.lock);

	/* ciphering the input password with the salt */
	encrypted_password = cipher_password(tmp_password, ref_monitor.salt);
	if(encrypted_password == NULL){
	    printk("cipher_password error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_password);
	    return -1;
	}

	/* comparing the input password with the reference monitor password anc checking euid */
	if(strcmp(ref_monitor.password, encrypted_password) != 0 || current->cred->euid.val != 0){
	    printk("wrong password or not euid set\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(encrypted_password);
	    kfree(tmp_password);
	    return -1;
	}

	/* if the current status of the reference monitor is OFF or REC-OFF -> enabling the probes*/
	if(ref_monitor.status == OFF || ref_monitor.status == RECOFF){
	    enable_kretprobe(&kp_open_file);
	    enable_kretprobe(&kp_create_dir);
	    enable_kretprobe(&kp_remove_dir);
	    enable_kretprobe(&kp_delete_file);
	    enable_kretprobe(&kp_move);
	}
	
	/* set the reference monitor status to ON */
	ref_monitor.status = ON;
	spin_unlock(&ref_monitor.lock);
	kfree(encrypted_password);
	kfree(tmp_password);
	
	printk("%s: Reference Monitor status correctly set to ON\n", MODNAME);

	return 0;
	
}

/*
* sys_set_status_off set the reference monitor STATUS to OFF
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _set_status_off, char *, password){
#else
asmlinkage long sys_set_status_off(char *password){
#endif

	char *encrypted_password;
	char *tmp_password;

	printk("%s: Asked to set Reference Monitor STATUS to OFF\n", MODNAME);
	
	if((tmp_password = kmalloc(SIZE, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    return -1;
	}

	if((copy_from_user(tmp_password, password, strnlen_user(password, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");
	    kfree(tmp_password);
	    return -1;
	}

	spin_lock(&ref_monitor.lock);

	/* ciphering the input password with the salt */
	encrypted_password = cipher_password(tmp_password, ref_monitor.salt);
	if(encrypted_password == NULL){
	    printk("cipher_password error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_password);
	    return -1;
	}

	/* comparing the input password with the reference monitor password anc checking euid */
	if(strcmp(ref_monitor.password, encrypted_password) != 0 || current->cred->euid.val != 0){
	    printk("wrong password or not euid set\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(encrypted_password);
	    kfree(tmp_password);
	    return -1;
	}

	/* if the current status of the reference monitor is ON or REC-ON -> disabling the probes*/
	if(ref_monitor.status == ON || ref_monitor.status == RECON){
	    disable_kretprobe(&kp_open_file);
	    disable_kretprobe(&kp_create_dir);
	    disable_kretprobe(&kp_remove_dir);
	    disable_kretprobe(&kp_delete_file);
	    disable_kretprobe(&kp_move);
	}
	
	/* set the reference monitor status to OFF */
	ref_monitor.status = OFF;
	spin_unlock(&ref_monitor.lock);
	kfree(encrypted_password);
	kfree(tmp_password);
	
	printk("%s: Reference Monitor status correctly set to OFF\n", MODNAME);

	return 0;
	
}

/*
* sys_set_status_rec_on set the reference monitor STATUS to REC-ON
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _set_status_rec_on, char *, password){
#else
asmlinkage long sys_set_status_rec_on(char *password){
#endif

	char *encrypted_password;
	char *tmp_password;

	printk("%s: Asked to set Reference Monitor STATUS to REC-ON\n", MODNAME);
	
	if((tmp_password = kmalloc(SIZE, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    return -1;
	}

	if((copy_from_user(tmp_password, password, strnlen_user(password, PAGE_SIZE))) != 0){
 	    printk("copy_from_user error\n");	
	    kfree(tmp_password);
	    return -1;
	}

	spin_lock(&ref_monitor.lock);

	/* ciphering the input password with the salt */
	encrypted_password = cipher_password(tmp_password, ref_monitor.salt);
	if(encrypted_password == NULL){
	    printk("cipher_password error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_password);
	    return -1;
	}

	/* comparing the input password with the reference monitor password anc checking euid */
	if(strcmp(ref_monitor.password, encrypted_password) != 0 || current->cred->euid.val != 0){
	    printk("wrong password or not euid set\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(encrypted_password);
	    kfree(tmp_password);
	    return -1;
	}
	
	/* if the current status of the reference monitor is OFF or REC-OFF -> enabling the probes*/
	if(ref_monitor.status == OFF || ref_monitor.status == RECOFF){
	    enable_kretprobe(&kp_open_file);
	    enable_kretprobe(&kp_create_dir);
	    enable_kretprobe(&kp_remove_dir);
	    enable_kretprobe(&kp_delete_file);
	    enable_kretprobe(&kp_move);
	}

	/* set the reference monitor status to REC-ON */
	ref_monitor.status = RECON;
	spin_unlock(&ref_monitor.lock);
	kfree(encrypted_password);
	kfree(tmp_password);
	
	printk("%s: Reference Monitor status correctly set to REC-ON\n", MODNAME);

	return 0;
	
}

/*
* sys_set_status_rec_off set the reference monitor STATUS to REC-OFF
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _set_status_rec_off, char *, password){
#else
asmlinkage long sys_set_status_rec_off(char *password){
#endif

	char *encrypted_password;
	char *tmp_password;

	printk("%s: Asked to set Reference Monitor STATUS to REC-OFF\n", MODNAME);
	
	if((tmp_password = kmalloc(SIZE, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    return -1;
	}

	if((copy_from_user(tmp_password, password, strnlen_user(password, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");
	    kfree(tmp_password);
	    return -1;
	}

	spin_lock(&ref_monitor.lock);

	/* ciphering the input password with the salt */
	encrypted_password = cipher_password(password, ref_monitor.salt);
	if(encrypted_password == NULL){
	    printk("cipher_password error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_password);
	    return -1;
	}

	/* comparing the input password with the reference monitor password anc checking euid */
	if(strcmp(ref_monitor.password, encrypted_password) != 0 || current->cred->euid.val != 0){
	    printk("wrong password or not euid set\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(encrypted_password);
	    kfree(tmp_password);  
	    return -1;
	}
	
	/* if the current status of the reference monitor is ON or REC-ON -> disabling the probes*/
	if(ref_monitor.status == ON || ref_monitor.status == RECON){
	    disable_kretprobe(&kp_open_file);
	    disable_kretprobe(&kp_create_dir);
	    disable_kretprobe(&kp_remove_dir);
	    disable_kretprobe(&kp_delete_file);
	    disable_kretprobe(&kp_move);
	}
	
	/* set the reference monitor status to REC-OFF */
	ref_monitor.status = RECOFF;
	spin_unlock(&ref_monitor.lock);
	kfree(encrypted_password);
	kfree(tmp_password);
	
	printk("%s: Reference Monitor status correctly set to REC-OFF\n", MODNAME);

	return 0;
	
}


/*
* sys_add_path ADD @new_path to the blacklisted paths
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _add_path, char*, new_path, char *, password){
#else
asmlinkage long sys_add_path(char *new_path, char *password){
#endif

	char *encrypted_password;
	char *tmp_password;
	char *full_path;
	char *tmp_path;
	int   i;

	printk("%s: Asked to ADD new path: [%s] to blacklist\n", MODNAME, new_path);
	
	if((tmp_path = kmalloc(SIZE, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    return -1;
	}

	if((copy_from_user(tmp_path, new_path, strnlen_user(new_path, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");
	    kfree(tmp_path);
	    return -1;
	}	

	if((tmp_password = kmalloc(SIZE, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    kfree(tmp_path);
	    return -1;
	}

	if((copy_from_user(tmp_password, password, strnlen_user(password, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");
	    kfree(tmp_path);
	    kfree(tmp_password);
	    return -1;
	}

	spin_lock(&ref_monitor.lock);

	/* ciphering the input password with the salt */
	encrypted_password = cipher_password(tmp_password, ref_monitor.salt);
	if(encrypted_password == NULL){
	    printk("cipher_password error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_path);
	    kfree(tmp_password);
	    return -1;
	}

	/* check if blacklist is full */
	if(ref_monitor.size == MAXSIZE-1){
	    printk("%s: Maximum number of paths reached\n", MODNAME);
	    spin_unlock(&(ref_monitor.lock));
	    kfree(tmp_path);
	    kfree(tmp_password);
	    kfree(encrypted_password);
	    return 2;
	}

	/* comparing the input password with the reference monitor password anc checking euid */
	if(strcmp(ref_monitor.password, encrypted_password) != 0 || current->cred->euid.val != 0){
	    printk("wrong password or not euid set\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_path);
	    kfree(tmp_password);
	    kfree(encrypted_password);
	    return -1;
	}

	/* get the absolute path from the user input */
	full_path = get_abs_path(tmp_path);
	if(full_path == NULL){
	    printk("get_abs_path error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_path);
	    kfree(tmp_password);
	    kfree(encrypted_password);
	    return -1;
	}

	/* check if file is the-file */
	if(full_path != NULL && strstr(full_path, "/singlefile-FS/mount/the-file") != NULL){
	    printk("%s: Cannot deny writes on Log-file. file_path is %s \n", MODNAME, full_path);
	    spin_unlock(&(ref_monitor.lock));
	    kfree(tmp_path);
	    kfree(tmp_password);
	    kfree(encrypted_password);
	    return -1;
	}

	/* check if current status is ON or OFF */
	if(ref_monitor.status == ON || ref_monitor.status == OFF){
	    printk("%s: Status is ON or OFF -> Impossible to add blacklisted paths\n", MODNAME);
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_path);
	    kfree(tmp_password);
	    kfree(encrypted_password);
	    return 2;
	}

	/* check if path is already present in blacklist */
	for(i=0; i<ref_monitor.size; i++){
	    if(strcmp(ref_monitor.path[i], full_path) == 0 ){
		printk("%s: Path [%s] already present in blacklist\n", MODNAME, full_path);
		spin_unlock(&ref_monitor.lock);
		kfree(tmp_path);
	    	kfree(tmp_password);
	    	kfree(encrypted_password);
		return 0;
	    }
	} 
	
	ref_monitor.path[ref_monitor.size] = full_path;
	ref_monitor.size++;
	spin_unlock(&ref_monitor.lock);
	kfree(tmp_path);
	kfree(tmp_password);
	kfree(encrypted_password);
	printk("%s: Path [%s] correctly ADDED\n", MODNAME, full_path);

	return 1;
	
}

/*
* sys_remove_path REMOVE @path from the blacklisted paths
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _remove_path, char *, path, char *, password){
#else
asmlinkage long sys_remove_path(char *path, char *password){
#endif

	char *encrypted_password;
	char *tmp_password;
	char *full_path;
	char *tmp_path;
	int i, j;

	printk("%s: Asked to REMOVE path [%s] from the blacklist\n",MODNAME, path);
	
	if((tmp_path = kmalloc(1024, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    return -1;
	}

	if((copy_from_user(tmp_path, path, strnlen_user(path, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");	
	    kfree(tmp_path);
	    return -1;
	}

	if((tmp_password = kmalloc(1024, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    kfree(tmp_path);
	    return -1;
	}

	if((copy_from_user(tmp_password, password, strnlen_user(password, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");	
	    kfree(tmp_path);
	    kfree(tmp_password);
	    return -1;
	}

	spin_lock(&ref_monitor.lock);

	/* ciphering the input password with the salt */
	encrypted_password = cipher_password(tmp_password, ref_monitor.salt);
	if(encrypted_password == NULL){
	    printk("cipher_password error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_path);
	    kfree(tmp_password);
	    return -1;
	}

	/* comparing the input password with the reference monitor password anc checking euid */
	if(strcmp(ref_monitor.password, encrypted_password) != 0 || current->cred->euid.val != 0){
	    printk("wrong password or not euid set\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_path);
	    kfree(tmp_password);
	    kfree(encrypted_password);
	    return -1;
	}

	/* check if current status is ON or OFF */
	if(ref_monitor.status == ON || ref_monitor.status == OFF){
	    printk("%s: Status is ON or OFF -> Impossible to remove blacklisted paths\n", MODNAME);
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_path);
	    kfree(tmp_password);
	    kfree(encrypted_password);
	    return 2;
	}

	/* get the absolute path from the user input */
	full_path = get_abs_path(tmp_path);
	if(full_path == NULL){
	    printk("get_abs_path error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_path);
	    kfree(tmp_password);
	    kfree(encrypted_password);
	    return -1;
	}

	//check if path is present in blacklist
	for(i = 0; i < ref_monitor.size; i++){
	    if(strcmp(ref_monitor.path[i], full_path) == 0 ){
		//removing path
		if((j == 0 && ref_monitor.size == 0) || j == MAXSIZE-1){
		    ref_monitor.path[j]= NULL;
		}else{
		    for(j = i; j < ref_monitor.size-1; j++){
			ref_monitor.path[j] = ref_monitor.path[j+1];
		    }
		}
		ref_monitor.size--;
		spin_unlock(&ref_monitor.lock);
		kfree(tmp_path);
	    	kfree(tmp_password);
	   	kfree(encrypted_password);
		printk("%s: Path [%s] correctly removed\n", MODNAME, full_path);
		return 1;
	    }
	} 

	kfree(tmp_password);
	kfree(tmp_path);
	kfree(encrypted_password);
	spin_unlock(&ref_monitor.lock);
	printk("%s: Path [%s] not present in blacklist\n", MODNAME, full_path);

	return 0;
	
}

/*
* sys_update_password CHANGE the password to access system calls
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _update_password, char *, new_pass, char *, old_pass){
#else
asmlinkage long sys_update_password(char *new_pass, char *old_pass){
#endif

	char *encrypted_new_password;
	char *tmp_new_password;
	char *encrypted_old_password;
	char *tmp_old_password;
	char salt[ENC_SIZE];

	printk("%s: Asked to UPDATE the password\n",MODNAME);	

	if((tmp_old_password = kmalloc(1024, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    return -1;
	}

	if((copy_from_user(tmp_old_password, old_pass, strnlen_user(old_pass, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");	
	    kfree(tmp_old_password);
	    return -1;
	}

	if((tmp_new_password = kmalloc(1024, GFP_KERNEL)) == NULL){
	    printk("kmalloc error\n");
	    kfree(tmp_old_password);
	    return -1;
	}

	if((copy_from_user(tmp_new_password, new_pass, strnlen_user(new_pass, PAGE_SIZE))) != 0){
	    printk("copy_from_user error\n");
	    kfree(tmp_new_password);
	    kfree(tmp_old_password);
	    return -1;
	}

	spin_lock(&ref_monitor.lock);

	/* ciphering the input old password with the salt */
	encrypted_old_password = cipher_password(tmp_old_password, ref_monitor.salt);
	if(encrypted_old_password == NULL){
	    printk("cipher_password error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(tmp_old_password);
	    kfree(tmp_new_password);
	    return -1;
	}

	/* comparing the input password with the reference monitor password anc checking euid */
	if(strcmp(ref_monitor.password, encrypted_old_password) != 0 || current->cred->euid.val != 0){
	    printk("wrong password or not euid set\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(encrypted_old_password);
	    kfree(tmp_old_password);
	    kfree(tmp_new_password);
	    return -1;
	}
		
	get_random_bytes(salt, ENC_SIZE);
	if(memcpy(ref_monitor.salt, salt, ENC_SIZE) == NULL){
	    printk("memcpy error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(encrypted_old_password);
	    kfree(tmp_old_password);
	    kfree(tmp_new_password);
	    return -1;
	}

	/* ciphering the input new password with the salt */
	encrypted_new_password = cipher_password(tmp_new_password, ref_monitor.salt);
	if (encrypted_new_password == NULL) {
	    printk("Errore durante la cifratura della password\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(encrypted_old_password);
	    kfree(tmp_old_password);
	    kfree(tmp_new_password);
	    return -1;
	}

	if(memcpy(ref_monitor.password, encrypted_new_password, strlen(encrypted_new_password)) == NULL){
	    printk("memcpy error\n");
	    spin_unlock(&ref_monitor.lock);
	    kfree(encrypted_old_password);
	    kfree(tmp_old_password);
	    kfree(tmp_new_password);
	    return -1;	
	}

	spin_unlock(&ref_monitor.lock);
	kfree(encrypted_old_password);
	kfree(encrypted_new_password);
	kfree(tmp_old_password);
	kfree(tmp_new_password);

	printk("%s: Reference Monitor password correctly UPDATED\n", MODNAME);

	return 0;
	
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_set_status_on = (unsigned long) __x64_sys_set_status_on;
long sys_set_status_off = (unsigned long) __x64_sys_set_status_off;
long sys_set_status_rec_on = (unsigned long) __x64_sys_set_status_rec_on;
long sys_set_status_rec_off = (unsigned long) __x64_sys_set_status_rec_off;
long sys_add_path = (unsigned long) __x64_sys_add_path;
long sys_remove_path = (unsigned long) __x64_sys_remove_path;   
long sys_update_password = (unsigned long) __x64_sys_update_password;      
#else
#endif

int init_module(void) {

	char *default_password;
	char salt[ENC_SIZE];
	int ret, i;
	
	printk("%s: initializing\n",MODNAME);

	/* generate random salt for default password encryption */
	get_random_bytes(salt, ENC_SIZE);
	memcpy(ref_monitor.salt, salt, ENC_SIZE);

	/* ciphering the default password of the reference monitor */
	default_password = cipher_password(def_password, ref_monitor.salt);
	if(default_password == NULL){
	    printk("cipher_password error\n");
	    return -1;
	}

	/* reference monitor infos inizialization */
	memcpy(ref_monitor.password, default_password, strlen(default_password));
	ref_monitor.status = ON;
	ref_monitor.path[0] = NULL;
	ref_monitor.size = 0;
	spin_lock_init(&(ref_monitor.lock));

    	AUDIT{
	    printk("%s: Reference-Monitor received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
	    printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
	}

	new_sys_call_array[0] = (unsigned long) sys_set_status_on;
	new_sys_call_array[1] = (unsigned long) sys_set_status_off;
	new_sys_call_array[2] = (unsigned long) sys_set_status_rec_on;
	new_sys_call_array[3] = (unsigned long) sys_set_status_rec_off;
	new_sys_call_array[4] = (unsigned long) sys_add_path;
	new_sys_call_array[5] = (unsigned long) sys_remove_path;
	new_sys_call_array[6] = (unsigned long) sys_update_password;

	ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)the_syscall_table,&the_ni_syscall);

	if (ret != HACKED_ENTRIES){
	    printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret); 
	    return -1;      
	}

	unprotect_memory();

	for(i=0;i<HACKED_ENTRIES;i++){
	    ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
	}

	protect_memory();

	printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

	syscall0 = restore[0];
	syscall1 = restore[1];
	syscall2 = restore[2];
	syscall3 = restore[3];
	syscall4 = restore[4];
	syscall5 = restore[5];
	syscall6 = restore[6];

	ret = register_kretprobe(&kp_open_file);
	if (ret < 0) {
	    printk("%s: kprobe kp_open_file registering failed, returned %d\n",MODNAME,ret);
	    return ret;
	}

	ret = register_kretprobe(&kp_delete_file);
	if (ret < 0) {
	    printk("%s: kprobe kp_delete_file registering failed, returned %d\n",MODNAME,ret);
	    return ret;
	}

	ret = register_kretprobe(&kp_create_dir);
	if (ret < 0) {
	    printk("%s: kprobe kp_create_dir registering failed, returned %d\n",MODNAME,ret);
	    return ret;
	}

	ret = register_kretprobe(&kp_remove_dir);
	if (ret < 0) {
	    printk("%s: kprobe kp_remove_dir registering failed, returned %d\n",MODNAME,ret);
	    return ret;
	}

	ret = register_kretprobe(&kp_move);
	if (ret < 0) {
	    printk("%s: kprobe kp_move registering failed, returned %d\n",MODNAME,ret);
	    return ret;
	}

	return 0;
}

void cleanup_module(void) {

	int i;        
	printk("%s: shutting down\n",MODNAME);

	unprotect_memory();
	for(i=0;i<HACKED_ENTRIES;i++){
	    ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
	}
	protect_memory();
	printk("%s: sys-call table restored to its original content\n",MODNAME);
	    
	//unregistering kprobes
	unregister_kretprobe(&kp_open_file);
	unregister_kretprobe(&kp_delete_file);
	unregister_kretprobe(&kp_create_dir);
	unregister_kretprobe(&kp_remove_dir);
	unregister_kretprobe(&kp_move);
	   
	printk("%s: kprobes unregistered\n", MODNAME);
	printk("%s: Module correctly removed\n", MODNAME);
            
}

