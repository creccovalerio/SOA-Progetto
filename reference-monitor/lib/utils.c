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
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>
#include <asm/segment.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Valerio Crecco");
MODULE_DESCRIPTION("Utils functions module");

#define LIBNAME "UTILS"

#define SIZE 32

/*
* This function returns the entire path from relative path
*/
char *get_abs_path(const char *rel_path) {

    char *k_full_path, *rel_path_tilde, *tilde_pos;
    struct path path;
    int ret;

    if (rel_path[0] == '/') {
        k_full_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!k_full_path) {
            pr_err("Error in kmalloc (get_full_path)\n");
            return NULL; 
        }

        strcpy(k_full_path, rel_path);
        
        return k_full_path;
    }


    k_full_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!k_full_path) {
        pr_err("Error in kmalloc (get_full_path)\n");
        return NULL; 
    }

    ret = kern_path(rel_path, LOOKUP_FOLLOW, &path);
    if (ret == -ENOENT) {
        rel_path_tilde = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!rel_path_tilde) {
            pr_err("Error in kmalloc (rel_path_tilde)\n");
            return NULL; 
        }

        strcpy(rel_path_tilde, rel_path);
        strcat(rel_path_tilde, "~");

        ret = kern_path(rel_path_tilde, LOOKUP_FOLLOW, &path);
        kfree(rel_path_tilde);

    }
   
    if (ret) {
        pr_info("Full path not found (error %d) for file %s\n", ret, rel_path);
        kfree(k_full_path);
        return NULL;
    }

    ret = snprintf(k_full_path, PATH_MAX, "%s", d_path(&path, k_full_path, PATH_MAX));
    if (ret < 0 || ret >= PATH_MAX) {
        kfree(k_full_path);
        pr_err("Full path is too long\n");
        return NULL;
    }

    tilde_pos = strrchr(k_full_path, '~');
    if (tilde_pos != NULL) {
            *tilde_pos = '\0'; 
    }

    return k_full_path;
}

/* function to retrieve the parent directory of a path */
char *retrieve_dir(char *path){

	int i= strlen(path)-1;
	char *new_string = kmalloc(strlen(path), GFP_KERNEL);
	if(new_string == NULL)  return "";
	
	while(i>=0){
		if(path[i] != '/'){ 
			new_string[i] = '\0'; 
		}
		else{
			new_string[i]='\0';
			i--;
		 	break;
		}
		i--;
	}
	
	while(i>=0){
		new_string[i] = path[i];
		i--;
	}
	
	return new_string;
}

/* function to retrieve the execution path to write on the log-file */
char *retrieve_exe_path(struct path path_struct){
	char *tpath;
	char *path;
	
	tpath=kmalloc(1024,GFP_KERNEL);
	if(tpath == NULL)  return "";
	path = d_path(&path_struct, tpath, 1024);
	
	return path;
}

/* function to retrieve the pwd */
char *retrieve_pwd(void){

	struct path abs_path;
    char *buf, *full_path;

	buf = kmalloc(1024,GFP_KERNEL);
	if(buf == NULL) return "";

	get_fs_pwd(current->fs, &abs_path);

	full_path = dentry_path_raw(abs_path.dentry, buf, PATH_MAX);
	
	return full_path;

}


/* function to encrypt password with a random salt */
char *cipher_password(char *password, char *salt){
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned char digest[SIZE];
    char encrypted_password[64];
    char *cipher;
    int ret;
    int i;
 
    cipher = kmalloc((SIZE*2) +1, GFP_KERNEL);
    if (!cipher)
        return NULL;

    // Concatena la password e il salt
    memcpy((unsigned char*)encrypted_password, salt, SIZE);
    memcpy(encrypted_password + SIZE, password, strlen(password));
    
    // Inizializza il transform context
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        goto out_free_mem;
    }
    
    // Alloca la descrizione dello shash
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto out_free_tfm;
    }
    desc->tfm = tfm;
    
    // Calcola l'hash della password concatenata al salt
    ret = crypto_shash_digest(desc, encrypted_password, SIZE + strlen(password), digest);
    if (ret) {
        pr_err("Errore durante la computazione dell'hash\n");
        goto out_free_desc;
    }
    
    // Libera la memoria e rilascia il transform context
    kfree(desc);
    crypto_free_shash(tfm);
    
    // Stampa l'hash della password
    pr_info("Encrypted Password: ");
    for (i = 0; i < SIZE; i++){
        pr_cont("%02x", digest[i]);
        sprintf(cipher + (i*2), "%02x", digest[i]);
    }

    pr_cont("\n");
    sprintf(cipher + (i*2), "%c", '\0');
    
    return cipher;
 
out_free_desc:
    kfree(desc);
out_free_tfm:
    crypto_free_shash(tfm);
out_free_mem:
    return NULL;
}

/* function to generate the cryptographic hash of the file content */
char *generate_hash(const char *cmd_path)
{
        struct crypto_shash *hash_tfm;
        struct shash_desc *desc;
        unsigned char *digest;
        char *result = NULL;
        int ret = -ENOMEM;
        int i;

        /* hash transform allocation */
        hash_tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(hash_tfm))
        {
                printk(KERN_ERR "Failed to allocate hash transform\n");
                return NULL;
        }

        /* hash descriptor allocation */
        desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash_tfm), GFP_ATOMIC);
        if (!desc)
        {
                printk(KERN_ERR "Failed to allocate hash descriptor\n");
                goto out;
        }
        desc->tfm = hash_tfm;

        /* digest allocation */
        digest = kmalloc(32, GFP_ATOMIC);
        if (!digest)
        {
                printk(KERN_ERR "Failed to allocate hash buffer\n");
                goto out;
        }

        /* hash computation */
        ret = crypto_shash_digest(desc, cmd_path, strlen(cmd_path), digest);
        if (ret)
        {
                printk(KERN_ERR "Failed to calculate hash\n");
                goto out;
        }

        /* result allocation */
        result = kmalloc(2 * 32 + 1, GFP_ATOMIC);
        if (!result)
        {
                printk(KERN_ERR "Failed to allocate memory for result\n");
                goto out;
        }

        /* printing result */
        for (i = 0; i < 32; i++)
                sprintf(&result[i * 2], "%02x", digest[i]);

out:
        if (digest)
                kfree(digest);
        if (desc)
                kfree(desc);
        if (hash_tfm)
                crypto_free_shash(hash_tfm);

        return result;
}


