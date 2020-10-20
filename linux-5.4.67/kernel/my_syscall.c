#include <linux/kernel.h>

asmlinkage long sys_mycall_sh(void) {
	printk("20165367 Kim Sanghyun, Custom syscall\n");

	return 0;
}
