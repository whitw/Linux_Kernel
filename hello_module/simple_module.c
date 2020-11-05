#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

int __init simple_module_init(void)
{
	printk("simple module\n");
	return 0;
}

void __exit simple_module_cleanup(void)
{
	printk("simple module end!\n");
}

module_init(simple_module_init);
module_exit(simple_module_cleanup);
MODULE_LICENSE("GPL");

