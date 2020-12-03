#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/slab.h>

int sum = 0;

int test_thread(void* _arg)
{
	int* arg = (int*)_arg;
	int value;
	value = __sync_add_and_fetch(&sum, *arg);
	printk("current sum = %d", value);
	return 0;
}

int __init simple_module_init(void)
{
	int i;
	int* arg;
	printk("simple module\n");
	for(i = 0; i < 4;i++){
		arg = (int*)kmalloc(sizeof(int), GFP_KERNEL);
		*arg = i;
		kthread_run(&test_thread, (void*)arg, "test_thread");
	}
	return 0;
}

void __exit simple_module_cleanup(void)
{
	printk("simple module end!\n");
}

module_init(simple_module_init);
module_exit(simple_module_cleanup);
MODULE_LICENSE("GPL");

