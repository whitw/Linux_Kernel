#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>

struct ll_node
{
	struct list_head list;
	int data;
};

void linked_list_test(void)
{
	struct list_head head3, head4, head5; //each are used to test 10**3, 10**4, 10**5 entries
	struct ll_node* current_node;
	ktime_t tbegin, tend;
	int i;
	struct ll_node* tmp;

	INIT_LIST_HEAD(&head3);
	INIT_LIST_HEAD(&head4);
	INIT_LIST_HEAD(&head5);

	//insert
	tbegin = ktime_get();
	for(i = 0;i <1000;i++)
	{
		struct ll_node* new = kmalloc(sizeof(struct ll_node), GFP_KERNEL);
		new->data = i;
		list_add(&new->list, &head3);
	}
	tend = ktime_get();
	printk("insert, 1000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
	tbegin = tend;
	for (i = 0;i < 10000;i++)
	{
		struct ll_node* new = kmalloc(sizeof(struct ll_node), GFP_KERNEL);
		new->data = i;
		list_add(&new->list, &head4);
	}
	tend = ktime_get();
	printk("insert, 10000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
	tbegin = tend;
	for (i = 0;i < 100000;i++)
	{
		struct ll_node* new = kmalloc(sizeof(struct ll_node), GFP_KERNEL);
		new->data = i;
		list_add(&new->list, &head5);
	}
	tend = ktime_get();
	printk("insert, 100000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
	tbegin = tend;
	//search
	for(i=0;i<1000;i++){
		list_for_each_entry(current_node, &head3, list)
		{
			if(current_node->data == i){
				//found i
				break;
			}
		}
	}
	tend = ktime_get();
	printk("search, 1000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
	tbegin = tend;
	for(i=0;i<10000;i++){
		list_for_each_entry(current_node, &head4, list)
		{
			if(current_node->data == i){
				//found i
				break;
			}
		}
	}
	tend = ktime_get();
	printk("search, 10000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
	tbegin = tend;
	for(i=0;i<100000;i++){
		list_for_each_entry(current_node, &head5, list)
		{
			if(current_node->data == i){
				//found i
				break;
			}
		}
	}
	tend = ktime_get();
	printk("search, 100000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
	tbegin = tend;
	
	//delete
	list_for_each_entry_safe(current_node, tmp, &head3, list)
	{
		list_del(&current_node->list);
		kfree(current_node);
	}
	tend = ktime_get();
	printk("delete, 1000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
	tbegin = tend;
	list_for_each_entry_safe(current_node, tmp, &head4, list)
	{
		list_del(&current_node->list);
		kfree(current_node);
	}
	tend = ktime_get();
	printk("delete, 10000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
	tbegin = tend;
	list_for_each_entry_safe(current_node, tmp, &head5, list)
	{
		list_del(&current_node->list);
		kfree(current_node);
	}
	tend = ktime_get();
	printk("delete, 100000) Time elapsed:%llu", ktime_to_ns(tend - tbegin));
}

int __init linked_list_module_init(void)
{
	printk("begin linked list module\n");
	linked_list_test();
	return 0;
}

void __exit linked_list_module_cleanup(void)
{
	printk("end linked list module\n");
}

module_init(linked_list_module_init);
module_exit(linked_list_module_cleanup);
MODULE_LICENSE("GPL");

