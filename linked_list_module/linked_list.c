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
	struct list_head head;
	struct ll_node* current_node;
	ktime_t tbegin, tend;
	int i, j;
	struct ll_node* tmp;
	int test_size[3] = {1000, 10000, 100000};

	for(i = 0;i <3;i++){
		INIT_LIST_HEAD(&head);

		//insert
		tbegin = ktime_get();
		for(j = 0;j <test_size[i];j++)
		{
			struct ll_node* new = kmalloc(sizeof(struct ll_node), GFP_KERNEL);
			new->data = j;
			list_add(&new->list, &head);
		}
		tend = ktime_get();
		printk("insert, %d) Time elapsed:%llu", test_size[i], ktime_to_ns(tend - tbegin));
		
		//search
		tbegin = ktime_get();
		for(j=0;j<test_size[i];j++)
		{
			list_for_each_entry(current_node, &head, list)
			{
				if(current_node->data == j){
					//found j
					break;
				}
			}
		}
		tend = ktime_get();
		printk("search, %d) Time elapsed:%llu", test_size[i], ktime_to_ns(tend - tbegin));
		
		//delete
		tbegin = ktime_get();
		list_for_each_entry_safe(current_node, tmp, &head, list)
		{
			list_del(&current_node->list);
			kfree(current_node);
		}
		tend = ktime_get();
		printk("delete, %d) Time elapsed:%llu", test_size[i], ktime_to_ns(tend - tbegin));
	}
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

