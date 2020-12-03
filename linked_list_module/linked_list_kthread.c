#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>


struct ll_node
{
	struct list_head list;
	int data;
};

struct list_head head;
spinlock_t counter_lock;
struct mutex mutex_lock;

int done = 0;

int ll_spin_insert(void* data)
{
	int j;
	int* value = (int*)data;
	for(j=0;j < 25000;j++){
		struct ll_node* new = kmalloc(sizeof(struct ll_node), GFP_KERNEL);
		new->data = 25000 * (*value) + j;
		spin_lock(&counter_lock);
		list_add(&new->list, &head);
		spin_unlock(&counter_lock);
	}
	__sync_fetch_and_add(&done, 1);
	kfree(data);
	return 0;
}

int ll_mutex_insert(void* data)
{
	int j;
	int* value = (int*)data;
	for(j=0;j < 25000;j++){
		struct ll_node* new = kmalloc(sizeof(struct ll_node), GFP_KERNEL);
		new->data = 25000 * (*value) + j;
		mutex_lock(&mutex_lock);
		list_add(&new->list, &head);
		spin_unlock(&mutex_lock);
	}
	__sync_fetch_and_add(&done, 1);
	kfree(data);
	return 0;
}

int ll_rw_insert(void* data)
{
	int j;
	int* value = (int*)data;
	for(j=0;j < 25000;j++){
		struct ll_node* new = kmalloc(sizeof(struct ll_node), GFP_KERNEL);
		new->data = 25000 * (*value) + j;
		mutex_lock(&mutex_lock);
		list_add(&new->list, &head);
		spin_unlock(&mutex_lock);
	}
	__sync_fetch_and_add(&done, 1);
	return 0;
}

int ll_spin_search(void* data)
{
	int* value = (int*)data;
	for(j=*value;j < 25000 * (*value) + 25000;j++){
		spin_lock(&counter_lock);
		list_for_each_entry(current_node, &head, list)
		{
			if(current_node->data == j){
				//found j
				break;
			}
		}
		spin_unlock(&counter_lock);
	}
	__sync_fetch_and_add(&done, 1);
	return 0;
}

int ll_mutex_search(void* data)
{
	return 0;
}

int ll_rw_search(void* data)
{
	return 0;
}
int ll_spin_delete_from(void* data)
{
	struct ll_node* current_node = (struct ll_node*)data;
	struct ll_node* next_node;
	int j;
	for(j=0;j < 25000;j++)
	{
		spin_lock(&counter_lock);
		list_del(&current_node->list);
		next_node = current_node->next;
		kfree(current_node);
		spin_unlock(&counter_lock);
		current_node = next_node;
	}
	
	__sync_fetch_and_add(&done, 1);
	return 0;
}

void linked_list_test(void)
{
	struct ll_node* current_node;
	ktime_t tbegin, tend;
	int i, j;
	struct ll_node* tmp;

	INIT_LIST_HEAD(&head);
	spin_lock_init(&counter_lock);

	done = 0;
	//insert
	tbegin = ktime_get();
	for(j = 0;j < 4;j++)
	{
		int* data = kmalloc(sizeof(int),GFP_KERNEL);
		*data = j;
		kthread_run(ll_spin_insert, data, "ll_spin_insert");
	}
	while(done != 4);
	tend = ktime_get();
	printk("insert, %d) Time elapsed:%llu", test_size[i], ktime_to_ns(tend - tbegin));
	
	//search
	done = 0;
	tbegin = ktime_get();
	for(j=0;j<4;j++)
	{
		int* data = kmalloc(sizeof(int), GFP_KERNEL);
		*data = j;
		kthread_run(ll_spin_search, data, "ll_spin_search");
	}
	while(done != 4);
	tend = ktime_get();
	printk("search, %d) Time elapsed:%llu", test_size[i], ktime_to_ns(tend - tbegin));
	
	//delete
	done = 0;
	tbegin = ktime_get();
	struct ll_head* from;
	from = head;
	for(i = 0;i < 4;i++){
		for(j = 0;j < 25000;j++){
			from = from->next;
		}
		kthread_run(ll_spin_delete_from, from, "ll_spin_delete_from");
	}
	while(done != 4);
	tend = ktime_get();
	printk("delete, %d) Time elapsed:%llu", test_size[i], ktime_to_ns(tend - tbegin));
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

