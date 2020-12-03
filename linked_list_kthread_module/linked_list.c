#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/sched.h>


struct ll_node
{
	struct list_head list;
	int data;
};

struct list_head head;
spinlock_t counter_lock;
struct mutex m_lock;
struct rw_semaphore rw_lock;

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
		mutex_lock(&m_lock);
		list_add(&new->list, &head);
		mutex_unlock(&m_lock);
	}
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
		down_write(&rw_lock);
		list_add(&new->list, &head);
		up_write(&rw_lock);
	}
	return 0;
}

int ll_spin_search(void* data)
{
	int j;
	int* value = (int*)data;
	struct ll_node* current_node;
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
	return 0;
}

int ll_mutex_search(void* data)
{
	int j;
	int* value = (int*)data;
	struct ll_node* current_node;
	for(j=*value;j < 25000 * (*value) + 25000;j++){
		mutex_lock(&m_lock);
		list_for_each_entry(current_node, &head, list)
		{
			if(current_node->data == j){
				//found j
				break;
			}
		}
		mutex_unlock(&m_lock);
	}
	return 0;
}

int ll_rw_search(void* data)
{
	int j;
	int* value = (int*)data;
	struct ll_node* current_node;
	for(j=*value;j < 25000 * (*value) + 25000;j++){
		down_read(&rw_lock);
		list_for_each_entry(current_node, &head, list)
		{
			if(current_node->data == j){
				//found j
				break;
			}
		}
		up_read(&rw_lock);
	}
	return 0;
}

void linked_list_test(void)
{
	ktime_t tbegin, tend;
	int i;
	struct ll_node* current_node, *tmp;
	struct task_struct* task_list[4];
	INIT_LIST_HEAD(&head);
	spin_lock_init(&counter_lock);
	
	
	//insert
	tbegin = ktime_get();
	for(i = 0;i < 4;i++)
	{
		int* data = kmalloc(sizeof(int),GFP_KERNEL);
		*data = i;
		task_list[i] = kthread_run(ll_spin_insert, data, "ll_spin_insert");
	}
	for(i=0;i<4;i++){
		kthread_stop(task_list[i]);
	}
	tend = ktime_get();
	printk("Spinlock linked list insert time : %llu ns", ktime_to_ns(tend - tbegin));
	//search
	tbegin = ktime_get();
	for(i=0;i<4;i++)
	{
		int* data = kmalloc(sizeof(int), GFP_KERNEL);
		*data = i;
		task_list[i] = kthread_run(ll_spin_search, data, "ll_spin_search");
	}
	for(i=0;i<4;i++)
	{
		kthread_stop(task_list[i]);
	}
	tend = ktime_get();
	printk("Spinlock linked list search time : %llu ns", ktime_to_ns(tend - tbegin));
	//delete
	list_for_each_entry_safe(current_node, tmp, &head, list)
	{
		list_del(&current_node->list);
		kfree(current_node);
	}
	
	
	
	
	
	
	
	
	
	mutex_init(&m_lock);
	//insert
	tbegin = ktime_get();
	for(i = 0;i < 4;i++)
	{
		int* data = kmalloc(sizeof(int),GFP_KERNEL);
		*data = i;
		task_list[i] = kthread_run(ll_mutex_insert, data, "ll_spin_insert");
	}
	for(i=0;i<4;i++){
		kthread_stop(task_list[i]);
	}
	tend = ktime_get();
	printk("Mutex linked list insert time : %llu ns", ktime_to_ns(tend - tbegin));
	//search
	tbegin = ktime_get();
	for(i=0;i<4;i++)
	{
		int* data = kmalloc(sizeof(int), GFP_KERNEL);
		*data = i;
		task_list[i] = kthread_run(ll_mutex_search, data, "ll_spin_search");
	}
	for(i=0;i<4;i++)
	{
		kthread_stop(task_list[i]);
	}
	tend = ktime_get();
	printk("Mutex linked list search time : %llu ns", ktime_to_ns(tend - tbegin));
	//delete
	list_for_each_entry_safe(current_node, tmp, &head, list)
	{
		list_del(&current_node->list);
		kfree(current_node);
	}
	
	init_rwsem(&rw_lock);
	
	//insert
	tbegin = ktime_get();
	for(i = 0;i < 4;i++)
	{
		int* data = kmalloc(sizeof(int),GFP_KERNEL);
		*data = i;
		task_list[i] = kthread_run(ll_rw_insert, data, "ll_spin_insert");
	}
	for(i=0;i<4;i++){
		kthread_stop(task_list[i]);
	}
	tend = ktime_get();
	printk("RW Semaphore linked list insert time : %llu ns", ktime_to_ns(tend - tbegin));
	//search
	tbegin = ktime_get();
	for(i=0;i<4;i++)
	{
		int* data = kmalloc(sizeof(int), GFP_KERNEL);
		*data = i;
		task_list[i] = kthread_run(ll_rw_search, data, "ll_spin_search");
	}
	for(i=0;i<4;i++)
	{
		kthread_stop(task_list[i]);
	}
	tend = ktime_get();
	printk("RW Semaphore linked list search time : %llu ns", ktime_to_ns(tend - tbegin));
	//delete
	list_for_each_entry_safe(current_node, tmp, &head, list)
	{
		list_del(&current_node->list);
		kfree(current_node);
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

