#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>

struct my_node
{
	struct rb_node node;
	int key, value;
};

int rb_insert(struct rb_root* root, struct my_node* my)
{
	struct rb_node** curr = &(root->rb_node), *parent = NULL;
	while(*curr){
		parent = *curr;
		if(rb_entry(*curr, struct my_node, node)->key < my->key){
			curr = &((*curr)->rb_right);
		}
		else if(rb_entry(*curr, struct my_node, node)->key > my->key){
			curr = &((*curr)->rb_left);
		}
		else return -1;
	}
	rb_link_node(&(my->node), parent, curr);
	rb_insert_color(&(my->node), root);
	return 0;
}

struct rb_node* rb_search(int to_search, struct rb_node* root)
{
	struct rb_node* curr = root;
	if(rb_entry(curr, struct my_node, node)->key == to_search){
		return curr;
	}
	else if(rb_entry(curr, struct my_node, node)->key < to_search){
		if(curr->rb_left) return rb_search(to_search, rb_prev(curr));
		else return NULL;
	}
	else{
		if(curr->rb_right) return rb_search(to_search, rb_next(curr));
		else return NULL;
	}

}

void rb_delete_tree(struct rb_node* root_node, struct rb_root* root){
	if(root_node->rb_left){
		rb_delete_tree(root_node->rb_left, root);
	}
	if(root_node->rb_right){
		rb_delete_tree(root_node->rb_right, root);
	}
	rb_erase(root_node, root);
}

void rbtree_test(void)
{
	int do_size[3] = {1000, 10000, 100000};
	struct rb_root root_node[3] = {RB_ROOT, RB_ROOT, RB_ROOT};
	int i, j;
	ktime_t tbegin, tend;

	//insert:
	printk("begin insertion");
	for(i = 0;i < 3; i++){
		tbegin = ktime_get();
		for(j=0;j<do_size[i];j++){
			struct my_node* new_node = kmalloc(sizeof(struct my_node), GFP_KERNEL);
			if(!new_node){
				printk("met !new_node condition");
				return;
			}
			new_node->value = i * 10;
			new_node->key = i;
			rb_insert(&root_node[i], new_node);
		}
		tend = ktime_get();
		printk("insert, %d) Time elapsed:%llu",do_size[i], ktime_to_ns(tend - tbegin));
	}
	//search
	printk("begin search");
	for(i=0;i < 3;i++){
		tbegin = ktime_get();
		for(j=0;j<do_size[i];j++){
			rb_search(j, root_node[i].rb_node);
		}
		tend = ktime_get();
		printk("search, %d) Time elapsed:%llu", do_size[i], ktime_to_ns(tend - tbegin));
	}
	printk("begin deletion");
	//delete
	for(i=0;i < 3;i++){
		tbegin = ktime_get();
		rb_delete_tree(root_node[i].rb_node, &root_node[i]);
		tend = ktime_get();
		printk("delete, %d) Time elapsed:%llu", do_size[i], ktime_to_ns(tend - tbegin));
	}
}

int __init rbtree_module_init(void)
{
	printk("begin rbtree module\n");
	rbtree_test();
	return 0;
}

void __exit rbtree_module_cleanup(void)
{
	printk("end rbtree module\n");
}

module_init(rbtree_module_init);
module_exit(rbtree_module_cleanup);
MODULE_LICENSE("GPL");

