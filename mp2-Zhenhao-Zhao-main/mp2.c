#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include "mp2_given.h"
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <uapi/linux/sched/types.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
// !!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!
// Please put your name and email here
MODULE_AUTHOR("Zhenhao Zhao <zz110@illinois.edu");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CS-423 MP2");

#define DEBUG 1
#define DIRECTORY "mp2"
#define FILENAME "status"
#define MAX_BUFFER_SIZE 150
#define RUNNING 2
#define SLEEPING 1
#define READY 0
#define AC_RATE 693
unsigned long rate_sum;
static struct proc_dir_entry *mp2_dir, *status_file;

static LIST_HEAD(process_list);
static struct kmem_cache *mp2_task_struct_cache;

static DEFINE_SPINLOCK(sp_lock);
typedef struct mp2_task_struct {
	struct list_head list;
    struct task_struct *tsk;
    struct timer_list task_timer;

    pid_t pid;
    unsigned long task_period;
    unsigned long task_process_time; // processing_time

	int task_state;
}mp2_task_struct;

static struct task_struct *dispatching_thread;
static mp2_task_struct *currtask  = NULL;


mp2_task_struct* select_highest_priority_task(void) {
    // get highest priority
	mp2_task_struct *temp, *tempn;
	mp2_task_struct *target = NULL;
	unsigned long min_period;
	list_for_each_entry_safe(temp, tempn, &process_list, list) {
		if(temp->task_state == READY){
			if(target == NULL || min_period > temp->task_period){
				target = temp;
				min_period = temp->task_period;
			}
		}
	}
	return target;
}

static int dispatching_thread_fn(void *data) {
    //dispatch function
    mp2_task_struct *target;
	unsigned long flags;

	while(!kthread_should_stop()){
		spin_lock_irqsave(&sp_lock, flags);
		target = select_highest_priority_task();

		if(target == NULL || (currtask != NULL && target->task_period >= currtask->task_period)){
		}else{
			//switch
            struct sched_attr attr;
            if(currtask != NULL){
                currtask->task_state = READY;
                attr.sched_policy = SCHED_NORMAL;
                attr.sched_priority = 0;
                sched_setattr_nocheck(currtask->tsk,&attr);
            }
            //new task
            target->task_state = RUNNING;
            attr.sched_policy = SCHED_FIFO;
            attr.sched_priority = 99;
            sched_setattr_nocheck(target->tsk, &attr);
            currtask = target;
			//put it into run queue
			wake_up_process(target->tsk);
		}

		spin_unlock_irqrestore(&sp_lock, flags);

		//set kthread
		set_current_state(TASK_INTERRUPTIBLE);

		//sleep
		schedule();

	}
    return 0;
}


static ssize_t status_read(struct file *file, char __user *buffer, size_t count, loff_t *ppos) {

    char *buf;
    int copied, ret = 0;
    mp2_task_struct *tmp,*tempn;
    unsigned long flags;
    buf = kzalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) return -ENOMEM;

	spin_lock_irqsave(&sp_lock, flags);
    list_for_each_entry_safe(tmp, tempn,&process_list, list) {
        copied = sprintf(buf + ret, "%d: %lu, %lu\n", tmp->pid, tmp->task_period, tmp->task_process_time);
        ret += copied;
    }
	spin_unlock_irqrestore(&sp_lock, flags);

    // Make sure that we have the offset right for reading
    if (*ppos >= ret) {
        kfree(buf);
        return 0;
    }

    if (copy_to_user(buffer, buf, ret)) {
        kfree(buf);
        return -EFAULT;
    }
    *ppos = ret;

    kfree(buf);

    return ret;
}
static int admit_control(unsigned long period, unsigned long computation){
    //admit control only register if rate sum/period sum <= 0.693
    unsigned long rate = computation * 1000 / period;
    if (rate + rate_sum <= AC_RATE) {
	rate_sum += rate;
	return true;
    } else {
	return false;
    }

}
static void timer_handler(struct timer_list *timer){
    //timer call back
	mp2_task_struct *object = from_timer(object, timer, task_timer);
	unsigned long flags;
	spin_lock_irqsave(&sp_lock, flags);
	//make timer periodic
	if(mod_timer(&(object->task_timer), jiffies + msecs_to_jiffies(object->task_period)) != 0){
		printk(KERN_ALERT "mod_timer error\n");
	}
	if(object->task_state == SLEEPING){
		object->task_state = READY;
	}
	spin_unlock_irqrestore(&sp_lock, flags);
	//trigger kernel thread
	wake_up_process(dispatching_thread);
}
static void Register(pid_t pid, unsigned long period, unsigned long computation){

	//For REGISTRATION
    unsigned long flags;
    mp2_task_struct *object;
    if(admit_control(period, computation) == false){
        return;
    }

    object = kmem_cache_alloc(mp2_task_struct_cache, GFP_KERNEL);
    object->tsk = find_task_by_pid(pid);
    object->pid = pid;
    object->task_period = period;
    object->task_process_time = computation;
    object->task_state = SLEEPING;
    //add timer
    timer_setup(&(object->task_timer), timer_handler, 0);
	if(mod_timer(&(object->task_timer), jiffies + msecs_to_jiffies(period)) != 0){
		printk(KERN_ALERT "mod_timer error\n");
	} 
    spin_lock_irqsave(&sp_lock, flags);
    INIT_LIST_HEAD(&(object->list));
    
    list_add(&(object->list), &process_list);
    
    spin_unlock_irqrestore(&sp_lock, flags);

}
static void Deregister(pid_t pid){
    // deregister
    struct mp2_task_struct *temp, *tempn;
    unsigned long flags;
    unsigned long rate;
    // find by pid
    spin_lock_irqsave(&sp_lock, flags);
    list_for_each_entry_safe(temp, tempn, &process_list, list) {
        
        if(temp->pid == pid){
            if(temp == currtask){
                currtask = NULL;
                rate = temp->task_process_time* 1000 / temp->task_period;
	            rate_sum -= rate;
            }
            //remove timer 
            del_timer(&(temp->task_timer));
            list_del(&(temp->list));
            kmem_cache_free(mp2_task_struct_cache, temp);
            spin_unlock_irqrestore(&sp_lock, flags);
            return;
        }
        
    }
    spin_unlock_irqrestore(&sp_lock, flags);
}
static void mYield(pid_t pid){
    // yield function
    struct mp2_task_struct *temp, *tempn;
    unsigned long flags;
    list_for_each_entry_safe(temp, tempn, &process_list, list) {
        spin_lock_irqsave(&sp_lock, flags);
        if(temp->pid == pid){
            temp->task_state = SLEEPING;
            set_current_state(TASK_UNINTERRUPTIBLE);
            currtask = NULL;
            
            spin_unlock_irqrestore(&sp_lock, flags);
            break;
        }
        spin_unlock_irqrestore(&sp_lock, flags);
    }

    //trigger kernel thread
    wake_up_process(dispatching_thread);
    //sleep
    schedule();
}
static ssize_t status_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {

    char *buf;
    char op;
    pid_t pid;
    unsigned long period, computation;

    buf = kzalloc(count, GFP_KERNEL);
    if (!buf) return -ENOMEM;
    //copy input
    if (copy_from_user(buf, buffer, count)) {
        kfree(buf);
        return -EFAULT;
    }

    switch (buf[0]) {
        case 'R': // Register

            sscanf(buf, "%c,%u,%lu,%lu", &op, &pid, &period, &computation);
            Register(pid,period,computation);
            break;

        case 'D': // Deregister
            sscanf(buf, "%c,%u", &op, &pid);
            Deregister(pid);
            break;

        case 'Y': // Yield
            // Implement your yield functionality here
            sscanf(buf, "%c,%u", &op, &pid);
            mYield(pid);
			break;

        default:
            printk(KERN_WARNING "Unknown command\n");
    }
    kfree(buf);

    return count;
}

static void destroy(void){
    struct mp2_task_struct *temp, *tempn;
	unsigned long flags;
	spin_lock_irqsave(&sp_lock, flags);
	
	list_for_each_entry_safe(temp, tempn, &process_list, list) {
		del_timer(&(temp->task_timer));
        list_del(&(temp->list));
        kmem_cache_free(mp2_task_struct_cache, temp);
	}
	
	spin_unlock_irqrestore(&sp_lock, flags);

    if (mp2_task_struct_cache){
        kmem_cache_destroy(mp2_task_struct_cache);
    }
    if (dispatching_thread){
        kthread_stop(dispatching_thread);
    }
}

static const struct proc_ops mp2_fops = {
    .proc_read = status_read,
    .proc_write = status_write,
};
// mp2_init - Called when module is loaded
int __init mp2_init(void)
{
#ifdef DEBUG
	printk(KERN_ALERT "MP2 MODULE LOADING\n");
#endif
	// Insert your code here ...
	mp2_dir = proc_mkdir(DIRECTORY, NULL);
    if (!mp2_dir) {
        printk(KERN_WARNING "Error creating proc directory\n");
        return -ENOMEM;
    }

    // Create status file
    status_file = proc_create(FILENAME, 0666, mp2_dir, &mp2_fops);
    if (!status_file) {
        printk(KERN_WARNING "Error creating proc file\n");
        remove_proc_entry(DIRECTORY, NULL);
        return -ENOMEM;
    }

    rate_sum =0;
	dispatching_thread = kthread_create(dispatching_thread_fn, NULL, "dpspatch_thread");

	wake_up_process(dispatching_thread);
	if(!IS_ERR(dispatching_thread)){
		printk(KERN_ALERT "Thread Created successfully\n");
	}else{
		printk(KERN_ALERT "Thread creation failed\n");
	}
	mp2_task_struct_cache = kmem_cache_create(
			"cache",
			sizeof(mp2_task_struct),
			0,
			SLAB_HWCACHE_ALIGN,
			NULL);

	printk(KERN_ALERT "MP2 MODULE LOADED\n");
	return 0;
}

// mp2_exit - Called when module is unloaded
void __exit mp2_exit(void)
{
#ifdef DEBUG
	printk(KERN_ALERT "MP2 MODULE UNLOADING\n");
#endif
	// Insert your code here ...

    destroy();
    remove_proc_entry(FILENAME, mp2_dir);
    remove_proc_entry(DIRECTORY, NULL);
	printk(KERN_ALERT "MP2 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp2_init);
module_exit(mp2_exit);