// SPDX-License-Identifier: GPL-2.0-only
/*
 * This module emits "Hello, world" on printk when loaded.
 *
 * It is designed to be used for basic evaluation of the module loading
 * subsystem (for example when validating module signing/verification). It
 * lacks any extra dependencies, and will not normally be loaded by the
 * system unless explicitly requested by name.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define PROC_DIR "mp1"
#define STATUS_FILE "status"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include "mp1_given.h"
// !!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!
// Please put your name and email here
MODULE_AUTHOR("Zhenhao Zhao <zz110@illinois.edu>");
MODULE_LICENSE("GPL");
#define MAX_PIDS 5000
#define BUF_SIZE (MAX_PIDS * 11)
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_status;
// Data structure to hold registered process details.
struct pid_entry {
    pid_t pid;
    unsigned long user_time;
    struct list_head list;
};
static LIST_HEAD(pid_list); // List head for registered processes.

static struct timer_list update_timer;
static struct workqueue_struct *mp1_workqueue;
static struct work_struct update_work;
struct mutex process_list_mutex; 

// This function gets called by the workqueue to update user CPU time for registered processes.
static void update_user_time_work(struct work_struct *work) {
    struct pid_entry *entry, *tmp;

    mutex_lock(&process_list_mutex);
    list_for_each_entry_safe(entry, tmp, &pid_list, list) {
        if (get_cpu_use(entry->pid, &entry->user_time) == 0) {
            printk(KERN_INFO "PID: %d, CPU Time: %lu\n", entry->pid, entry->user_time);
        }else{
            // If the process is dead or an error occurred, do nothing
        }
    }
    mutex_unlock(&process_list_mutex);
}
// Callback function when the timer fires.
void my_timer_callback(struct timer_list *timer) {
    // Schedule work when the timer expires
    queue_work(mp1_workqueue, &update_work);
    
    // Reschedule the timer for 5 seconds later
    mod_timer(&update_timer, jiffies + 5*HZ);
}



// Read function for /proc/mp1/status to provide current CPU times for registered processes.
static ssize_t mp1_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
    char buf[512];
    int len = 0;

    struct pid_entry *entry;

    mutex_lock(&process_list_mutex);
    list_for_each_entry(entry, &pid_list, list) {
        len += snprintf(buf + len, sizeof(buf) - len, "%d: %lu\n", entry->pid, entry->user_time);
    }
    mutex_unlock(&process_list_mutex);
    if (*ppos > 0 || len == 0)
        return 0;

    if (copy_to_user(ubuf, buf, len))
        return -EFAULT;
    *ppos = len;
    return len;
}
// Helper function to register a process by its PID.
void register_process(pid_t pid) {
    struct pid_entry *new_entry;

    new_entry = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);
    if (!new_entry) {
        printk(KERN_ALERT "MP1: Failed to allocate memory for process registration\n");
        return;
    }

    new_entry->pid = pid;
    new_entry->user_time = 0;

    list_add(&new_entry->list, &pid_list);

}
// Write function for /proc/mp1/status. Allows user-space to register PIDs.
static ssize_t mp1_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char *buf;
    pid_t *pids;
    int total_pids = 0;
    char *token;
    char *endptr;
    long pid;
    bool duplicate;
    int i, j;

    if (count > BUF_SIZE - 1 || count == 0) {
        return -EINVAL;
    }

    // Allocate memory for the buffer and PID list
    buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!buf) {
        return -ENOMEM;
    }

    pids = kmalloc(sizeof(pid_t) * MAX_PIDS, GFP_KERNEL);
    if (!pids) {
        kfree(buf);
        return -ENOMEM;
    }

    if (copy_from_user(buf, ubuf, count)) {
        kfree(buf);
        kfree(pids);
        return -EFAULT;
    }

    buf[count] = '\0';

    // Parsing the comma-separated list of PIDs
    while ((token = strsep(&buf, ",")) && total_pids < MAX_PIDS) {
        pid = simple_strtol(token, &endptr, 10);

        if (endptr == token) {
            kfree(buf);
            kfree(pids);
            return -EINVAL;
        }

        // Check for duplicates among the newly added PIDs
        duplicate = false;
        for (i = 0; i < total_pids; ++i) {
            if (pids[i] == (pid_t)pid) {
                duplicate = true;
                break;
            }
        }

        if (!duplicate) {
            pids[total_pids++] = (pid_t)pid;
        }
    }

    // Now, register the PIDs
    for (j = 0; j < total_pids; ++j) {
        register_process(pids[j]);
    }

    // Free the allocated memory
    kfree(buf);
    kfree(pids);

    return count;
}

static const struct proc_ops status_fops = {
    .proc_read  = mp1_read,
    .proc_write = mp1_write,
};

static int __init mp1_init(void) {
    // create /proc/mp1
    proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!proc_dir) {
        return -ENOMEM;
    }

    // create /proc/mp1/status
    proc_status = proc_create(STATUS_FILE, 0666, proc_dir, &status_fops);
    if (!proc_status) {
        remove_proc_entry(PROC_DIR, NULL);
        return -ENOMEM;
    }
    mp1_workqueue = create_singlethread_workqueue("mp1_workqueue");
    if (!mp1_workqueue) {
        printk(KERN_ALERT "mp1: Error creating workqueue\n");
        return -ENOMEM;
    }
    mutex_init(&process_list_mutex);

    // Initialize the workqueue task
    INIT_WORK(&update_work, update_user_time_work);

    // Setup the timer to fire in 5 seconds
    timer_setup(&update_timer, my_timer_callback, 0);
    mod_timer(&update_timer, jiffies + 5*HZ);

    printk(KERN_INFO "MP1 module loaded.\n");
    return 0;
}



static void __exit mp1_exit(void) {

    del_timer_sync(&update_timer);
    flush_workqueue(mp1_workqueue);
    destroy_workqueue(mp1_workqueue);
    mutex_destroy(&process_list_mutex);
    remove_proc_entry(STATUS_FILE, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);
    printk(KERN_INFO "MP1 module unloaded.\n");
}

module_init(mp1_init);
module_exit(mp1_exit);
