#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include "mp3_given.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhenhao Zhao");
MODULE_DESCRIPTION("CS-423 MP3");

#define DEBUG 1
#define DIRECTORY "mp3"
#define FILENAME "status"
#define MAX_BUFFER_SIZE 4096
static struct proc_dir_entry *mp3_dir, *status_file;

#define MONITOR_CHRDEV "mp3_chrdev"


#define NPAGES 128
#define MY_MAJOR 423
#define MY_MINOR 0
static struct cdev my_cdev;

struct kmem_cache *tasks_cache;

// Spinlock
spinlock_t sl;

// mapped buffer
unsigned long* mapped;
// mapped buffer offset
unsigned long mapped_offset = 0;


static struct workqueue_struct *wq;

static void work_handler(struct work_struct *work_arg);

#define MONITOR_WQ "monitor_wq"

DECLARE_DELAYED_WORK(monitor_work, work_handler);


struct mp3_task_struct {
   struct list_head next;
   unsigned int pid;

   unsigned long utilization;
   unsigned long major_pf;
   unsigned long minor_pf;
};
LIST_HEAD(reg_task_list);

// Work handler for monitoring tasks
static void work_handler(struct work_struct *work_arg) {
   unsigned long flags;

   // Spinlock lock
   spin_lock_irqsave(&sl, flags);

   struct mp3_task_struct *cur, *temp;
   unsigned long min_flt, maj_flt, utime, stime;
   unsigned long sum_min_flt = 0, sum_maj_flt = 0, sum_util = 0;
   int ret;

   // Iterate the whole linked list to update each registered process
   list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
      // Get the task PCB corresponding information by PID
      ret = get_cpu_use((int)cur->pid, &min_flt, &maj_flt, &utime, &stime);
      if (ret != 0) {
      list_del(&cur->next);
      kmem_cache_free(tasks_cache, cur);
      } else {
         cur->utilization = utime + stime;
         cur->major_pf = maj_flt;
         cur->minor_pf = min_flt;
      }
   }

    // Accumulate stats for all tasks
   list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
   // Get the task PCB corresponding information by PID
      sum_util += cur->utilization;
      sum_min_flt += cur->minor_pf;
      sum_maj_flt += cur->major_pf;
   }

   // Copy to the mapped buffer
   *(mapped + mapped_offset++) = jiffies;
   *(mapped + mapped_offset++) = sum_min_flt;
   *(mapped + mapped_offset++) = sum_maj_flt;
   *(mapped + mapped_offset++) = sum_util;

   // Spinlock unlock
   spin_unlock_irqrestore(&sl, flags);

   // Queue next monitor work
   queue_delayed_work(wq, &monitor_work, msecs_to_jiffies(50));

}
// mmap operation for character device
static int my_mmap(struct file *filp, struct vm_area_struct *vma) {
   unsigned long len, pfn, offset;
   int ret;
   len = vma->vm_end - vma->vm_start;

   for (offset = 0; offset < len; offset += PAGE_SIZE) {
      pfn = vmalloc_to_pfn((void *)((unsigned long)mapped + offset));
      ret = remap_pfn_range(vma, vma->vm_start + offset, pfn, PAGE_SIZE, vma->vm_page_prot);
      if (ret < 0) {
         printk(KERN_ERR "could not map the vmlloc address page\n");
         return -1;
      }
   }
   return 0;
}

static int my_open(struct inode *inode, struct file *filp) {
    return 0;
}

static int my_close(struct inode *inode, struct file *filp) {
    return 0;
}

// Character device operation options
static const struct file_operations mp3_chrdev_fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_close,
    .mmap = my_mmap
};
// Function to register a process
static ssize_t Register(pid_t pid) {
   struct mp3_task_struct *task_ptr;
   struct mp3_task_struct *cur, *temp;
   unsigned long flags, min_flt, maj_flt, utime, stime;
   int ret, size = 0;

   // Get the task PCB corresponding information by PID
   ret = get_cpu_use((int)pid, &min_flt, &maj_flt, &utime, &stime);


   task_ptr = kmem_cache_alloc(tasks_cache, GFP_KERNEL);

   task_ptr->pid = pid;
   task_ptr->utilization = utime + stime;
   task_ptr->major_pf = maj_flt;
   task_ptr->minor_pf = min_flt;

   INIT_LIST_HEAD(&task_ptr->next);

   spin_lock_irqsave(&sl, flags);
   list_add(&task_ptr->next, &reg_task_list);
   list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
   size++;
   }

   if (size == 1) {
      memset(mapped, -1L, NPAGES * PAGE_SIZE);
      queue_delayed_work(wq, &monitor_work, msecs_to_jiffies(50));
   }


   spin_unlock_irqrestore(&sl, flags);

   return 0;
}


// Function to deregister a process
static ssize_t Deregister(pid_t pid) {
   int flag = 0;
   unsigned long flags;

   // Spinlock lock
   spin_lock_irqsave(&sl, flags);

   struct mp3_task_struct *cur, *temp;
   int size = 0;

   list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
   size++;

   if (cur->pid == pid) {
      flag = 1;
      list_del(&cur->next);
      kmem_cache_free(tasks_cache, cur);
   }
   }


   if (size == 1) {      
      cancel_delayed_work_sync(&monitor_work);
      mapped_offset = 0;
   }

   spin_unlock_irqrestore(&sl, flags);

   if (flag == 0) 
   return -EFAULT;

   return 0;
}
// Write operation for the status file in procfs
static ssize_t status_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {

    char *buf;
    char op;
    pid_t pid;


    buf = kzalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) return -ENOMEM;
    //copy input
    if (copy_from_user(buf, buffer, count)) {
        kfree(buf);
        return -EFAULT;
    }

    switch (buf[0]) {
        case 'R': // Register

            sscanf(buf, "%c %u", &op, &pid);
            Register(pid);
            break;

        case 'U': // Deregister
            sscanf(buf, "%c %u", &op, &pid);
            Deregister(pid);
            break;
			break;

        default:
            printk(KERN_WARNING "Unknown command\n");
    }
    kfree(buf);

    return count;
}
// Read operation for the status file in procfs
static ssize_t status_read(struct file *file, char __user *buffer, size_t count, loff_t *ppos) {

    char *buf;
    int copied, ret = 0;
    struct mp3_task_struct *tmp,*tempn;
    unsigned long flags;
    buf = kzalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) return -ENOMEM;

	spin_lock_irqsave(&sl, flags);
    list_for_each_entry_safe(tmp, tempn,&reg_task_list, next) {
        copied = sprintf(buf + ret, "%u\n", tmp->pid);
        ret += copied;
    }
	spin_unlock_irqrestore(&sl, flags);
   if (copied == 0) {
      kfree(buf);
      copied = sprintf(buf, "No PID registered\n");
   }
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
static const struct proc_ops mp3_fops = {
    .proc_read = status_read,
    .proc_write = status_write,
};


// mp1_init - Called when module is loaded
int __init mp3_init(void)
{
   int ret;
   unsigned long i;
   dev_t dev_num;
   #ifdef DEBUG
   printk(KERN_ALERT "MP3 MODULE LOADING\n");
   #endif
   // Insert your code here ...
   mp3_dir = proc_mkdir(DIRECTORY, NULL);
   if (!mp3_dir) {
      printk(KERN_WARNING "Error creating proc directory\n");
      return -ENOMEM;
   }

   // Create status file
   status_file = proc_create(FILENAME, 0666, mp3_dir, &mp3_fops);
   if (!status_file) {
      printk(KERN_WARNING "Error creating proc file\n");
      remove_proc_entry(DIRECTORY, NULL);
      return -ENOMEM;
   }

   dev_num = MKDEV(MY_MAJOR, MY_MINOR);
   
   ret = register_chrdev_region(dev_num, 1, MONITOR_CHRDEV);
   if (ret < 0) {
      printk(KERN_WARNING "Can't register major number %d\n", MY_MAJOR);
      return ret;
   }
   // Initialize and add the character device to the system
   cdev_init(&my_cdev, &mp3_chrdev_fops);
   my_cdev.owner = THIS_MODULE;
   ret = cdev_add(&my_cdev, dev_num, 1);
   if (ret < 0) {
      printk(KERN_WARNING "Can't add char device\n");
      unregister_chrdev_region(dev_num, 1);
      return ret;
   }
   tasks_cache = KMEM_CACHE(mp3_task_struct, 0);

   // Allocate the vmalloc buffer in size 128 * 4KB
   mapped = (unsigned long*)vmalloc(NPAGES * PAGE_SIZE);
   // Set the page reversed bit
   for(i = 0; i < NPAGES * PAGE_SIZE; i += PAGE_SIZE) {
      SetPageReserved(vmalloc_to_page((void *)((unsigned long)mapped + i)));
   }

   // Initialize a new workqueue
   wq = alloc_workqueue(MONITOR_WQ, WQ_MEM_RECLAIM, 0);

   // Make a new spinlock for sychronization
   spin_lock_init(&sl);



   printk(KERN_ALERT "MP3 MODULE LOADED\n");
   return 0;   
}

// mp1_exit - Called when module is unloaded
void __exit mp3_exit(void)
{
   struct mp3_task_struct *cur, *temp;
   unsigned long i;
   dev_t dev_num;
   #ifdef DEBUG
   printk(KERN_ALERT "MP3 MODULE UNLOADING\n");
   #endif
   // Insert your code here ...
   proc_remove(status_file);
   proc_remove(mp3_dir);

   // Destroy the workqueue
   if (wq != NULL) {

      cancel_delayed_work_sync(&monitor_work);
      destroy_workqueue(wq);
   }

   //Iterate the whole linked list to delete the PID equals this pid
   list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
      list_del(&cur->next);
      kmem_cache_free(tasks_cache, cur);
   }
   cdev_del(&my_cdev);

   // Unregister the device region
   dev_num = MKDEV(MY_MAJOR, MY_MINOR);
   unregister_chrdev_region(dev_num, 1);
   //unregister_chrdev(chrdev_major, MONITOR_CHRDEV);

   // Clear the page reversed bit and then vfree
   for(i = 0; i < NPAGES * PAGE_SIZE; i += PAGE_SIZE) {
      ClearPageReserved(vmalloc_to_page((void *)((unsigned long)mapped + i)));
   }
   vfree(mapped);

   kmem_cache_destroy(tasks_cache);

   

   printk(KERN_ALERT "MP3 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp3_init);
module_exit(mp3_exit);
