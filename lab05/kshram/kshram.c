/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include "kshram.h"

static dev_t devnum;
static struct class *clazz;
static struct device *devices[8];
static unsigned long sizes[8];
static struct cdev c_dev;

static long kshrammod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
  int minor = iminor(fp->f_inode);
	if(cmd == KSHRAM_GETSLOTS) {
    return 8;
  } else if(cmd == KSHRAM_GETSIZE) {
    return sizes[minor];
  } else if(cmd == KSHRAM_SETSIZE) {
    ClearPageReserved(virt_to_page(devices[minor]->driver_data));
    devices[minor]->driver_data = krealloc(devices[minor]->driver_data, arg, GFP_KERNEL);
    sizes[minor] = arg;
    SetPageReserved(virt_to_page(devices[minor]->driver_data));
    return arg;
  }
	return -ENOTTY;
}

static int kshrammod_dev_mmap(struct file *filp, struct vm_area_struct *vma) {
  int minor = iminor(filp->f_inode);
  unsigned long len = vma->vm_end - vma->vm_start;
  if (remap_pfn_range(vma, vma->vm_start,
                      page_to_pfn(virt_to_page(devices[minor]->driver_data)), len,
                      vma->vm_page_prot) < 0) {
    pr_err("could not map the address area\n");
    return -EIO;
  }
  printk(KERN_INFO "kshram/mmap: idx %d size %lu\n", minor, sizes[minor]);
  
  return 0;
}

static const struct file_operations kshrammod_dev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = kshrammod_dev_ioctl,
  .mmap = kshrammod_dev_mmap
};

static int kshrammod_proc_read(struct seq_file *m, void *v) {
  for(int i=0; i<8; ++i)
    seq_printf(m, "0%d: %lu\n", i, sizes[i]);
	return 0;
}

static int kshrammod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, kshrammod_proc_read, NULL);
}

static const struct proc_ops kshrammod_proc_fops = {
  .proc_open = kshrammod_proc_open,
  .proc_read = seq_read,
	.proc_lseek = seq_lseek,
  .proc_release = single_release
};

static char *kshrammod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshrammod_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 8, "driver") < 0)
		return -1;
	if((clazz = class_create(THIS_MODULE, "class")) == NULL)
		goto release_region;
	clazz->devnode = kshrammod_devnode;

  for(int i=0; i<8; ++i) {
    if((devices[i] = device_create(clazz, NULL, MKDEV(MAJOR(devnum), MINOR(devnum)+i), NULL, "kshram%d", i)) == NULL)
      goto release_device;
    devices[i]->driver_data = kzalloc(PAGE_SIZE, GFP_KERNEL);
    sizes[i] = PAGE_SIZE;
    SetPageReserved(virt_to_page(devices[i]->driver_data));
    printk(KERN_INFO "kshram%d: %lu bytes allocated @ %px\n", i, PAGE_SIZE, devices[i]->driver_data);
  }
  cdev_init(&c_dev, &kshrammod_dev_fops);
  if(cdev_add(&c_dev, MKDEV(MAJOR(devnum), MINOR(devnum)), 8) == -1)
    goto release_device;

  proc_create("kshram", 0, NULL, &kshrammod_proc_fops);

	printk(KERN_INFO "kshrammod: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
  for(int i=0; i<8; ++i) {
    if(devices[i]) {
      ClearPageReserved(virt_to_page(devices[i]->driver_data));
      kfree(devices[i]->driver_data);
      device_destroy(clazz, MKDEV(MAJOR(devnum), MINOR(devnum)+i));
    }
  } 
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 8);
	return -1;
}

static void __exit kshrammod_cleanup(void)
{
	remove_proc_entry("kshram", NULL);

  cdev_del(&c_dev);
  for(int i=0; i<8; ++i) {
    ClearPageReserved(virt_to_page(devices[i]->driver_data));
    kfree(devices[i]->driver_data);
    
    device_destroy(clazz, MKDEV(MAJOR(devnum), MINOR(devnum)+i));
  }
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 8);

	printk(KERN_INFO "kshrammod: cleaned up.\n");
}

module_init(kshrammod_init);
module_exit(kshrammod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
