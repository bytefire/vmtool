#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/timekeeping.h>
#include <linux/time64.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <asm/msr.h>

#define BUF_LEN 32
#define MAX_LEN 256
#define MSR_IA32_VMX_BASIC 0x00000480
/* isolate bits 44:32 of MSR_IA32_VMX_BASIC */
#define VMCS_SIZE(x) (((x) << 19) >> 51)
#define NO_CURRENT_VMCS 0xffffffffffffffff
#define MIN(a,b) ((a)<(b) ? (a):(b))

struct vm_vcpu_info {
	u64 vmcs_addr;
	/* TODO: currently this is seconds since epoch. we want to be more accurate */
	time64_t last_seen;
	struct list_head list;
};


struct per_cpu_info {
	struct dentry *cpu_dir;
	struct list_head vcpu_list;
};

struct vm_info {
	struct dentry *root;
	u64 msr_vmx_basic;
	struct task_struct **threads;
	int thread_count;
	struct per_cpu_info *per_cpu_arr;
	int stop_per_cpu_threads;
};

static struct vm_info *vm_info;

static u64 get_vmx_basic(void)
{
	u32 msrlow, msrhigh;
	u64 ret;

	rdmsr(MSR_IA32_VMX_BASIC, msrlow, msrhigh);
	ret = msrhigh;
	ret = (ret << 32) | msrlow;

	return ret;
}

static int create_debugfs(void)
{
	struct dentry *root;

	root = debugfs_create_dir("vmtool", NULL);
	if (root == NULL || IS_ERR(root)) {
		pr_warn("vmtool: can't create debugfs entries. not going to load the module.\n");
		return PTR_ERR(root);
	}

	vm_info->root = root;
	debugfs_create_x64("vmx-basic", 0444, root, &vm_info->msr_vmx_basic);

	return 0;
}

static int get_vmcs_addr(u64 *addr)
{
	int ret = 0;
	u64 q;

	/* TODO: this leads to linker warning about modified stack for
	 * the caller of this function.
	 */
	asm volatile ("1: vmptrst (%%rax); movl $0, %0;"
                "2:\t\n"
                "\t.section .fixup,\"ax\"\n"
                "3:\tmov\t$-1, %0\n"
                "\tjmp\t2b\n"
                "\t.previous\n"
                _ASM_EXTABLE(1b, 3b)
                : "=r"(ret)
                : "a"(&q)
                : "memory"
	);

	*addr = q;
	if (q == NO_CURRENT_VMCS)
		ret = -1;

	return ret;
}

static int per_cpu_create_debugfs(int cpu_num)
{
	struct dentry *dir;
	char dir_name[8]; /* something like cpu-001 */

	snprintf(dir_name, 8, "cpu-%03d", cpu_num);
	dir = debugfs_create_dir(dir_name, vm_info->root);
	if (dir == NULL || IS_ERR(dir)) {
		pr_warn("vmtool: cpu %d: failed to create per cpu dir.\n",
				cpu_num);
		return PTR_ERR(dir);
	}

	vm_info->per_cpu_arr[cpu_num].cpu_dir = dir;

	return 0;
}

static int per_cpu_init(int cpu_num)
{
	int ret;
	struct list_head *vcpu_list =
		&(vm_info->per_cpu_arr[cpu_num].vcpu_list);

	ret = per_cpu_create_debugfs(cpu_num);
	if (ret)
		return ret;

	INIT_LIST_HEAD(vcpu_list);

	return ret;
}

static ssize_t vm_vcpu_read(struct file *filp, char __user *buf,
		size_t size, loff_t *off)
{
	/* in future this can contain colon separated values */
	char data[BUF_LEN];
	struct vm_vcpu_info *v;

	if (*off == BUF_LEN)
		return 0;

	if (!filp->private_data)
		return -ENOENT;
	v = filp->private_data;
	memset(data, 0, BUF_LEN);
	snprintf(data, BUF_LEN, "%lld", v->last_seen);

	if (copy_to_user(buf, data, BUF_LEN))
		return -EFAULT;

	*off += BUF_LEN;

	return BUF_LEN;
}

static const struct file_operations vm_vcpu_fops = {
	.owner = THIS_MODULE,
	.read = vm_vcpu_read,
	.open = simple_open,
};

static int per_cpu_handle_addr(int cpu_num, u64 addr)
{
	struct list_head *vcpu_list =
		&(vm_info->per_cpu_arr[cpu_num].vcpu_list);
	struct vm_vcpu_info *vci;
	int found = 0;

	list_for_each_entry(vci, vcpu_list, list) {
		if (vci->vmcs_addr == addr) {
			found = 1;
			break;
		}
	}

	if (found) {
		vci->last_seen = ktime_get_real_seconds();
	} else {
		char fn[17];
		vci = kmalloc(sizeof(struct vm_vcpu_info), GFP_KERNEL);
		if (!vci)
			return -ENOMEM;
		vci->vmcs_addr = addr;
		vci->last_seen = ktime_get_real_seconds();
		list_add(&vci->list, vcpu_list);
		snprintf(fn, 17, "%llx", addr);
		debugfs_create_file(fn, 0444,
				vm_info->per_cpu_arr[cpu_num].cpu_dir,
				vci, &vm_vcpu_fops);
	}

	return 0;
}

static void per_cpu_do_work(int cpu_num)
{
	while (!vm_info->stop_per_cpu_threads) {
		u64 addr;
		if (get_vmcs_addr(&addr) == 0)
			if (per_cpu_handle_addr(cpu_num, addr))
				return;
		/* TODO: make this configurable. */
		msleep_interruptible(1000); /* sleep for 1 second */
	}
}

static int per_cpu_thread(void *arg)
{
	int cpu_num = (long)arg;

	per_cpu_init(cpu_num);
	per_cpu_do_work(cpu_num);

	return 0;
}

static int start_per_cpu_threads(void)
{
	int cpu, i, ret = 0;
	u32 online_cpus = num_online_cpus();

	vm_info->threads = kmalloc_array(online_cpus, sizeof(*vm_info->threads), GFP_KERNEL);
	if (!vm_info->threads) {
		ret = -ENOMEM;
		goto out;
	}

	/* TODO: array length must be number of _available_ cpus, not
	 * the number of online cpus.
	 */
	vm_info->per_cpu_arr = kmalloc_array(online_cpus,
			sizeof(struct per_cpu_info), GFP_KERNEL);
	if (!vm_info->per_cpu_arr) {
		ret = -ENOMEM;
		goto out;
	}

	for_each_online_cpu(cpu) {
		struct task_struct *thread;

		thread = kthread_create(per_cpu_thread, (void *)(long)cpu,
				"vmtool-per-cpu");
		if (IS_ERR(thread))
			pr_err("error (%d) creating per-cpu thread on cpu %ld\n",
					cpu, PTR_ERR(thread));
		else
			vm_info->threads[vm_info->thread_count++] = thread;
		kthread_bind(thread, cpu);
	}

	vm_info->stop_per_cpu_threads = 0;

	pr_info("vmtool: going to start per cpu threads\n");
	for (i = 0; i < vm_info->thread_count; i++)
		wake_up_process(vm_info->threads[i]);

out:
	return ret;
}

static void stop_per_cpu_threads(void)
{
	int i, ret;

	vm_info->stop_per_cpu_threads = 1;
	for (i = 0; i < vm_info->thread_count; i++) {
		struct list_head *vcpu_list;
		struct vm_vcpu_info *curr, *next;
		/* this check is in case we have fewer online cpus than
		 * available cpus
		 */
		if (vm_info->threads[i]) {
			ret = kthread_stop(vm_info->threads[i]);
			if (ret)
				pr_warn("vmtool: thread %d failed to stop and returned %d\n",
					i, ret);
		}

		vcpu_list = &vm_info->per_cpu_arr[i].vcpu_list;
		list_for_each_entry_safe(curr, next, vcpu_list, list) {
			list_del(&curr->list);
			kfree(curr);
		}
	}

	kfree(vm_info->threads);
	kfree(vm_info->per_cpu_arr);
}

static int __init vmtool_init(void)
{
	int ret = 0;

	vm_info = kzalloc(sizeof(struct vm_info), GFP_KERNEL);
	if (!vm_info)
		return -ENOMEM;

	vm_info->msr_vmx_basic = get_vmx_basic();

	if (create_debugfs())
		return -ENODEV;

	ret = start_per_cpu_threads();

	return ret;
}
  
static void __exit vmtool_exit(void)
{
	stop_per_cpu_threads();
	debugfs_remove_recursive(vm_info->root);
	kfree(vm_info);
	pr_info("Exiting vmtool\n");
} 
  
module_init(vmtool_init); 
module_exit(vmtool_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Okash Khawaja");
