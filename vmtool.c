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
#include <asm/msr.h>

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



	u64 vmcs_addr;
	char vmcs_addrs[MAX_LEN];
	size_t vmcs_addrs_len;
	/* TODO: we will not need following two when we have per-cpu kthreads
	 * which create read-only files for every vmcs
	 */
	u64 cached_addrs[64];
	int cached_addrs_count;
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

static void add_to_cache(u64 addr)
{
	int i;

	if (vm_info->cached_addrs_count >= 64) {
		pr_warn("unable to add vmcs address to cache.");
		return;
	}

	for (i = 0; i < vm_info->cached_addrs_count; i++)
		if (vm_info->cached_addrs[i] == addr)
			return;

	vm_info->cached_addrs[vm_info->cached_addrs_count] = addr;
	vm_info->cached_addrs_count++;
}

static void populate_vmcs_addrs(void)
{
	int ret = 0;
	u64 q;
	u32 *identifier;

	/* TODO: this is okay for start but we really want to be more robust in
	 * searching for vmcsc addrs. main reason is vmptrst will only return a
	 * valid result when we get a timeslice on the cpu which is running as a
	 * hypervisor for a vcpu and one of the vmcs's is active and current on
	 * that cpu.
	 *
	 * 1. look for vmcs on different cpus.
	 * 2. make multiple attempts at getting vmcs
	 * 3. record the cpu number on which a particular vmcsc was observed.
	 *   this is important because migrating a vmcs is costly and cpus are
	 *   incentivised to keep a vcpu on the same cpu. we should also report
	 *   the physical cpu number along with physical address of vmcs.
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

        pr_info("ret=%d, q=0x%llx\n", ret, q);

	/* no error happened */
	if (ret != -1 && q != NO_CURRENT_VMCS) {
		/* TODO: in future we will return comma separated list of
		 * physical addresses */
		vm_info->vmcs_addrs_len = snprintf(vm_info->vmcs_addrs, MAX_LEN, "0x%llx", q);
		// TODO: this won't be needed when we have per-cpu kthreads which create a
		// file for each vmcs
		add_to_cache(q);
		// TODO: for testing only
		identifier = __va(q);
		pr_info("identifier=0x%x\n", *identifier);
	} else {
		pr_info("couldn't get vmcs\n");
	}
}

static ssize_t vmcs_addrs_read(struct file *filp, char __user *buf,
		size_t size, loff_t *off)
{
	loff_t uoff = *off;
	size_t delta, bytes_to_copy;

	if (uoff == 0) {
		/* TODO: perhaps this should be stored in filp's private_data if
		 * the file is opened multiple times */
		populate_vmcs_addrs();
	}

	if (uoff > vm_info->vmcs_addrs_len)
		return -ERANGE;
	
	delta = vm_info->vmcs_addrs_len - uoff;
	bytes_to_copy = MIN(delta, size);
	/* TODO: take into account bytes actually copied */
	copy_to_user(buf, vm_info->vmcs_addrs + uoff, bytes_to_copy);
	*off += bytes_to_copy;

	return bytes_to_copy;
}

static const struct file_operations vmcs_addrs_fops = {
	.owner = THIS_MODULE,
	.read = vmcs_addrs_read,
};

static ssize_t vmcs_read(struct file *filp, char __user *buf,
		size_t size, loff_t *off)
{
	// TODO: get the size of vmcs using VMCS_SIZE(vm_info->msr_vmx_basic)
	//	convert physical address in vm_info->vmcs_addr into va.
	//	read vmcs's size worth of bytes into buf - or size worth
	//	of bytes and return read bytes and update off accordingly.
	u8 *ptr;
	loff_t uoff = *off;
	size_t bytes_to_copy;
	size_t vmcs_size = VMCS_SIZE(vm_info->msr_vmx_basic);

	if (vm_info->vmcs_addr == 0)
		return -ENODATA;
	if (uoff > vmcs_size)
		return -EINVAL;

	ptr = __va(vm_info->vmcs_addr);

	bytes_to_copy = MIN(size, (vmcs_size - uoff));


	if (copy_to_user(buf, ptr + uoff, bytes_to_copy))
		return -EFAULT;

	*off += bytes_to_copy;

	return bytes_to_copy;
}

static ssize_t vmcs_write(struct file *filp, const char __user *buf,
		size_t size, loff_t *off)
{
	ssize_t ret;
	char *kbuf = kmalloc(size, GFP_KERNEL);
	u64 addr;
	int i;

	if (!kbuf) {
		ret = -ENOMEM;
		goto out;
	}

	copy_from_user(kbuf, buf, size);
	kbuf[size] = '\0';
	ret = kstrtoull(kbuf, 0, &addr);

	if (ret)
		goto free_and_out;

	for (i = 0; i < vm_info->cached_addrs_count; i++)
		if (vm_info->cached_addrs[i] == addr)
			break;

	if (i == vm_info->cached_addrs_count) {
		ret = -EINVAL;
		goto free_and_out;
	}

	vm_info->vmcs_addr = addr;
free_and_out:
	kfree(kbuf);
out:
	return ret ? ret : size;
}

static const struct file_operations vmcs_fops = {
	.owner = THIS_MODULE,
	.read = vmcs_read,
	.write = vmcs_write,
};

static int create_debugfs(void)
{
	struct dentry *root;

	root = debugfs_create_dir("vmtool", NULL);
	if (root == NULL || IS_ERR(root)) {
		pr_warn("vmtool: can't create debugfs entries. not going to load the module.\n");
		return PTR_ERR(root);
	}

	vm_info->root = root;

	debugfs_create_file("vmcs-addrs", 0444, root, NULL, &vmcs_addrs_fops);
	/* TODO: we should spin a kthread for each cpu, which periodically search
	 * for vmcs create files under vmtool/ debugfs entry where each file's name
	 * is <cpu-number>-<physical address of a vmcs>. these can be files created
	 * with debugfs_create_blob().
	 *
	 * this current set up isn't thread safe.
	 */
	debugfs_create_file("vmcs", 0644, root, NULL, &vmcs_fops);
	debugfs_create_x64("vmx-basic", 0444, root, &vm_info->msr_vmx_basic);

	return 0;
}

static int get_vmcs_addr(u64 *addr)
{
	int ret = 0;
	u64 q;

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

static int per_cpu_handle_addr(int cpu_num, u64 addr)
{
	struct list_head *vcpu_list =
		&(vm_info->per_cpu_arr[cpu_num].vcpu_list);
	struct vm_vcpu_info *vci;
	int found = 0;

	list_for_each_entry(vci, vcpu_list, list) {
		// TODO: for testing only
		pr_info("cpu: %d: vci->vmcs_addr = 0x%llx\n",
				cpu_num, vci->vmcs_addr);
		if (vci->vmcs_addr == addr) {
			found = 1;
			break;
		}
	}

	if (found) {
		vci->last_seen = ktime_get_real_seconds();
	} else {
		vci = kmalloc(sizeof(struct vm_vcpu_info), GFP_KERNEL);
		if (!vci)
			return -ENOMEM;
		vci->vmcs_addr = addr;
		vci->last_seen = ktime_get_real_seconds();
		list_add(&vci->list, vcpu_list);
		/* TODO: create a file with name = addr string */
	}

	return 0;
}

static void per_cpu_do_work(int cpu_num)
{
	while (!vm_info->stop_per_cpu_threads) {
		u64 addr;
		if (get_vmcs_addr(&addr) == 0)
			// TODO: check return value
			per_cpu_handle_addr(cpu_num, addr);
		msleep_interruptible(1000); /* sleep for 1 second */
	}
}

static int per_cpu_thread(void *arg)
{
	int cpu_num = get_cpu();
	pr_info("hello from cpu %d. arg = %ld\n", cpu_num, (long)arg);
	put_cpu();

	per_cpu_init(cpu_num);
	per_cpu_do_work(cpu_num);

	return 0;
}

static int start_per_cpu_threads(void)
{
	int cpu, i, ret = 0;
	u32 online_cpus = num_online_cpus();

	pr_info(">>> number of online cpus = %d\n", online_cpus);
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

	pr_info("going to start per cpu threads\n");
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
	/* TODO: 1. list all cpu's and for each cpu spin a kthread
	 *	2. each thread to create a directory "cpu-<cpu-num>"
	 *	3. inside it create a file whose name is physical address of vmcs as hex string
	 *	4. reading each such file will give a timestamp and data of that vmcs
	 */
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
