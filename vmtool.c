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
#include <asm/msr.h>

#define MAX_LEN 256
#define MSR_IA32_VMX_BASIC 0x00000480
/* isolate bits 44:32 of MSR_IA32_VMX_BASIC */
#define VMCS_SIZE(x) (((x) << 19) >> 51)
#define NO_CURRENT_VMCS 0xffffffffffffffff
#define MIN(a,b) ((a)<(b) ? (a):(b))

static atomic_t active_threads;
static struct completion per_cpu_threads_done =
	COMPLETION_INITIALIZER(per_cpu_threads_done);

struct vm_info {
	struct dentry *root;
	u64 msr_vmx_basic;
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
		// TODO: return proper error code
		return -1;
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

static int per_cpu_thread(void *arg)
{
	// TODO: get cpu number
	int cpu_num = get_cpu();
	pr_info("hello from cpu %d. arg = %ld\n", cpu_num, (long)arg);
	put_cpu();

	if (atomic_dec_return_relaxed(&active_threads) == 0)
		complete(&per_cpu_threads_done);

	return 0;
}

static int start_per_cpu_threads(void)
{
	int cpu, thread_count = 0, i, ret;
	struct task_struct **threads;
	u32 online_cpus = num_online_cpus();

	pr_info(">>> number of online cpus = %d\n", online_cpus);
	threads = kmalloc_array(online_cpus, sizeof(*threads), GFP_KERNEL);
	if (!threads)
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		struct task_struct *thread;


		pr_info(">>>> (parent thread) for each cpu: %d\n", cpu);
		thread = kthread_create(per_cpu_thread, (void *)(long)cpu,
				"vmtool-per-cpu");
		if (IS_ERR(thread))
			pr_err(">>> ERROR creating per-cpu thread on cpu %d\n", cpu);
		else
			threads[thread_count++] = thread;
		kthread_bind(thread, cpu);
	}

	atomic_set(&active_threads, thread_count);

	pr_info("going to start per cpu threads\n");
	for (i = 0; i < thread_count; i++)
		wake_up_process(threads[i]);

	wait_for_completion(&per_cpu_threads_done);

	for (i = 0; i < thread_count; i++) {
		ret = kthread_stop(threads[i]);
		if (ret)
			pr_warn(">>> thread %d returned %d\n", i, ret);
	}

	kfree(threads);
	return 0;

}

static int __init vmtool_init(void)
{
	// TODO: check drivers/firmware/psci_checker.c:suspend_tests(void) which runs a test on each cpu
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
	/* TODO: close all per-cpu kthreads */
	debugfs_remove_recursive(vm_info->root);
	kfree(vm_info);
	pr_info("Exiting vmtool\n");
} 
  
module_init(vmtool_init); 
module_exit(vmtool_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Okash Khawaja");
