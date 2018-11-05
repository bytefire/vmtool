#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/msr.h>

#define MAX_LEN 256
#define MSR_IA32_VMX_BASIC 0x00000480
#define NO_CURRENT_VMCS 0xffffffffffffffff
#define MIN(a,b) ((a)<(b) ? (a):(b))

struct vm_info {
	struct dentry *root;
	u64 msr_vmx_basic;
	u64 vmcs_addr;
	char vmcs_addrs[MAX_LEN];
	size_t vmcs_addrs_len;
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

static int populate_vmcs_addrs(void)
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
		// TODO: for testing only
		identifier = __va(q);
		pr_info("identifier=0x%x\n", *identifier);

		return 0;
	}
	// TODO: return more accurate error code
	pr_info("couldn't get vmcs\n");
	return -1;
}

static ssize_t vmcs_addrs_read(struct file *filp, char __user *buf,
		size_t size, loff_t *off)
{
	int ret;
	loff_t uoff = *off;
	size_t delta, bytes_to_copy;

	if (uoff == 0) {
		/* TODO: perhaps this should be stored in filp's private_data if
		 * the file is opened multiple times */
		ret = populate_vmcs_addrs();
		if (ret)
			return -ret;
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
	/* TODO: this is dummy implementation */
	const char *ret = "vmcs_read_result";
	size_t bytes_to_copy = MIN(strlen(ret) + 1, size);
	size_t delta = bytes_to_copy - (*off);

	copy_to_user(buf, ret + (*off), delta);

	*off += delta;

	return delta;
}

static ssize_t vmcs_write(struct file *filp, const char __user *buf,
		size_t size, loff_t *off)
{
	ssize_t ret;
	char *kbuf = kmalloc(size, GFP_KERNEL);

	if (!kbuf)
		return -ENOMEM;

	copy_from_user(kbuf, buf, size);
	kbuf[size] = '\0';
	ret = kstrtoull(kbuf, 0, &vm_info->vmcs_addr);

	kfree(kbuf);

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
		return -1;
	}

	vm_info->root = root;

	debugfs_create_file("vmcs-addrs", 0444, root, NULL, &vmcs_addrs_fops);
	/* TODO: why are we not using debugfs_create_blob() here? */
	debugfs_create_file("vmcs", 0644, root, NULL, &vmcs_fops);
	debugfs_create_u64("vmx-basic", 0444, root, &vm_info->msr_vmx_basic);

	return 0;
}

static int __init vmtool_init(void)
{
	vm_info = kzalloc(sizeof(struct vm_info), GFP_KERNEL);
	if (!vm_info)
		return -ENOMEM;

	vm_info->msr_vmx_basic = get_vmx_basic();

	if (create_debugfs())
		return -ENODEV;

	return 0;
}
  
static void __exit vmtool_exit(void)
{
	debugfs_remove_recursive(vm_info->root);
	kfree(vm_info);
	pr_info("Exiting vmtool\n");
} 
  
module_init(vmtool_init); 
module_exit(vmtool_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Okash Khawaja");
