#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/msr.h>

#define MSR_IA32_VMX_BASIC 0x00000480
#define NO_CURRENT_VMCS 0xffffffffffffffff
#define MIN(a,b) ((a)<(b) ? (a):(b))

struct vm_info {
	struct dentry *root;
	u64 msr_vmx_basic;
};

static struct vm_info *vm_info;

static int get_vmcs_addr(void)
{
	u64 q = 0xabcd;
	int ret = 0;
	u32 *identifier;
	u32 msrlow, msrhigh;

	pr_info("Hello world\n");
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

	rdmsr(MSR_IA32_VMX_BASIC, msrlow, msrhigh);
	pr_info("msrlow = 0x%x, msrhigh = 0x%x\n", msrlow, msrhigh);

	/* no error happened */
	if (ret != -1 && q != NO_CURRENT_VMCS) {
		identifier = __va(q);
		pr_info("identifier=0x%x\n", *identifier);
	} else
		pr_info("couldn't get vmcs\n");

	return 0;
}

static ssize_t vmcs_addrs_read(struct file *filp, char __user *buf,
		size_t size, loff_t *off)
{
	/* TODO: this is dummy implementation */
	const char *ret = "vmcs_addrs_read_result";
	size_t bytes_to_copy = MIN(strlen(ret) + 1, size);
	size_t delta = bytes_to_copy - (*off);

	copy_to_user(buf, ret + (*off), delta);

	*off += delta;

	return delta;
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
	/* TODO: this is dummy implementation */
	return size;
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
	/* TODO: perhaps this should debugfs_create_blob() here */
	debugfs_create_file("vmcs", 0644, root, NULL, &vmcs_fops);
	debugfs_create_u64("vmx-basic", 0444, root, &vm_info->msr_vmx_basic);

	return 0;
}

static int __init vmtool_init(void)
{
	vm_info = kmalloc(sizeof(struct vm_info), GFP_KERNEL);
	if (!vm_info)
		return -ENOMEM;

	/* TODO: initialise msr_vmx_basic properly */
	vm_info->msr_vmx_basic = 0xabcdefab12345678;

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
