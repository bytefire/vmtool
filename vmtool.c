#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/msr.h>

#define MSR_IA32_VMX_BASIC 0x00000480
#define NO_CURRENT_VMCS 0xffffffffffffffff

static int __init vmtool_init(void) 
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
  
static void __exit vmtool_exit(void) 
{ 
	printk("Exiting vmtool\n"); 
} 
  
module_init(vmtool_init); 
module_exit(vmtool_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Okash Khawaja");
