// SPDX-License-Identifier: GPL-2.0
/*
 * Harmless test module for the Phase 8 demonstration on a real Linux VM.
 * It does nothing except log when it is loaded and unloaded. Do NOT load it
 * on a machine you care about; use the throw-away VM from docs/TESTING.md.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int __init test_rogue_init(void)
{
	pr_info("test_rogue: loaded (harmless demo module)\n");
	return 0;
}

static void __exit test_rogue_exit(void)
{
	pr_info("test_rogue: unloaded\n");
}

module_init(test_rogue_init);
module_exit(test_rogue_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-module-rootkit-detector demo");
MODULE_DESCRIPTION("Harmless module used to test the rootkit detector");
