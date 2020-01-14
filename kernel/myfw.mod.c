#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa683b406, "module_layout" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0x91715312, "sprintf" },
	{ 0x20c55ae0, "sscanf" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x88473f72, "cdev_del" },
	{ 0xc996d097, "del_timer" },
	{ 0x5d3b55b5, "nf_unregister_hook" },
	{ 0xf0673fdb, "class_destroy" },
	{ 0x612a8ef9, "class_unregister" },
	{ 0x5b2cfa3b, "device_destroy" },
	{ 0xfb0e29f, "init_timer_key" },
	{ 0xadc2290a, "nf_register_hook" },
	{ 0x99d4dc24, "device_create" },
	{ 0x5f84e71, "__class_create" },
	{ 0xe798e8ea, "cdev_add" },
	{ 0xb0bc3bba, "cdev_init" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0xd8e484f0, "register_chrdev_region" },
	{ 0xabd0c91c, "rtc_time_to_tm" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0x440a4045, "kmalloc_caches" },
	{ 0x7d50a24, "csum_partial" },
	{ 0xbe2c0274, "add_timer" },
	{ 0x7d11c268, "jiffies" },
	{ 0x37a0cba, "kfree" },
	{ 0x4f68e5c9, "do_gettimeofday" },
	{ 0x50eedeb8, "printk" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "00DE9778FE7C0D91FA2374B");
