#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0xb3753869, "module_layout" },
	{ 0x78f44845, "cdev_del" },
	{ 0xbabacef1, "device_destroy" },
	{ 0x4f66026e, "nf_unregister_net_hook" },
	{ 0xc5850110, "printk" },
	{ 0xb356c301, "class_destroy" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x58fd4cc1, "nf_register_net_hook" },
	{ 0x4ea55841, "init_net" },
	{ 0xff9c16ee, "device_create" },
	{ 0x7afe113a, "cdev_add" },
	{ 0xa3036ef8, "cdev_init" },
	{ 0x8d62ea07, "__class_create" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x37a0cba, "kfree" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0x96b29254, "strncasecmp" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "F0F4C1A3F2D551C7F69F21D");
