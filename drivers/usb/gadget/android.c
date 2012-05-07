/*
 * Gadget Driver for Android
 *
 * Copyright (C) 2008 Google, Inc.
 * Copyright (c) 2009-2010, Code Aurora Forum. All rights reserved.
 * Author: Mike Lockwood <lockwood@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

/* #define DEBUG */
/* #define VERBOSE_DEBUG */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/debugfs.h>

#include <linux/usb/android_composite.h>
#include <linux/usb/ch9.h>
#include <linux/usb/composite.h>
#include <linux/usb/gadget.h>

#include "gadget_chips.h"

/*
 * Kbuild is not very cooperative with respect to linking separately
 * compiled library objects into one module.  So for now we won't use
 * separate compilation ... ensuring init/exit sections work to shrink
 * the runtime footprint, and giving us at least some parts of what
 * a "gcc --combine ... part1.c part2.c part3.c ... " build would.
 */
#include "usbstring.c"
#include "config.c"
#include "epautoconf.c"
#include "composite.c"

MODULE_AUTHOR("Mike Lockwood");
MODULE_DESCRIPTION("Android Composite USB Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

// [START] seunghun.kim : for LG_USB_DRIVER 2011.03.25
#ifdef CONFIG_LGE_USB_GADGET_DRIVER
/* usb mode switching by product id */
#ifdef CONFIG_LGE_USB_FACTORY
extern int usb_cable_info;
#endif
u16 product_id;
int android_set_pid(const char *val, struct kernel_param *kp);
static int android_get_pid(char *buffer, struct kernel_param *kp);
module_param_call(product_id, android_set_pid, android_get_pid,
					&product_id, 0664);
MODULE_PARM_DESC(product_id, "USB device product id");

#ifdef CONFIG_LGE_USB_VZW_DRIVER
const u16 lg_default_pid = 0x6204;
const u16 lg_ndis_pid = 0x6204;
#define lg_ndis_pid_string "6204"
#else
#ifdef CONFIG_LGE_USB_TWO_MODEM
const u16 lg_default_pid = 0x6318;
#define lg_default_pid_string "6318"
const u16 lg_ndis_pid = 0x6318;
#define lg_ndis_pid_string "6318"
#else
const u16 lg_default_pid = 0x6315;
#define lg_default_pid_string "6315"
const u16 lg_ndis_pid = 0x6315;
#define lg_ndis_pid_string "6315"
#endif
#endif

#ifdef CONFIG_LGE_USB_FACTORY
#include "../../../lge/include/lg_power_common.h"
const u16 lg_factory_pid = 0x6000;
u16 iSerialNumber_id = 0x00;
#endif

#ifdef CONFIG_LGE_USB_AUTORUN
#ifdef CONFIG_LGE_USB_VZW_DRIVER
const u16 lg_autorun_pid = 0x6207;
#define lg_autorun_pid_string "6207"
#else
const u16 lg_autorun_pid = 0x630E;
#define lg_autorun_pid_string "630E"
#endif

static u16 autorun_user_mode;
static int android_set_usermode(const char *val, struct kernel_param *kp);
module_param_call(user_mode, android_set_usermode, param_get_string,
					&autorun_user_mode, 0664);
MODULE_PARM_DESC(user_mode, "USB Autorun user mode");
#endif

#ifdef CONFIG_LGE_USB_VZW_DRIVER
const u16 lg_ums_pid = 0x6205;
#define lg_ums_pid_string "6205"
#else
const u16 lg_ums_pid = 0x6320;	/* ums only  */
#define lg_ums_pid_string "6320"
#endif

#if 1//def CONFIG_USB_SUPPORT_LGE_ANDROID_AUTORUN_CGO
int adb_disable = 1;
const u16 lg_charge_only_pid = 0xFFFF;
#define lg_charge_only_pid_string "FFFF"
extern void usb_charge_only_softconnect(void);
#endif

#if 1//def CONFIG_USB_SUPPORT_LGE_ANDROID_AUTORUN
#define MAX_USB_MODE_LEN 32
static char usb_mode[MAX_USB_MODE_LEN] = "init_mode";
int android_set_usb_mode(const char *val, struct kernel_param *kp);
static int android_get_usb_mode(char *buffer, struct kernel_param *kp);
module_param_call(usb_mode, android_set_usb_mode, android_get_usb_mode,
					&usb_mode, 0664);
MODULE_PARM_DESC(usb_mode, "USB device connection mode");
#endif
#endif //CONFIG_LGE_USB_GADGET_DRIVER

// START sungchae.koo@lge.com 2011/07/28 P1_LAB_BSP : FIX_USB_CONNECTION_MODE_WHILE_FACTORY_CABLE {
#ifdef CONFIG_LGE_USB_FACTORY
extern acc_cable_type get_usb_cable_type_value(void);
#endif
// END sungchae.koo@lge.com 2011/07/28 P1_LAB_BSP }

static const char longname[] = "Gadget Android";

/* Default vendor and product IDs, overridden by platform data */
#define VENDOR_ID		0x18D1
#define PRODUCT_ID		0x0001

struct android_dev {
	struct usb_composite_dev *cdev;
	struct usb_configuration *config;
	int num_products;
	struct android_usb_product *products;
	int num_functions;
	char **functions;

	int product_id;
	int version;
// [START] seunghun.kim : for LG_USB_DRIVER 2011.03.25
#ifdef CONFIG_LGE_USB_GADGET_DRIVER
	struct mutex lock;
#endif
};

static struct android_dev *_android_dev;

#define MAX_STR_LEN		16
/* string IDs are assigned dynamically */

#define STRING_MANUFACTURER_IDX		0
#define STRING_PRODUCT_IDX		1
#define STRING_SERIAL_IDX		2

char serial_number[MAX_STR_LEN];
/* String Table */
static struct usb_string strings_dev[] = {
	/* These dummy values should be overridden by platform data */
	[STRING_MANUFACTURER_IDX].s = "Android",
	[STRING_PRODUCT_IDX].s = "Android",
	[STRING_SERIAL_IDX].s = "0123456789ABCDEF",
	{  }			/* end of list */
};

static struct usb_gadget_strings stringtab_dev = {
	.language	= 0x0409,	/* en-us */
	.strings	= strings_dev,
};

static struct usb_gadget_strings *dev_strings[] = {
	&stringtab_dev,
	NULL,
};

static struct usb_device_descriptor device_desc = {
	.bLength              = sizeof(device_desc),
	.bDescriptorType      = USB_DT_DEVICE,
	.bcdUSB               = __constant_cpu_to_le16(0x0200),
	.bDeviceClass         = USB_CLASS_PER_INTERFACE,
	.idVendor             = __constant_cpu_to_le16(VENDOR_ID),
	.idProduct            = __constant_cpu_to_le16(PRODUCT_ID),
	.bcdDevice            = __constant_cpu_to_le16(0xffff),
	.bNumConfigurations   = 1,
};

static struct usb_otg_descriptor otg_descriptor = {
	.bLength =		sizeof otg_descriptor,
	.bDescriptorType =	USB_DT_OTG,
	.bmAttributes =		USB_OTG_SRP | USB_OTG_HNP,
	.bcdOTG               = __constant_cpu_to_le16(0x0200),
};

static const struct usb_descriptor_header *otg_desc[] = {
	(struct usb_descriptor_header *) &otg_descriptor,
	NULL,
};

static struct list_head _functions = LIST_HEAD_INIT(_functions);
static int _registered_function_count = 0;

static void android_set_default_product(int product_id);

void android_usb_set_connected(int connected)
{
	if (_android_dev && _android_dev->cdev && _android_dev->cdev->gadget) {
		if (connected)
			usb_gadget_connect(_android_dev->cdev->gadget);
		else
			usb_gadget_disconnect(_android_dev->cdev->gadget);
	}
}

static struct android_usb_function *get_function(const char *name)
{
	struct android_usb_function	*f;
	list_for_each_entry(f, &_functions, list) {
		if (!strcmp(name, f->name))
			return f;
	}
	return 0;
}

static void bind_functions(struct android_dev *dev)
{
	struct android_usb_function	*f;
	char **functions = dev->functions;
	int i;

	for (i = 0; i < dev->num_functions; i++) {
		char *name = *functions++;
		f = get_function(name);
		if (f)
			f->bind_config(dev->config);
		else
			pr_err("%s: function %s not found\n", __func__, name);
	}

	/*
	 * set_alt(), or next config->bind(), sets up
	 * ep->driver_data as needed.
	 */
	usb_ep_autoconfig_reset(dev->cdev->gadget);
}

static int __ref android_bind_config(struct usb_configuration *c)
{
	struct android_dev *dev = _android_dev;

	pr_debug("android_bind_config\n");
	dev->config = c;

	/* bind our functions if they have all registered */
	if (_registered_function_count == dev->num_functions)
		bind_functions(dev);

	return 0;
}

static int android_setup_config(struct usb_configuration *c,
		const struct usb_ctrlrequest *ctrl);

static struct usb_configuration android_config_driver = {
	.label		= "android",
	.bind		= android_bind_config,
	.setup		= android_setup_config,
	.bConfigurationValue = 1,
	.bMaxPower	= 0xFA, /* 500ma */
};

static int android_setup_config(struct usb_configuration *c,
		const struct usb_ctrlrequest *ctrl)
{
	int i;
	int ret = -EOPNOTSUPP;

	for (i = 0; i < android_config_driver.next_interface_id; i++) {
		if (android_config_driver.interface[i]->setup) {
			ret = android_config_driver.interface[i]->setup(
				android_config_driver.interface[i], ctrl);
			if (ret >= 0)
				return ret;
		}
	}
	return ret;
}

static int product_has_function(struct android_usb_product *p,
		struct usb_function *f)
{
	char **functions = p->functions;
	int count = p->num_functions;
	const char *name = f->name;
	int i;

	for (i = 0; i < count; i++) {
		if (!strcmp(name, *functions++))
			return 1;
	}
	return 0;
}

#ifdef CONFIG_LGE_USB_GADGET_DRIVER
/* find matches function by product id */
static int product_matches_functions(struct android_dev *dev, struct android_usb_product *p)
{
	if (p->product_id == dev->product_id)
    	return 1;
	else
		return 0;  
}
#else /* below is original */
static int product_matches_functions(struct android_usb_product *p)
{
	struct usb_function		*f;
	list_for_each_entry(f, &android_config_driver.functions, list) {
		if (product_has_function(p, f) == !!f->disabled)
			return 0;
	}
	return 1;
}
#endif

static int get_product_id(struct android_dev *dev)
{
	struct android_usb_product *p = dev->products;
	int count = dev->num_products;
	int i;

	if (p) {
		for (i = 0; i < count; i++, p++) {
#ifdef CONFIG_LGE_USB_GADGET_DRIVER
      if (product_matches_functions(dev,p))
#else /* below is original */
			if (product_matches_functions(p))
#endif
				return p->product_id;
		}
	}
	/* use default product ID */
	return dev->product_id;
}

static int __devinit android_bind(struct usb_composite_dev *cdev)
{
	struct android_dev *dev = _android_dev;
	struct usb_gadget	*gadget = cdev->gadget;
	int			gcnum, id, product_id, ret;

	pr_debug("android_bind\n");

	/* Allocate string descriptor numbers ... note that string
	 * contents can be overridden by the composite_dev glue.
	 */
	id = usb_string_id(cdev);
	if (id < 0)
		return id;
	strings_dev[STRING_MANUFACTURER_IDX].id = id;
	device_desc.iManufacturer = id;

	id = usb_string_id(cdev);
	if (id < 0)
		return id;
	strings_dev[STRING_PRODUCT_IDX].id = id;
	device_desc.iProduct = id;

	id = usb_string_id(cdev);
	if (id < 0)
		return id;
	strings_dev[STRING_SERIAL_IDX].id = id;
	device_desc.iSerialNumber = id;
#ifdef CONFIG_LGE_USB_FACTORY
    iSerialNumber_id = id;
    if (device_desc.idProduct == lg_factory_pid)
        device_desc.iSerialNumber = 0x00;
#endif

	if (gadget_is_otg(cdev->gadget))
		android_config_driver.descriptors = otg_desc;

	if (!usb_gadget_set_selfpowered(gadget))
		android_config_driver.bmAttributes |= USB_CONFIG_ATT_SELFPOWER;

	if (gadget->ops->wakeup)
		android_config_driver.bmAttributes |= USB_CONFIG_ATT_WAKEUP;

	/* register our configuration */
	ret = usb_add_config(cdev, &android_config_driver);
	if (ret) {
		pr_err("%s: usb_add_config failed\n", __func__);
		return ret;
	}

	gcnum = usb_gadget_controller_number(gadget);
	if (gcnum >= 0)
		device_desc.bcdDevice = cpu_to_le16(0x0200 + gcnum);
	else {
		/* gadget zero is so simple (for now, no altsettings) that
		 * it SHOULD NOT have problems with bulk-capable hardware.
		 * so just warn about unrcognized controllers -- don't panic.
		 *
		 * things like configuration and altsetting numbering
		 * can need hardware-specific attention though.
		 */
		pr_warning("%s: controller '%s' not recognized\n",
			longname, gadget->name);
		device_desc.bcdDevice = __constant_cpu_to_le16(0x9999);
	}

	usb_gadget_set_selfpowered(gadget);
	dev->cdev = cdev;
	product_id = get_product_id(dev);

	device_desc.idProduct = __constant_cpu_to_le16(product_id);
	cdev->desc.idProduct = device_desc.idProduct;

#ifdef CONFIG_LGE_USB_GADGET_DRIVER
	if(product_id == lg_ndis_pid)
	{
		device_desc.bDeviceClass		 = USB_CLASS_MISC;
		device_desc.bDeviceSubClass 	 = 0x02;
		device_desc.bDeviceProtocol 	 = 0x01;
	}
	else
	{
		device_desc.bDeviceClass		 = USB_CLASS_PER_INTERFACE;
		device_desc.bDeviceSubClass 	 = 0x00;
		device_desc.bDeviceProtocol 	 = 0x00;
	}
#endif

	return 0;
}

static struct usb_composite_driver android_usb_driver = {
	.name		= "android_usb",
	.dev		= &device_desc,
	.strings	= dev_strings,
	.bind		= android_bind,
	.enable_function = android_enable_function,
};

#ifndef CONFIG_LGE_USB_GADGET_DRIVER
/* this function isn't needed, cause function registered already done */
static bool is_func_supported(struct android_usb_function *f)
{
	char **functions = _android_dev->functions;
	int count = _android_dev->num_functions;
	const char *name = f->name;
	int i;

	for (i = 0; i < count; i++) {
		if (!strcmp(*functions++, name))
			return true;
	}
	return false;
}
#endif

void android_register_function(struct android_usb_function *f)
{
	struct android_dev *dev = _android_dev;

	pr_debug("%s: %s\n", __func__, f->name);

#ifndef CONFIG_LGE_USB_GADGET_DRIVER
	if (!is_func_supported(f))
		return;
#endif

	list_add_tail(&f->list, &_functions);
	_registered_function_count++;
	pr_info("%s: %s %d %d\n", __func__, f->name, _registered_function_count, dev->num_functions);

	/* bind our functions if they have all registered
	 * and the main driver has bound.
	 */
	if (dev->config && _registered_function_count == dev->num_functions) {
		bind_functions(dev);
		android_set_default_product(dev->product_id);
	}
}

/**
 * android_set_function_mask() - enables functions based on selected pid.
 * @up: selected product id pointer
 *
 * This function enables functions related with selected product id.
 */
static void android_set_function_mask(struct android_usb_product *up)
{
	int index, found = 0;
	struct usb_function *func;

	list_for_each_entry(func, &android_config_driver.functions, list) {
#if 1//ndef CONFIG_LGE_USB_GADGET_DRIVER 
//TD bug fix 37248
		/* adb function enable/disable handled separetely */
		if (!strcmp(func->name, "adb") )//&& !func->disabled)
		{
			if(up->product_id == lg_ndis_pid)
			{
				usb_function_set_enabled(func,!adb_disable);
			}
			else
			{
				usb_function_set_enabled(func,0);
			}
			continue;


		}
#endif
		for (index = 0; index < up->num_functions; index++) {
			if (!strcmp(up->functions[index], func->name)) {
				found = 1;
				break;
			}
		}

		if (found) { /* func is part of product. */
			/* if func is disabled, enable the same. */
			if (func->disabled)
				usb_function_set_enabled(func, 1);
			found = 0;
		} else { /* func is not part if product. */
			/* if func is enabled, disable the same. */
			if (!func->disabled)
				usb_function_set_enabled(func, 0);
		}
	}
}

/**
 * android_set_defaut_product() - selects default product id and enables
 * required functions
 * @product_id: default product id
 *
 * This function selects default product id using pdata information and
 * enables functions for same.
*/
static void android_set_default_product(int pid)
{
	struct android_dev *dev = _android_dev;
	struct android_usb_product *up = dev->products;
	int index;

	for (index = 0; index < dev->num_products; index++, up++) {
		if (pid == up->product_id)
			break;
	}
	android_set_function_mask(up);
}

/**
 * android_config_functions() - selects product id based on function need
 * to be enabled / disabled.
 * @f: usb function
 * @enable : function needs to be enable or disable
 *
 * This function selects first product id having required function.
 * RNDIS/MTP function enable/disable uses this.
*/
#if defined (CONFIG_USB_ANDROID_RNDIS) || defined (CONFIG_LGE_USB_GADGET_DRIVER)
static void android_config_functions(struct usb_function *f, int enable)
{
	struct android_dev *dev = _android_dev;
	struct android_usb_product *up = dev->products;
	int index;

	/* Searches for product id having function */
	if (enable) {
		for (index = 0; index < dev->num_products; index++, up++) {
			if (product_has_function(up, f))
				break;
		}
		android_set_function_mask(up);
	} else
		android_set_default_product(dev->product_id);
}
#endif

void update_dev_desc(struct android_dev *dev)
{
	struct usb_function *f;
	struct usb_function *last_enabled_f = NULL;
	int num_enabled = 0;
	int has_iad = 0;

	dev->cdev->desc.bDeviceClass = USB_CLASS_PER_INTERFACE;
	dev->cdev->desc.bDeviceSubClass = 0x00;
	dev->cdev->desc.bDeviceProtocol = 0x00;

	list_for_each_entry(f, &android_config_driver.functions, list) {
		if (!f->disabled) {
			num_enabled++;
			last_enabled_f = f;
			if (f->descriptors[0]->bDescriptorType ==
					USB_DT_INTERFACE_ASSOCIATION)
				has_iad = 1;
		}
		if (num_enabled > 1 && has_iad) {
			dev->cdev->desc.bDeviceClass = USB_CLASS_MISC;
			dev->cdev->desc.bDeviceSubClass = 0x02;
			dev->cdev->desc.bDeviceProtocol = 0x01;
			break;
		}
	}

	if (num_enabled == 1) {
#ifdef CONFIG_USB_ANDROID_RNDIS
		if (!strcmp(last_enabled_f->name, "rndis")) {
#ifdef CONFIG_USB_ANDROID_RNDIS_WCEIS
			dev->cdev->desc.bDeviceClass =
					USB_CLASS_WIRELESS_CONTROLLER;
#else
			dev->cdev->desc.bDeviceClass = USB_CLASS_COMM;
#endif
		}
#endif
	}
}


static char *sysfs_allowed[] = {
	"rndis",
	"mtp",
	"adb",
};

static int is_sysfschange_allowed(struct usb_function *f)
{
	char **functions = sysfs_allowed;
	int count = ARRAY_SIZE(sysfs_allowed);
	int i;

	for (i = 0; i < count; i++) {
		if (!strncmp(f->name, functions[i], 32))
			return 1;
	}
	return 0;
}

int android_enable_function(struct usb_function *f, int enable)
{
	struct android_dev *dev = _android_dev;
	int disable = !enable;
	int product_id;

	if (!is_sysfschange_allowed(f))
		return -EINVAL;
	if (!!f->disabled != disable) {
		usb_function_set_enabled(f, !disable);

#ifdef CONFIG_LGE_USB_GADGET_DRIVER
	if (!strcmp(f->name, "cdc_ethernet")) {

		/* We need to specify the MISC class in the device descriptor
		 * if we are using CDC-ECM.
		 */
		dev->cdev->desc.bDeviceClass = USB_CLASS_MISC;
		dev->cdev->desc.bDeviceSubClass      = 0x02;
		dev->cdev->desc.bDeviceProtocol      = 0x01;

		android_config_functions(f, enable);
	}
#endif

#ifdef CONFIG_USB_ANDROID_RNDIS
		if (!strcmp(f->name, "rndis")) {

			/* We need to specify the COMM class in the device descriptor
			 * if we are using RNDIS.
			 */
			if (enable) {
#ifdef CONFIG_USB_ANDROID_RNDIS_WCEIS
				dev->cdev->desc.bDeviceClass = USB_CLASS_MISC;
				dev->cdev->desc.bDeviceSubClass      = 0x02;
				dev->cdev->desc.bDeviceProtocol      = 0x01;
#else
				dev->cdev->desc.bDeviceClass = USB_CLASS_COMM;
#endif
			} else {
				dev->cdev->desc.bDeviceClass = USB_CLASS_PER_INTERFACE;
				dev->cdev->desc.bDeviceSubClass      = 0;
				dev->cdev->desc.bDeviceProtocol      = 0;
			}

			android_config_functions(f, enable);
		}
#endif

#ifdef CONFIG_USB_ANDROID_MTP
		if (!strcmp(f->name, "mtp"))
			android_config_functions(f, enable);
#endif

		product_id = get_product_id(dev);
		device_desc.idProduct = __constant_cpu_to_le16(product_id);
		if (dev->cdev)
			dev->cdev->desc.idProduct = device_desc.idProduct;
		usb_composite_force_reset(dev->cdev);
	}
	return 0;
}

#ifdef CONFIG_LGE_USB_GADGET_DRIVER
void android_set_device_class(u16 pid)
{
	struct android_dev *dev = _android_dev;
    int deviceclass = -1;

	if(pid == lg_ndis_pid) 
	{
		deviceclass = USB_CLASS_MISC;
		goto SetClass;
	}
    if(pid == lg_ums_pid) 
    {
  	  deviceclass = USB_CLASS_PER_INTERFACE;
  	  goto SetClass;
    }
#ifdef CONFIG_LGE_USB_FACTORY	
	if(pid == lg_factory_pid) 
	{
	  deviceclass = USB_CLASS_COMM;
	  goto SetClass;
	}
#endif
#ifdef CONFIG_LGE_USB_AUTORUN
	if(pid == lg_autorun_pid) 
	{
	  deviceclass = USB_CLASS_PER_INTERFACE;
	  goto SetClass;
	}
#endif
#if 1//def CONFIG_USB_SUPPORT_LGE_ANDROID_AUTORUN_CGO
    if(pid == lg_charge_only_pid) 
    {
	  deviceclass = USB_CLASS_PER_INTERFACE;
	  goto SetClass;
	}
#endif

SetClass:
	if(deviceclass == USB_CLASS_COMM)
	{
  		dev->cdev->desc.bDeviceClass = USB_CLASS_COMM;
		dev->cdev->desc.bDeviceSubClass      = 0x00;
		dev->cdev->desc.bDeviceProtocol      = 0x00;
	}
	else if(deviceclass == USB_CLASS_MISC)
	{
	  	dev->cdev->desc.bDeviceClass = USB_CLASS_MISC;
		dev->cdev->desc.bDeviceSubClass      = 0x02;
		dev->cdev->desc.bDeviceProtocol      = 0x01;
	}
	else if(deviceclass == USB_CLASS_PER_INTERFACE)
	{
		dev->cdev->desc.bDeviceClass = USB_CLASS_PER_INTERFACE;
		dev->cdev->desc.bDeviceSubClass      = 0x00;
		dev->cdev->desc.bDeviceProtocol      = 0x00;
	}
	else
	{
		dev->cdev->desc.bDeviceClass = USB_CLASS_PER_INTERFACE;
		dev->cdev->desc.bDeviceSubClass      = 0x00;
		dev->cdev->desc.bDeviceProtocol      = 0x00;
	}
}


int android_set_pid(const char *val, struct kernel_param *kp)
{
	struct android_dev *dev = _android_dev;
	int ret = 0;
	unsigned long tmp;
	u16 pid;
// START sungchae.koo@lge.com 2011/07/28 P1_LAB_BSP : FIX_USB_CONNECTION_MODE_WHILE_FACTORY_CABLE {
#ifdef CONFIG_LGE_USB_FACTORY
    acc_cable_type usb_cable_type = 0;
#endif
// END sungchae.koo@lge.com 2011/07/28 P1_LAB_BSP }

	ret = strict_strtoul(val, 16, &tmp);
	if (ret)
		goto out;

	/* We come here even before android_probe, when product id
	 * is passed via kernel command line.
	 */
	if (!_android_dev) {
		device_desc.idProduct = tmp;
		goto out;
	}

// START sungchae.koo@lge.com 2011/07/28 P1_LAB_BSP : FIX_USB_CONNECTION_MODE_WHILE_FACTORY_CABLE {
#ifdef CONFIG_LGE_USB_FACTORY
    usb_cable_type = get_usb_cable_type_value();
    if( LT_CABLE_56K == usb_cable_type || LT_CABLE_130K == usb_cable_type ) {
        if( lg_factory_pid != tmp ) {
            pr_info("[%s] It's factory cable conditon. Block Requested PID: 0x%lx\n", __func__, tmp);
    		goto out;
        }
    }
#endif
// END sungchae.koo@lge.com 2011/07/28 P1_LAB_BSP }

	/* Ignore request same pid switching */
#if 0
	pr_info("[%s] PID: %d, Requested PID: %lx\n", __func__, device_desc.idProduct, tmp);
	if (device_desc.idProduct == tmp) {
		pr_info("[%s] Requested product id is same(%lx), ignore it\n", __func__, tmp);
		goto out;
	}
#endif 

	/* set product id */
	pid = tmp;
	product_id = pid;
	device_desc.idProduct = __constant_cpu_to_le16(pid);  
	if (dev->cdev)
		dev->cdev->desc.idProduct = device_desc.idProduct;

#ifdef CONFIG_LGE_USB_FACTORY
    if (pid == lg_factory_pid)
    {
        strings_dev[STRING_SERIAL_IDX].s = NULL;
        strings_dev[STRING_SERIAL_IDX].id = 0x00;
        device_desc.iSerialNumber = 0x00;
    }
    else
    {
        strings_dev[STRING_SERIAL_IDX].s = serial_number;
        strings_dev[STRING_SERIAL_IDX].id = iSerialNumber_id;
        device_desc.iSerialNumber = iSerialNumber_id;
    }
#endif

#if 1//def CONFIG_USB_SUPPORT_LGE_ANDROID_AUTORUN_CGO
	/* We need to specify the COMM class in the device descriptor
	* if we are using RNDIS.
	*/
	usb_charge_only_softconnect();
#endif

#if 1//def CONFIG_USB_SUPPORT_LGE_ANDROID_AUTORUN_CGO
	if (pid == lg_charge_only_pid) {
		product_id = pid;
		device_desc.idProduct = __constant_cpu_to_le16(pid);
		if (dev->cdev)
		dev->cdev->desc.idProduct = device_desc.idProduct;

		/* If we are in charge only pid, disconnect android gadget */
		usb_gadget_disconnect(dev->cdev->gadget);
		return 0;
	}
#endif

	/* set function enable/disable and device class */
	android_set_default_product(pid);
	android_set_device_class(pid);

	pr_info("[%s] user set product id - 0x%x begin\n", __func__, pid);


	/* force reenumeration */
	usb_composite_force_reset(dev->cdev);
	
	pr_info("[%s] user set product id - 0x%x complete\n", __func__, pid);

out:
	return ret;
}

#ifdef CONFIG_LGE_USB_FACTORY
int android_set_pid_without_reset(const char *val, acc_cable_type usb_cable_type)
{
	struct android_dev *dev = _android_dev;
	int ret = 0;
	unsigned long tmp;
	u16 pid;

	ret = strict_strtoul(val, 16, &tmp);
	if (ret)
		goto out;

	/* We come here even before android_probe, when product id
	 * is passed via kernel command line.
	 */
	if (!_android_dev) {
		device_desc.idProduct = tmp;
		goto out;
	}

	/* Ignore request same pid switching */
	if (device_desc.idProduct == tmp) {
		pr_info("[%s] Requested product id is same(%lx), ignore it\n", __func__, tmp);
		goto out;
	}

	/* set product id */
	pid = tmp;
	product_id = pid;
	device_desc.idProduct = __constant_cpu_to_le16(pid);
	if (dev->cdev)
		dev->cdev->desc.idProduct = device_desc.idProduct;

    if (pid == lg_factory_pid)
    {
        struct android_usb_product *up = dev->products;
        struct android_dev *dev = _android_dev;

        strings_dev[STRING_SERIAL_IDX].s = NULL;
        strings_dev[STRING_SERIAL_IDX].id = 0x00;
        dev->cdev->desc.iSerialNumber = 0x00;

        while (up->product_id != lg_factory_pid) up++;

        if (usb_cable_type == LT_CABLE_56K)
        {
            dev->cdev->desc.bcdUSB = cpu_to_le16(0x0110);
            up->num_functions = 2;
            dev->num_functions = 2;
        }
        else
        {
            dev->cdev->desc.bcdUSB = cpu_to_le16(0x0200);
            up->num_functions = 3;
            dev->num_functions = 3;
        }
    }
    else
    {
        strings_dev[STRING_SERIAL_IDX].s = serial_number;
        strings_dev[STRING_SERIAL_IDX].id = iSerialNumber_id;
        dev->cdev->desc.iSerialNumber = iSerialNumber_id;
        dev->cdev->desc.bcdUSB = cpu_to_le16(0x0200);
    }
    
	/* set function enable/disable and device class */
	android_set_default_product(pid);
	android_set_device_class(pid);

out:
	return ret;
}
#endif

static int android_get_pid(char *buffer, struct kernel_param *kp)
{
	int ret;

	mutex_lock(&_android_dev->lock);
	ret = sprintf(buffer, "%x", device_desc.idProduct);
	mutex_unlock(&_android_dev->lock);
	return ret;
}
#if 1//def CONFIG_USB_SUPPORT_LGE_ANDROID_AUTORUN
int android_set_usb_mode(const char *val, struct kernel_param *kp)
{
	int ret = 0;
    static u8 first_chk = 1;

//	return 0; //yss temp block
	
    if(first_chk == 1 )
    {
        first_chk = 0;
		return -EINVAL;
    }
	
	memset(usb_mode, 0, MAX_USB_MODE_LEN);
	pr_info("[%s] request connection mode : [%s]\n", __func__,val);

#ifdef CONFIG_LGE_USB_GADGET_LLDM_DRIVER
	if (get_lldm_sdio_mode())
	{
		ret = android_set_pid(lg_lldm_sdio_pid_string, NULL);
		return ret;
	}			
#endif

	if (strstr(val, "mass_storage")) {
		strcpy(usb_mode, "mass_storage");
		ret = android_set_pid(lg_ums_pid_string, NULL);
		return ret;
	}
#if 1//def CONFIG_USB_SUPPORT_LGE_ANDROID_AUTORUN_CGO
    else if (strstr(val, "charge_only")) {
		strcpy(usb_mode, "charge_only");
		ret = android_set_pid(lg_charge_only_pid_string, NULL);
		return ret;
	}
#endif
#ifdef CONFIG_LGE_USB_GADGET_MTP_DRIVER
	else if (strstr(val, "windows_media_sync")) {
		strcpy(usb_mode, "windows_media_sync");
		ret = android_set_pid(lg_mtp_pid_string, NULL);
		return ret;
	}
#endif
	else if (strstr(val, "internet_connection")) {
		strcpy(usb_mode, "internet_connection");
		ret = android_set_pid(lg_default_pid_string, NULL);
		return ret;
	}
#ifdef CONFIG_LGE_USB_AUTORUN	
	else if (strstr(val, "auto_run")) {
		strcpy(usb_mode, "auto_run");
		ret = android_set_pid(lg_auto_run_pid_string, NULL);
		return ret;
	}
#endif
	else {
		pr_info("[%s] undefined connection mode, ignore it : [%s]\n", __func__,val);
		return -EINVAL;
	}
}

static int android_get_usb_mode(char *buffer, struct kernel_param *kp)
{
	int ret;
	pr_info("[%s][%s] get usb connection mode\n", __func__, usb_mode);
	mutex_lock(&_android_dev->lock);
	ret = sprintf(buffer, "%s", usb_mode);
	mutex_unlock(&_android_dev->lock);
	return ret;
}
#endif

u16 android_get_product_id(void)
{
	if(device_desc.idProduct != 0x0000 && device_desc.idProduct != 0x0001)
		return device_desc.idProduct;
	else
		return lg_default_pid;
}
#endif /* CONFIG_LGE_USB_GADGET_DRIVER */

#ifdef CONFIG_LGE_USB_AUTORUN
static int android_set_usermode(const char *val, struct kernel_param *kp)
{
	int ret = 0;
	unsigned long tmp;

	ret = strict_strtoul(val, 16, &tmp);
	if (ret)
		return ret;

	autorun_user_mode = (unsigned int)tmp;
	pr_info("autorun user mode : %d\n", autorun_user_mode);

	return ret;
}

int get_autorun_user_mode(void)
{
	return autorun_user_mode;
}
EXPORT_SYMBOL(get_autorun_user_mode);
#endif


#ifdef CONFIG_DEBUG_FS
static int android_debugfs_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t android_debugfs_serialno_write(struct file *file, const char
				__user *buf,	size_t count, loff_t *ppos)
{
	char str_buf[MAX_STR_LEN];

	if (count > MAX_STR_LEN)
		return -EFAULT;

	if (copy_from_user(str_buf, buf, count))
		return -EFAULT;

	memcpy(serial_number, str_buf, count);

	if (serial_number[count - 1] == '\n')
		serial_number[count - 1] = '\0';

	strings_dev[STRING_SERIAL_IDX].s = serial_number;

	return count;
}
const struct file_operations android_fops = {
	.open	= android_debugfs_open,
	.write	= android_debugfs_serialno_write,
};

struct dentry *android_debug_root;
struct dentry *android_debug_serialno;

static int android_debugfs_init(struct android_dev *dev)
{
	android_debug_root = debugfs_create_dir("android", NULL);
	if (!android_debug_root)
		return -ENOENT;

	android_debug_serialno = debugfs_create_file("serial_number", 0222,
						android_debug_root, dev,
						&android_fops);
	if (!android_debug_serialno) {
		debugfs_remove(android_debug_root);
		android_debug_root = NULL;
		return -ENOENT;
	}
	return 0;
}

static void android_debugfs_cleanup(void)
{
       debugfs_remove(android_debug_serialno);
       debugfs_remove(android_debug_root);
}
#endif
static int __init android_probe(struct platform_device *pdev)
{
	struct android_usb_platform_data *pdata = pdev->dev.platform_data;
	struct android_dev *dev = _android_dev;
	int result;

	dev_dbg(&pdev->dev, "%s: pdata: %p\n", __func__, pdata);
#ifdef CONFIG_LGE_USB_FACTORY
    strcpy(serial_number, pdata->serial_number);
    if (pdata->product_id == lg_factory_pid)
    {
        pdata->serial_number = NULL;
        strings_dev[STRING_SERIAL_IDX].s = NULL;

        if (usb_cable_info == LT_CABLE_56K)
            device_desc.bcdUSB = cpu_to_le16(0x0110);
    }
#endif

	pm_runtime_set_active(&pdev->dev);
	pm_runtime_enable(&pdev->dev);

	result = pm_runtime_get(&pdev->dev);
	if (result < 0) {
		dev_err(&pdev->dev,
			"Runtime PM: Unable to wake up the device, rc = %d\n",
			result);
		return result;
	}

	if (pdata) {
		dev->products = pdata->products;
		dev->num_products = pdata->num_products;
		dev->functions = pdata->functions;
		dev->num_functions = pdata->num_functions;
		if (pdata->vendor_id)
			device_desc.idVendor =
				__constant_cpu_to_le16(pdata->vendor_id);
		if (pdata->product_id) {
			dev->product_id = pdata->product_id;
// [START] seunghun.kim : for LG_USB_DRIVER 2011.03.25
#ifdef CONFIG_LGE_USB_GADGET_DRIVER
			product_id = pdata->product_id;
#endif
// [END] seunghun.kim : for LG_USB_DRIVER 2011.03.25
			device_desc.idProduct =
				__constant_cpu_to_le16(pdata->product_id);
		}
		if (pdata->version)
			dev->version = pdata->version;

		if (pdata->product_name)
			strings_dev[STRING_PRODUCT_IDX].s = pdata->product_name;
		if (pdata->manufacturer_name)
			strings_dev[STRING_MANUFACTURER_IDX].s =
					pdata->manufacturer_name;
		if (pdata->serial_number)
			strings_dev[STRING_SERIAL_IDX].s = pdata->serial_number;
	}
#ifdef CONFIG_DEBUG_FS
	result = android_debugfs_init(dev);
	if (result)
		pr_debug("%s: android_debugfs_init failed\n", __func__);
#endif
	return usb_composite_register(&android_usb_driver);
}

static int andr_runtime_suspend(struct device *dev)
{
	dev_dbg(dev, "pm_runtime: suspending...\n");
	return 0;
}

static int andr_runtime_resume(struct device *dev)
{
	dev_dbg(dev, "pm_runtime: resuming...\n");
	return 0;
}

static struct dev_pm_ops andr_dev_pm_ops = {
	.runtime_suspend = andr_runtime_suspend,
	.runtime_resume = andr_runtime_resume,
};

static struct platform_driver android_platform_driver = {
	.driver = { .name = "android_usb", .pm = &andr_dev_pm_ops},
};

static int __init init(void)
{
	struct android_dev *dev;

	pr_debug("android init\n");

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	/* set default values, which should be overridden by platform data */
	dev->product_id = PRODUCT_ID;
	_android_dev = dev;

#ifdef CONFIG_LGE_USB_GADGET_DRIVER
    mutex_init(&dev->lock);
#endif

	return platform_driver_probe(&android_platform_driver, android_probe);

}
module_init(init);

static void __exit cleanup(void)
{
#ifdef CONFIG_DEBUG_FS
	android_debugfs_cleanup();
#endif
	usb_composite_unregister(&android_usb_driver);
	platform_driver_unregister(&android_platform_driver);
	kfree(_android_dev);
	_android_dev = NULL;
}
module_exit(cleanup);
