/* linux/drivers/usb/gadget/u_lgeusb.c
 *
 * Copyright (C) 2008 Google, Inc.
 * Copyright (C) 2010 LGE.
 * Author : Hyeon H. Park <hyunhui.park@lge.com>
 *			Youn Suk Song <younsuk.song@lge.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <mach/msm_hsusb.h>
#include <mach/rpc_hsusb.h>
#ifdef CONFIG_USB_ANDROID
#include <linux/usb/android.h>
#endif
#include <mach/board.h>

#include "u_lgeusb.h"

#ifdef CONFIG_LGE_USB_GADGET_SUPPORT_FACTORY_USB
/* FIXME: This length must be same as MAX_SERIAL_LEN in android.c */
#define MAX_SERIAL_NO_LEN 256
extern int msm_chg_LG_cable_type(void);
extern void msm_get_MEID_type(char* sMeid);

static int do_get_usb_serial_number(char *serial_number)
{
	memset(serial_number, 0, MAX_SERIAL_NO_LEN);
	msm_get_MEID_type(serial_number);
	printk(KERN_ERR "LG_FW :: %s Serail number %s \n",__func__, serial_number);

	if(!strcmp(serial_number,"00000000000000")) 
		serial_number[0] = '\0';
#if 0
	if(msm_chg_LG_cable_type() == LT_ADB_CABLE)
	{
		sprintf(serial_number,"%s","LGE_ANDROID_DE");
	}
#endif		

	return 0;
}

static int do_detect_factory_cable(void)
{
	int cable_type =  msm_chg_LG_cable_type();

	if((cable_type == LG_FACTORY_CABLE_130K_TYPE) ||
			(cable_type == LG_FACTORY_CABLE_130K_TYPE))
		return 1;
	else
		return 0;
}

/* Common Interface */

/*
 * lge_detect_factory_cable
 *
 * If factory cable (PIF or LT) is connected,
 * return 1, otherwise return 0.
 *
 */
int lge_detect_factory_cable(void)
{
	return do_detect_factory_cable();
}
EXPORT_SYMBOL(lge_detect_factory_cable);

/*
 * lge_get_usb_serial_number
 *
 * Get USB serial number from ARM9 using RPC or RAPI.
 * return -1 : If any error
 * return 0 : success
 *
 */
int lge_get_usb_serial_number(char *serial_number)
{
	return do_get_usb_serial_number(serial_number);
}
EXPORT_SYMBOL(lge_get_usb_serial_number);
#endif
