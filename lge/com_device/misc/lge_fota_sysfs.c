// BEGIN : eundeok.bae@lge.com FTM MODE FOR ONLY KERNEL BOOTING
/* 
 * arch/arm/mach-msm/lge/lg_diag_testmode_sysfs.c
 *
 * Copyright (C) 2010 LGE, Inc
 *
 * This software is licensed under the terms of the GNU General Public
 * License vpseudomeidion 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/device.h>
//#include <linux/sysdev.h>
#include <linux/platform_device.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/limits.h>
//#include <mach/lg_diagcmd.h>
//#include <mach/lg_diag_testmode.h>

/* BEGIN: 0016311 jihoon.lee@lge.com 20110217 */
/* ADD 0016311: [POWER OFF] CALL EFS_SYNC */
/*#ifdef CONFIG_LGE_SYNC_CMD
#include <linux/kmod.h>
#include <linux/workqueue.h>
*/
#include <mach/oem_rapi_client.h>
//#endif

/* END: 0016311 jihoon.lee@lge.com 20110217 */

#define TESTMODE_DRIVER_NAME "testmode"

//extern uint8_t if_condition_is_on_air_plain_mode;
// BEGIN : munho.lee@lge.com 2010-12-10
// ADD: 0012164: [Hidden_menu] For gettng PCB version. 
//extern byte CheckHWRev(void);
// END : munho.lee@lge.com 2010-12-10

/* BEGIN: 0015325 jihoon.lee@lge.com 20110204 */
/* ADD 0015325: [KERNEL] HW VERSION FILE */
//#ifdef CONFIG_LGE_PCB_VERSION
//extern void lg_set_hw_version_string(char *pcb_version, int size);
/* BEGIN: 0015983 jihoon.lee@lge.com 20110214 */
/* MOD 0015983: [MANUFACTURE] HW VERSION DISPLAY */
//extern void CheckHWRevStr(char *buf, int str_size);
/* END: 0015983 jihoon.lee@lge.com 20110214 */
//#endif

/* END: 0015325 jihoon.lee@lge.com 20110204 */

#ifdef CONFIG_LGE_FOTA_MISC_INFO
extern int remote_rpc_request_val(uint32_t command, char *buf, int size);
#endif

/*static ssize_t sleep_flight_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int value = if_condition_is_on_air_plain_mode;
	if (value)
		printk("testmode sysfs: flight mode\n");

	return sprintf(buf, "%d\n", value);
}

static DEVICE_ATTR(sleep_flight, 0444, sleep_flight_show, NULL);

// BEGIN : munho.lee@lge.com 2010-12-10
// ADD: 0012164: [Hidden_menu] For gettng PCB version. 
*/
/*static ssize_t hw_rev_check(struct device *dev, struct device_attribute *attr, char *buf)
{
	byte rev = 0; 
	rev = CheckHWRev();
	printk("#LMH_TEST hw_rev_ceck() rev=%d \n", rev);	
	return sprintf(buf, "%d\n", rev);
}

static DEVICE_ATTR(rev_check, 0444, hw_rev_check, NULL);
// END : munho.lee@lge.com 2010-12-10
*/

/* BEGIN: 0015325 jihoon.lee@lge.com 20110204 */
/* ADD 0015325: [KERNEL] HW VERSION FILE */
// this file will be generated on /sys/devices/platform/testmode/hw_version
/*#ifdef CONFIG_LGE_PCB_VERSION
static char hw_pcb_version[17] = "Unknown";
static ssize_t lg_show_hw_version(struct sys_device *dev,
									struct sysdev_attribute *attr, char *buf)
{
	if (!strncmp(hw_pcb_version, "Unknown", 7)) 
	{
		printk(KERN_INFO "%s: get pcb version using rpc\n", __func__);
		//lg_set_hw_version_string((char *)hw_pcb_version, sizeof(hw_pcb_version));
*/
/* BEGIN: 0015983 jihoon.lee@lge.com 20110214 */
/* MOD 0015983: [MANUFACTURE] HW VERSION DISPLAY */
//		CheckHWRevStr((char *)hw_pcb_version, sizeof(hw_pcb_version));
//		printk(KERN_INFO "%s: pcb version %s\n", __func__, hw_pcb_version);
/* END: 0015983 jihoon.lee@lge.com 20110214 */
//	}
//	return snprintf(buf, sizeof(hw_pcb_version), "Rev.%s\n", hw_pcb_version);
//}

//static DEVICE_ATTR(hw_version, S_IRUGO | S_IRUSR, lg_show_hw_version, NULL);
//#endif
/* END: 0015325 jihoon.lee@lge.com 20110204 */

/* BEGIN: 0016311 jihoon.lee@lge.com 20110217 */
/* ADD 0016311: [POWER OFF] CALL EFS_SYNC */
// request sync using rpc
/*#ifdef CONFIG_LGE_SYNC_CMD

#ifdef CONFIG_LGE_SUPPORT_RAPI
extern int remote_rpc_request(uint32_t command);
#endif

static struct workqueue_struct *sync_cmd_wq;
struct __sync_cmd_data {
    unsigned long cmd;
    struct work_struct work;
};
static struct __sync_cmd_data sync_cmd_data;

static void sync_cmd_func(struct work_struct *work);

static ssize_t request_sync_cmd(struct device *dev, struct device_attribute *attr, char *buf)
{
	unsigned long cmd=0;

	if(buf == NULL)
	{
		printk(KERN_ERR "%s, NULL buffer\n", __func__);	
		return 0;
	}

	cmd = simple_strtoul(buf,NULL,10);

	// request sync through work queue and do not wait the response here, fast return
	if (cmd == 1)
	{
		printk(KERN_INFO "%s, received cmd : %ld, activate work queue\n", __func__, cmd);
		sync_cmd_data.cmd = cmd;
		queue_work(sync_cmd_wq, &sync_cmd_data.work);
	}
}

static DEVICE_ATTR(sync_cmd, S_IWUGO |S_IWUSR , NULL, request_sync_cmd);

static void
sync_cmd_func(struct work_struct *work)
{
	printk(KERN_INFO "%s, cmd : %ld\n", __func__, sync_cmd_data.cmd);	

	switch(sync_cmd_data.cmd)
	{
		case LGE_SYNC_REQUEST:
#ifdef CONFIG_LGE_SUPPORT_RAPI
			if(remote_rpc_request(LGE_SYNC_REQUEST) < 0)
				printk(KERN_ERR "%s, rpc request failed\n", __func__);
			else
				printk(KERN_INFO "%s, sync request succeeded\n", __func__);
#endif
			break;
		default:
			printk(KERN_ERR "%s, unknown command : %d\n", __func__, sync_cmd_data.cmd);
			break;
	}
	
	return;
}
#endif *//*CONFIG_LGE_SYNC_CMD*/
/* END: 0016311 jihoon.lee@lge.com 20110217 */

#ifdef CONFIG_LGE_FOTA_MISC_INFO
static char testmode_sw_version_info[50] = "UNKNOWN";
static ssize_t lg_show_sw_version_info(struct device *dev,
									struct device_attribute *attr, char *buf)
{
	char *split_char_ptr = NULL;
	printk(KERN_INFO "%s\n", __func__);
	
	if (!strncmp(testmode_sw_version_info, "UNKNOWN", 7)) 
	{
		remote_rpc_request_val(LGE_SW_VERSION_INFO, (char *)testmode_sw_version_info, sizeof(testmode_sw_version_info));
		printk(KERN_INFO "%s, SW version : %s\n", __func__, testmode_sw_version_info);
	}

	split_char_ptr = strstr(testmode_sw_version_info, "-");
	if(split_char_ptr == NULL)
	{
		printk(KERN_ERR "%s, NULL split ptr\n", __func__);
		return snprintf(buf, sizeof(testmode_sw_version_info), "%s\n", testmode_sw_version_info);
	}
	else
	{
		return snprintf(buf, (size_t)(split_char_ptr - testmode_sw_version_info +1), "%s\n", testmode_sw_version_info);
	}
}

static DEVICE_ATTR(sw_version_info, S_IRUGO | S_IRUSR, lg_show_sw_version_info, NULL);


static char testmode_min_info[50] = "UNKNOWN";
static ssize_t lg_show_min_info(struct device *dev,
									struct device_attribute *attr, char *buf)
{

	printk(KERN_INFO "%s\n", __func__);
	
	if (!strncmp(testmode_min_info, "UNKNOWN", 7)) 
	{
		remote_rpc_request_val(LGE_MIN_INFO, (char *)testmode_min_info, sizeof(testmode_min_info));
		printk(KERN_INFO "%s, MIN : %s\n", __func__, testmode_min_info);
	}
	return snprintf(buf, sizeof(testmode_min_info), "%s\n", testmode_min_info);
}

static DEVICE_ATTR(min_info, S_IRUGO | S_IRUSR, lg_show_min_info, NULL);
#endif


#if 1//def CONFIG_LGE_MANUAL_MODE_TEST
static char testmode_manual_mode_info[50] = "UNKNOWN";
#endif

#if 1//def CONFIG_LGE_MANUAL_MODE_TEST
static ssize_t lg_show_manual_mode_info(struct device *dev,
									struct device_attribute *attr, char *buf)
{
	printk(KERN_INFO "%s\n", __func__);
	remote_rpc_request_val(LGE_TESTMODE_MANUAL_TEST_INFO, (char *)testmode_manual_mode_info, sizeof(testmode_manual_mode_info));
	return snprintf(buf, sizeof(testmode_manual_mode_info), "%s\n", testmode_manual_mode_info);
}

static DEVICE_ATTR(manual_mode_info, S_IRUGO | S_IRUSR, lg_show_manual_mode_info, NULL);
#endif

static int __devinit testmode_probe(struct platform_device *pdev)
{
	int ret;

	printk("testmode_probe\n");

//	ret = device_create_file(&pdev->dev, &dev_attr_sleep_flight);
// BEGIN : munho.lee@lge.com 2010-12-10
// ADD: 0012164: [Hidden_menu] For gettng PCB version. 
//	ret = device_create_file(&pdev->dev, &dev_attr_rev_check);
// END : munho.lee@lge.com 2010-12-10

/* BEGIN: 0016311 jihoon.lee@lge.com 20110217 */
/* ADD 0016311: [POWER OFF] CALL EFS_SYNC */
// create file to receive command and generate work queue in order not to make any delays for the request
/*#ifdef CONFIG_LGE_SYNC_CMD
	ret = device_create_file(&pdev->dev, &dev_attr_sync_cmd);
	sync_cmd_wq = create_singlethread_workqueue("sync_cmd_wq");
	INIT_WORK(&sync_cmd_data.work, sync_cmd_func);
#endif */
/* END: 0016311 jihoon.lee@lge.com 20110217 */

/* BEGIN: 0015325 jihoon.lee@lge.com 20110204 */
/* ADD 0015325: [KERNEL] HW VERSION FILE */
/*#ifdef CONFIG_LGE_PCB_VERSION
	ret = device_create_file(&pdev->dev, &dev_attr_hw_version);
#endif */
/* END: 0015325 jihoon.lee@lge.com 20110204 */

#ifdef CONFIG_LGE_FOTA_MISC_INFO
	ret = device_create_file(&pdev->dev, &dev_attr_sw_version_info);
	ret = device_create_file(&pdev->dev, &dev_attr_min_info);
#endif
#if 1//def CONFIG_LGE_MANUAL_MODE_TEST
	ret = device_create_file(&pdev->dev, &dev_attr_manual_mode_info);
#endif
	if (ret < 0) {
		printk("device_create_file error!\n");
		return ret;
	}
	
	return ret;
}

static int __devexit testmode_remove(struct platform_device *pdev)
{	
  printk("testmode_remove\n");
  
 // device_remove_file(&pdev->dev, &dev_attr_sleep_flight);

// BEGIN : munho.lee@lge.com 2010-12-10
// ADD: 0012164: [Hidden_menu] For gettng PCB version. 
//  device_remove_file(&pdev->dev, &dev_attr_rev_check);
// END : munho.lee@lge.com 2010-12-10

/* BEGIN: 0015325 jihoon.lee@lge.com 20110204 */
/* ADD 0015325: [KERNEL] HW VERSION FILE */
//#ifdef CONFIG_LGE_PCB_VERSION
//  device_remove_file(&pdev->dev, &dev_attr_hw_version);
//#endif
/* END: 0015325 jihoon.lee@lge.com 20110204 */

/* BEGIN: 0016311 jihoon.lee@lge.com 20110217 */
/* ADD 0016311: [POWER OFF] CALL EFS_SYNC */
/*#ifdef CONFIG_LGE_SYNC_CMD
  device_remove_file(&pdev->dev, &dev_attr_sync_cmd);
#endif */
/* END: 0016311 jihoon.lee@lge.com 20110217 */

#ifdef CONFIG_LGE_FOTA_MISC_INFO
  device_remove_file(&pdev->dev, &dev_attr_sw_version_info);
  device_remove_file(&pdev->dev, &dev_attr_min_info);
#endif
#if 1//def CONFIG_LGE_MANUAL_MODE_TEST
  device_remove_file(&pdev->dev, &dev_attr_manual_mode_info);
#endif

	return 0;
}

static struct platform_driver testmode_driver = {
	.probe = testmode_probe,
	.remove = __devexit_p(testmode_remove),
	.driver = {
		.name = TESTMODE_DRIVER_NAME,
		.owner = THIS_MODULE,
	},
};

static int __devinit testmode_init(void)
{
  printk("testmode_init\n");
	return platform_driver_register(&testmode_driver);
}
module_init(testmode_init);

static void __devexit testmode_exit(void)
{
	platform_driver_unregister(&testmode_driver);
}
module_exit(testmode_exit);

MODULE_DESCRIPTION("TESTMODE Driver");
MODULE_LICENSE("GPL");
// END : eundeok.bae@lge.com FTM MODE FOR ONLY KERNEL BOOTING
