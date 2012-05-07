/* Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */
 
/*
 * SDIO Debug Channel Driver 
  		-- Provides SDIO_ULS port interface.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/workqueue.h>
#include <linux/pm_runtime.h>
#include <linux/platform_device.h>
#include <mach/sdio_al.h>
#include <linux/timer.h>
#include <linux/gpio.h>
#include <mach/subsystem_restart.h>
#define LGE_FW_MDM_FATAL_NO_HIGH
#ifdef LGE_FW_MDM_FATAL_NO_HIGH
#define MDM2AP_ERRFATAL_GPIO 133
struct timer_list fatal_timer;
#endif


#define SDIO_DEBUG_CH_INFO
#ifdef	SDIO_DEBUG_CH_INFO
#define LTE_INFO(fmt,args...) printk("[%s] "fmt,__FUNCTION__, ## args)
#else
#define LTE_INFO(fmt,args...)
#endif

// ----------------------------------------------------
//		Following data structure should be synced with MDM side
// ----------------------------------------------------

#define ULS_LOG_FORMAT_VAL_MODE			(1)			// 1: uls mode, 0: test mode - always 1 is used
#define ULS_LOG_FORMAT_LEN_FILE_NAME	(50)		// refer to 	ERR_LOG_MAX_FILE_LEN in errlog.h
#define ULS_LOG_FORMAT_LEN_LINE			(4)			// uint32 in errlog.h
#define ULS_LOG_FORMAT_LEN_ERR_MSG		(80)		// refer to ERR_LOG_MAX_MSG_LEN in errlog.h
#define ULS_LOG_FORMAT_LEN_SW_VER		(100)		//[ULS] for s/w ver display < wj1208.jo@lge.com >

// buffers used by ULS client
typedef struct 
{
	short	mode; 			// mode is always 1 (0: test mode, 1: ULS mode)
	short	total_size; 	// header + body
} tULS_Rx_Header;

typedef struct  
{
	tULS_Rx_Header header;
	char 	filename[ULS_LOG_FORMAT_LEN_FILE_NAME];
	int		line;
	char 	msg[ULS_LOG_FORMAT_LEN_ERR_MSG];	
	char	sw_ver[ULS_LOG_FORMAT_LEN_SW_VER]; //[ULS] for s/w ver display < wj1208.jo@lge.com >
} tULS_Rx_Data;

// rx log information
tULS_Rx_Data		*g_p_uls_rx_log = NULL;

typedef struct
{
	bool				valid;		// 0: invalid, 1: valid
	tULS_Rx_Data		rx_data;	// contains debugging information
} tULS_PRx_Data;


// for UI display
tULS_PRx_Data		g_uls_rx_data = {0,};
// ----------------------------------------------

static void sdio_debug_read(struct work_struct *work);
static DECLARE_WORK(sdio_debug_work, sdio_debug_read);
static struct workqueue_struct *sdio_debug_wq;

struct sdio_channel *sdio_debug_ch;

#ifdef LGE_FW_MDM_FATAL_NO_HIGH
static void sdio_debug_mdm_fatal_time_func(unsigned long v)
{
       del_timer(&fatal_timer);
       if (gpio_get_value(MDM2AP_ERRFATAL_GPIO) != 1)
       {
               LTE_INFO("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
               LTE_INFO("ULS sent from MDM, But MDM error fatal gpio doesn't go to high within 10 seconds!!!\n");
               subsystem_restart("external_modem");
       }

}
#endif


static void sdio_debug_display_uls_log(void *buff)
{
	g_p_uls_rx_log = (tULS_Rx_Data *)buff;
	LTE_INFO("[ULS] ------------------------------------------\n");	
	LTE_INFO("[ULS] [Asserted] File: %s, Line: %d\n",g_p_uls_rx_log->filename, g_p_uls_rx_log->line);	
	LTE_INFO("[ULS] Error Message: %s \n", g_p_uls_rx_log->msg);
	LTE_INFO("[ULS] SW Version: %s \n", g_p_uls_rx_log->sw_ver); //[ULS] for s/w ver display < wj1208.jo@lge.com  2011.09.06 >
	LTE_INFO("[ULS] ------------------------------------------\n");

	g_uls_rx_data.rx_data = *((tULS_Rx_Data *)buff);
	g_uls_rx_data.valid		= true;		// set to true after copying uls_log

#ifdef LGE_FW_MDM_FATAL_NO_HIGH
       init_timer(&fatal_timer);
       fatal_timer.expires = 10*HZ + jiffies;  // 10 second 
       fatal_timer.data = 1;
       fatal_timer.function = &sdio_debug_mdm_fatal_time_func; /* timer handler */
       add_timer(&fatal_timer);
#endif

}

static void sdio_debug_read(struct work_struct *work)
{
	int read_avail = 0, rc = 0;
	char *buff = NULL;

	LTE_INFO("++\n");
	
	read_avail = sdio_read_avail(sdio_debug_ch);
	LTE_INFO("read_avail = %d\n", read_avail);
	if(read_avail <= 0 )
	{
		LTE_INFO("read_avail is not available value!!!\n");		
		return;
	}
	
	buff = kmalloc(read_avail, GFP_KERNEL);
	if(buff == NULL)
	{
		LTE_INFO("buff memory allocation is failed!!");
		return;
	}
	
	rc = sdio_read(sdio_debug_ch, (void*)buff, read_avail);
	if (rc) 
	{
		LTE_INFO("sdio read failed %d\n", rc);
		kfree(buff);
		return;
	}		

#ifdef	SDIO_DEBUG_CH_INFO
	sdio_debug_display_uls_log(buff);
//	LTE_INFO("[ULS] File Data : %s\n", buff );	
#endif
	LTE_INFO("--\n");

}

static void sdio_debug_notify(void *ctxt, unsigned event) 
{
	LTE_INFO("++\n");
	if (event == SDIO_EVENT_DATA_READ_AVAIL){
		LTE_INFO(" Received SDIO_EVENT_DATA_READ_AVAIL\n");
		queue_work(sdio_debug_wq, &sdio_debug_work);
	}		

	if (event == SDIO_EVENT_DATA_WRITE_AVAIL){
		LTE_INFO("Received SDIO_EVENT_DATA_WRITE_AVAIL\n");
		LTE_INFO("Writing operation is not supported\n");
	}
	LTE_INFO("--\n");
}

static int sdio_debug_probe(struct platform_device *pdev)
{
	int err = 0;
	LTE_INFO("++\n");

	sdio_debug_wq = create_singlethread_workqueue("sdio_debug_ch_wq");
	if (IS_ERR(sdio_debug_wq))
		return -ENOMEM;

	err = sdio_open("SDIO_ULS", &sdio_debug_ch, NULL,
							 sdio_debug_notify);
	if (err)
		LTE_INFO("could not open SDIO debug channel\n");
	else
		LTE_INFO("opened SDIO debug channel\n");

	LTE_INFO("--\n");
	return err;
}

static int sdio_debug_remove(struct platform_device *pdev)
{
	sdio_close(sdio_debug_ch);
	if( sdio_debug_wq )
		destroy_workqueue(sdio_debug_wq);

	return 0;
}


static int sdio_debug_runtime_suspend(struct device *dev)
{
	LTE_INFO("++\n");
	return 0;
}

static int sdio_debug_runtime_resume(struct device *dev)
{
	LTE_INFO("++\n");
	return 0;
}

static const struct dev_pm_ops sdio_debug_dev_pm_ops = {
	.runtime_suspend = sdio_debug_runtime_suspend,
	.runtime_resume = sdio_debug_runtime_resume,
};

static struct platform_driver sdio_debug_ch_driver = {
	.probe = sdio_debug_probe,
	.remove = sdio_debug_remove,
	.driver = {
		   .name = "SDIO_ULS",
		   .owner = THIS_MODULE,
		   },
};

static int __init sdio_debug_init(void)
{
	int ret = 0;
	LTE_INFO("++\n");

	ret = platform_driver_register(&sdio_debug_ch_driver);
	
	if (ret)
		LTE_INFO(" could not register SDIO device\n");
	else
		LTE_INFO(" successfully registered SDIO device");
	
	LTE_INFO("--\n");
	return ret;

}

static void __exit sdio_debug_exit(void)
{
	platform_driver_unregister(&sdio_debug_ch_driver);
}

module_init(sdio_debug_init);
module_exit(sdio_debug_exit);

MODULE_DESCRIPTION("MDM SDIO DEBUG Channel");
MODULE_LICENSE("GPL v2");

