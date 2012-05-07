/* lge/com_device/display/mhl/mhl_sii9244.h 
*
* SiI9244 Mobile High-definition Link(MHL) Transmitter driver
*  
* Copyright (C) 2011-2012 LGE Inc.  
* Chanhee Park <chanhee.park@lge.com>
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

#ifndef __SII9244_H__
#define __SII9244_H__

#include <linux/debugfs.h>
#include <linux/delay.h>

#define MHL_SII9244_DEBUG

#ifdef MHL_SII9244_DEBUG
#define MHL_MSG(fmt, args...)	printk(KERN_ERR "MHL_MSG [%-18s:%5d] " fmt, __FUNCTION__, __LINE__, ## args)
#define MHL_ERR(fmt, args...)	printk(KERN_ERR "MHL_ERR [%-18s:%5d] " fmt, __FUNCTION__, __LINE__, ## args)
#else
#define MHL_MSG(fmt, args...)
#define MHL_ERR(fmt, args...)
#endif


#define SII9244_PAGE0_I2C_NAME  		"sii9244_i2c_page0"
#define SII9244_PAGE1_I2C_NAME  		"sii9244_i2c_page1"
#define SII9244_PAGE2_I2C_NAME  		"sii9244_i2c_page2"
#define SII9244_PAGE3_I2C_NAME  		"sii9244_i2c_page3"
#define SII9244_DRIVER                           "sii9244_driver"

#define SII9244_PAGE0_SLAVE_ADDR	0x72 
#define SII9244_PAGE1_SLAVE_ADDR 	0x7A
#define SII9244_PAGE2_SLAVE_ADDR 	0x92
#define SII9244_PAGE3_SLAVE_ADDR 	0xC8



int 	 sii9244_i2c_device_id_write(u8 device_id, u8 offset, u8 value);
int 	 sii9244_i2c_device_id_read(u8 device_id, u8 offset);
void  sii9244_init_wakeup_hrtimer(void);
void  sii9244_start_wakeup_hrtimer(unsigned long delay_in_ms);


void  MHL_On(bool on);
//void rcp_cbus_uevent(u8);	


#endif //__MHL_SII9244_H__

