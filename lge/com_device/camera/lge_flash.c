/* 
*  
* Copyright (C) 2010-2011 LGE Inc.  
*
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

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/leds-pmic8058.h>
#include <linux/pwm.h>
#include <linux/pmic8058-pwm.h>
#include <linux/hrtimer.h>
#include <mach/pmic.h>
#include <mach/camera.h>
#include <mach/gpio.h>


/*---------------------------------------------------------------------------
    EXTERNAL DECLARATIONS
---------------------------------------------------------------------------*/
#ifdef CONFIG_LGE_FLASH_LM3559
extern int lm3559_flash_set_led_state(int state);
#endif 

/*---------------------------------------------------------------------------
  lge_flash_ctrl
---------------------------------------------------------------------------*/
int lge_flash_ctrl(struct msm_camera_sensor_info *sdata,
	struct flash_ctrl_data *flash_info)
{
	int rc = 0;

	CDBG(" %s:\n",__func__);
	
	switch (flash_info->flashtype) {
	case LED_FLASH:
		rc = lm3559_flash_set_led_state(flash_info->ctrl_data.led_state);
			break;
	case STROBE_FLASH:
		break;
	default:
		pr_err("Invalid Flash MODE\n");
		rc = -EINVAL;
	}
	return rc;
}


