/* drivers/video/backlight/lm3530_bl.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/backlight.h>
#include <linux/fb.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <mach/board.h>

#include <mach/board_lge.h>
#define MAX_BRIGHTNESS 			0x71//20mA , shoogi.lee@lge.com, 2011_04_20
#define DEFAULT_BRIGHTNESS 		0x33//220nit, shoogi.lee@lge.com, 2011_04_20
#define I2C_BL_NAME "lm3530"

#define BL_ON	1
#define BL_OFF	0

#ifdef CONFIG_LGE_PM_FACTORY_CURRENT_DOWN
__attribute__((weak)) int usb_cable_info;
#endif

static struct i2c_client *lm3530_i2c_client;

struct backlight_platform_data {
   void (*platform_init)(void);
   int gpio;
   unsigned int mode;
   int max_current;
   int init_on_boot;
   int min_brightness;
//start, linear mode, shoogi.lee@lge.com, 2011_04_20
   int default_brightness;
   int max_brightness;
//end, linear mode, shoogi.lee@lge.com, 2011_04_20   
};

struct lm3530_device {
	struct i2c_client *client;
	struct backlight_device *bl_dev;
	int gpio;
	int max_current;
	int min_brightness;
//start, linear mode, shoogi.lee@lge.com, 2011_04_20
	int default_brightness;
	int max_brightness;
//end, linear mode, shoogi.lee@lge.com, 2011_04_20 
	struct mutex bl_mutex;
};

static const struct i2c_device_id lm3530_bl_id[] = {
	{ I2C_BL_NAME, 0 },
	{ },
};

static int lm3530_write_reg(struct i2c_client *client, unsigned char reg, unsigned char val);

static int cur_main_lcd_level = DEFAULT_BRIGHTNESS;
static int saved_main_lcd_level = DEFAULT_BRIGHTNESS;

static int backlight_status = BL_OFF;
static struct lm3530_device *main_lm3530_dev = NULL;

static void lm3530_hw_reset(void)
{
	int gpio = main_lm3530_dev->gpio;	
	
	gpio_tlmm_config(GPIO_CFG(gpio, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
	gpio_set_value(gpio, 1);
	mdelay(1);
}

static int lm3530_write_reg(struct i2c_client *client, unsigned char reg, unsigned char val)
{
	int err;
	u8 buf[2];
	struct i2c_msg msg = {
		client->addr, 0, 2, buf
	};

	buf[0] = reg;
	buf[1] = val;
	
	if ((err = i2c_transfer(client->adapter, &msg, 1)) < 0) {
		dev_err(&client->dev, "i2c write error\n");
	}
	
	return 0;
}

extern int lge_bd_rev;

static void lm3530_set_main_current_level(struct i2c_client *client, int level)
{
	struct lm3530_device *dev;
	int cal_value;
	
	int min_brightness = main_lm3530_dev->min_brightness;
	int max_current = main_lm3530_dev->max_current;
	int default_brightness=main_lm3530_dev->default_brightness;
   	int max_brightness=main_lm3530_dev->max_brightness;

   dev = (struct lm3530_device *)i2c_get_clientdata(client);
	cur_main_lcd_level = level; 
	dev->bl_dev->props.brightness = cur_main_lcd_level;

	mutex_lock(&main_lm3530_dev->bl_mutex);

	if(level!= 0){
		if(lge_bd_rev == LGE_REV_A) {
			cal_value = 0x7F - ( (MAX_BRIGHTNESS - level) * 2);
			lm3530_write_reg(client, 0x10, 0x11);	// device enable with 19mA full scale.
			lm3530_write_reg(client, 0xA0, cal_value);
		}
		else if(lge_bd_rev == LGE_REV_B) {
			if((level == 22) || (level == 21) || (level == 20))
				cal_value = 0x7F;
			if((level == 19) || (level == 18) || (level == 17) || (level == 16))
				cal_value = 0x7B;
			if((level == 15) || (level == 14) || (level == 13) || (level == 12))
				cal_value = 0x77;
			if((level == 11) || (level == 10) || (level == 9) || (level == 8))
				cal_value = 0x73;
			if((level == 7))
				cal_value = 0x6F;
			if((level == 6))
				cal_value = 0x6B;
			if((level == 5))
				cal_value = 0x67;
			if((level == 4))
				cal_value = 0x63;
			if((level == 3))
				cal_value = 0x5F;
			if((level == 2) || (level == 1))
				cal_value = 0x57;

			// Change code for testing only. minjong.gong@lge.com
			lm3530_write_reg(client, 0x10, 0x11);	// device enable with 19mA full scale.
			lm3530_write_reg(client, 0xA0, cal_value);
		}
		else if(lge_bd_rev >= LGE_REV_C) {		
			// ACL + default setting
			if(level < 26)
				cal_value = min_brightness;
			else if(level >= 26 && level < 32)
				cal_value = 0x10;
			else if(level >= 32 && level < 39)
				cal_value = 0x16;
			else if(level >= 39 && level < 46)
				cal_value = 0x1E;
			else if(level >= 46 && level < 51)
				cal_value = 0x28;
			else if(level >= 51 && level < 54)
				cal_value = 0x31;
			else if(level >= 54 && level < 56)
				cal_value = 0x35;
			else if(level >= 56 && level < 64)
				cal_value = 0x38;
			else if(level == 64)
				cal_value = 0x40;
			else if(level >64)
				cal_value = (level - 51) * (max_brightness - default_brightness) / (113 - 51) + default_brightness;

			if(cal_value > max_brightness)
				cal_value = max_brightness;

#ifdef CONFIG_LGE_PM_FACTORY_CURRENT_DOWN
			if((usb_cable_info == 6) ||(usb_cable_info == 7)||(usb_cable_info == 11))
			{
				cal_value = min_brightness;
			}
#endif
			/*
			if (level <= 15)
			{
				cal_value = min_brightness;
			}
			else if(level > 15 && level <= 51) //level = UI value/ 2, default UI level =102
			{
				cal_value = (level - 15) * (default_brightness - min_brightness) / (51 - 15) + min_brightness;
			}
			else if(level >51)
			{
				cal_value = (level - 51) * (max_brightness - default_brightness) / (127 - 51) + default_brightness;
			}
			*/
			
			lm3530_write_reg(client, 0x10, max_current);
			lm3530_write_reg(client, 0xA0, cal_value);
			lm3530_write_reg(client, 0x30, 0x2d); //fade in, out //101101 16.384ms/step

			//printk("%s() :level is : %d, cal_value is : 0x%x\n", __func__, level, cal_value);
		}
	}
	else{
		
		lm3530_write_reg(client, 0x10, 0x00);
	}

	//msleep(1);

	mutex_unlock(&main_lm3530_dev->bl_mutex);
}

void lm3530_backlight_on(int level)
{
	//printk("%s received (prev backlight_status: %s)\n", __func__, backlight_status?"ON":"OFF");
	lm3530_hw_reset();
	lm3530_set_main_current_level(main_lm3530_dev->client, level);
	backlight_status = BL_ON;

	return;
}

void lm3530_backlight_off(void)
{
	int gpio = main_lm3530_dev->gpio;

	if (backlight_status == BL_OFF) return;
	saved_main_lcd_level = cur_main_lcd_level;
	lm3530_set_main_current_level(main_lm3530_dev->client, 0);
	backlight_status = BL_OFF;

	gpio_tlmm_config(GPIO_CFG(gpio, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
	gpio_direction_output(gpio, 0);
	msleep(6);
	
	return;
}

void lm3530_lcd_backlight_set_level( int level)
{
	if (level > MAX_BRIGHTNESS)
		level = MAX_BRIGHTNESS;

	if(lm3530_i2c_client!=NULL )
	{		
		if(level == 0) {
			lm3530_backlight_off();
		} else {
			lm3530_backlight_on(level);
		}

		//printk("%s() : level is : %d\n", __func__, level);
	}else{
		printk("%s(): No client\n",__func__);
	}
}
EXPORT_SYMBOL(lm3530_lcd_backlight_set_level);

static int bl_set_intensity(struct backlight_device *bd)
{
	
	struct i2c_client *client = to_i2c_client(bd->dev.parent);

	lm3530_set_main_current_level(client, bd->props.brightness);
	cur_main_lcd_level = bd->props.brightness; 
	
	return 0;
}

static int bl_get_intensity(struct backlight_device *bd)
{
    unsigned char val=0;
	 val &= 0x1f;
    return (int)val;
}

static ssize_t lcd_backlight_show_level(struct device *dev, struct device_attribute *attr, char *buf)
{
	int r;

	r = snprintf(buf, PAGE_SIZE, "LCD Backlight Level is : %d\n", cur_main_lcd_level);
	
	return r;
}

static ssize_t lcd_backlight_store_level(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int level;
	struct i2c_client *client = to_i2c_client(dev); 

	if (!count)
		return -EINVAL;
	
	level = simple_strtoul(buf, NULL, 10);
	
	if (level > MAX_BRIGHTNESS)
		level = MAX_BRIGHTNESS;

	lm3530_set_main_current_level(client, level);
	cur_main_lcd_level = level; 
	
	return count;
}

static int lm3530_bl_resume(struct i2c_client *client)
{
    lm3530_backlight_on(saved_main_lcd_level);
    
    return 0;
}

static int lm3530_bl_suspend(struct i2c_client *client, pm_message_t state)
{
    printk(KERN_INFO"%s: new state: %d\n",__func__, state.event);

    lm3530_backlight_off();

    return 0;
}

static ssize_t lcd_backlight_show_on_off(struct device *dev, struct device_attribute *attr, char *buf)
{
	int r = 0;

	printk("%s received (prev backlight_status: %s)\n", __func__, backlight_status?"ON":"OFF");

	return r;
}

static ssize_t lcd_backlight_store_on_off(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int on_off;
	struct i2c_client *client = to_i2c_client(dev); 

	if (!count)
		return -EINVAL;
	
	printk("%s received (prev backlight_status: %s)\n", __func__, backlight_status?"ON":"OFF");
	
	on_off = simple_strtoul(buf, NULL, 10);
	
	printk(KERN_ERR "%d",on_off);
	
	if(on_off == 1){
		lm3530_bl_resume(client);
	}else if(on_off == 0)
	    lm3530_bl_suspend(client, PMSG_SUSPEND);
	
	return count;

}
DEVICE_ATTR(lm3530_level, 0644, lcd_backlight_show_level, lcd_backlight_store_level);
DEVICE_ATTR(lm3530_backlight_on_off, 0644, lcd_backlight_show_on_off, lcd_backlight_store_on_off);

static struct backlight_ops lm3530_bl_ops = {
	.update_status = bl_set_intensity,
	.get_brightness = bl_get_intensity,
};

static int lm3530_probe(struct i2c_client *i2c_dev, const struct i2c_device_id *id)
{
	struct backlight_platform_data *pdata;
	struct lm3530_device *dev;
	struct backlight_device *bl_dev;
	struct backlight_properties props;
	int err;

	printk(KERN_INFO"%s: i2c probe start\n", __func__);

	pdata = i2c_dev->dev.platform_data;
	lm3530_i2c_client = i2c_dev;

	dev = kzalloc(sizeof(struct lm3530_device), GFP_KERNEL);
	if(dev == NULL) {
		dev_err(&i2c_dev->dev,"fail alloc for lm3530_device\n");
		return 0;
	}

	main_lm3530_dev = dev;

	memset(&props, 0, sizeof(struct backlight_properties));
	props.max_brightness = MAX_BRIGHTNESS;
	
	bl_dev = backlight_device_register(I2C_BL_NAME, &i2c_dev->dev, NULL, &lm3530_bl_ops, &props);
	bl_dev->props.max_brightness = MAX_BRIGHTNESS;
	bl_dev->props.brightness = DEFAULT_BRIGHTNESS;
	bl_dev->props.power = FB_BLANK_UNBLANK;
	
	dev->bl_dev = bl_dev;
	dev->client = i2c_dev;
	dev->gpio = pdata->gpio;
	dev->max_current = pdata->max_current;
	dev->min_brightness = pdata->min_brightness;
	//start, linear mode, shoogi.lee@lge.com, 2011_04_20
	dev->default_brightness = pdata->default_brightness;
	dev->max_brightness = pdata->max_brightness;
	//end, linear mode, shoogi.lee@lge.com, 2011_04_20
	i2c_set_clientdata(i2c_dev, dev);

	if(dev->gpio && gpio_request(dev->gpio, "lm3530 reset") != 0) {
		return -ENODEV;
	}

	mutex_init(&dev->bl_mutex);

#ifdef CONFIG_LGE_BOOTLOADER_DISP_INIT
#else
	lm3530_hw_reset();
	lm3530_backlight_on(DEFAULT_BRIGHTNESS);
#endif

	err = device_create_file(&i2c_dev->dev, &dev_attr_lm3530_level);
	err = device_create_file(&i2c_dev->dev, &dev_attr_lm3530_backlight_on_off);

	return 0;
}

static int lm3530_remove(struct i2c_client *i2c_dev)
{
	struct lm3530_device *dev;
	int gpio = main_lm3530_dev->gpio;

 	device_remove_file(&i2c_dev->dev, &dev_attr_lm3530_level);
 	device_remove_file(&i2c_dev->dev, &dev_attr_lm3530_backlight_on_off);
	dev = (struct lm3530_device *)i2c_get_clientdata(i2c_dev);
	backlight_device_unregister(dev->bl_dev);
	i2c_set_clientdata(i2c_dev, NULL);

	if (gpio_is_valid(gpio))
		gpio_free(gpio);
	return 0;
}	

static struct i2c_driver main_lm3530_driver = {
	.probe = lm3530_probe,
	.remove = lm3530_remove,
	.suspend = NULL,
	.resume = NULL,
	.id_table = lm3530_bl_id, 
	.driver = {
		.name = I2C_BL_NAME,
		.owner = THIS_MODULE,
	},
};


static int __init lcd_backlight_init(void)
{
	static int err=0;

	err = i2c_add_driver(&main_lm3530_driver);

	return err;
}
 
module_init(lcd_backlight_init);

MODULE_DESCRIPTION("LM3530 Backlight Control");
MODULE_AUTHOR("Jaeseong Gim <jaeseong.gim@lge.com>");
MODULE_LICENSE("GPL");
