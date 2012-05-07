/* drivers/video/backlight/lm3537_bl.c
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

//seungkwan.jung
#include <mach/board_lge.h>

#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>
#endif

//#define lm3537_DBG

// Change code for testing. minjong.gong@lge.com
#define MAX_BRIGHTNESS 		128	// 19 steps. 1step : 1mA
#define DEFAULT_BRIGHTNESS 	55	//  60% of full scale

#define BL_ON	1
#define BL_OFF	0

#ifdef CONFIG_LGE_PM_FACTORY_CURRENT_DOWN
__attribute__((weak)) int usb_cable_info;
#endif

static struct i2c_client *lm3537_i2c_client;

struct lm3537_device {
	struct i2c_client *client;
	struct backlight_device *bl_dev;
    struct early_suspend early_suspend; 
};

struct bl_ctrl_data {
	unsigned short reg;
	unsigned short val;
};

#define LCD_DCDC_EN 49
#define I2C_BL_NAME "lm3537"

static const struct i2c_device_id lm3537_bl_id[] = {
	{ I2C_BL_NAME, 0 },
	{ },
};
static int alc_mode=1;

enum{
	POWERSAVE_MODE = 0, 
	OPTIMIZE_MODE = 1,
	ALC_MANUAL_MODE = 2
	};

static int lm3537_write_reg(struct i2c_client *client, unsigned char reg, unsigned char val);

static int cur_main_lcd_level = DEFAULT_BRIGHTNESS;
static int saved_main_lcd_level = DEFAULT_BRIGHTNESS;
static int lm3537_power_off=0;

static int backlight_status = BL_OFF;
static struct lm3537_device *main_lm3537_dev = NULL;

static void lm3537_hreset(void)
{
#if defined(lm3537_DBG)
		printk("%s()  lm3537_hardware_reset !!\n",__func__);
#endif
	gpio_tlmm_config(GPIO_CFG(LCD_DCDC_EN, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
	mdelay(1);
	gpio_set_value(LCD_DCDC_EN, 1);
}

static int lm3537_write_reg(struct i2c_client *client, unsigned char reg, unsigned char val)
{
	int err;
	u8 buf[2];
	struct i2c_msg msg = {	
		client->addr, 0, 2, buf 
	};

	buf[0] = reg;
	buf[1] = val;
	
	if(lm3537_power_off)	
	{
	#if defined(lm3537_DBG)
		printk("%s()  this message never called if this message call error found!!!\n",__func__);
	#endif		
		return 0;
	}
	if ((err = i2c_transfer(client->adapter, &msg, 1)) < 0) {
		dev_err(&client->dev, "i2c write error\n");
	}
#if defined(lm3537_DBG)
		printk("%s()  ==[Backlight]write register value = %x\n",__func__ ,val);
#endif
	return 0;
}

static void lm3537_set_main_current_level(struct i2c_client *client, int level)
{
	struct lm3537_device *dev;
	int cal_value;
		
    dev = (struct lm3537_device *)i2c_get_clientdata(client);
	cur_main_lcd_level = level; 
	dev->bl_dev->props.brightness = cur_main_lcd_level;

	// ACL + default setting
	              if(level < 16)
                                   cal_value = 35;
                  else if(level >= 16 && level < 22)
                                   cal_value = 55;
                  else if(level >= 22 && level < 25)
                                   cal_value = 76;
                  else if(level >= 25 && level < 28)
                                   cal_value = 80;
                  else if(level >= 28 && level < 32)
                                   cal_value = 82;
                  else if(level >= 32 && level < 35)
                                   cal_value = 85;
                  else if(level >= 35 && level < 39)
                                   cal_value = 88;
                  else if(level >= 39 && level < 40)
                                   cal_value = 92;
                  else if(level >= 40 && level < 42)
                                   cal_value = 93;
                  else if(level >= 42 && level < 45)
                                   cal_value = 97;
                  else if(level >= 45 && level < 47)
                                   cal_value = 98;
                  else if(level >= 47 && level < 49)
                                   cal_value = 100;
                  else if(level >= 49 && level < 52)
                                   cal_value = 101;
                  else if(level >= 52 && level < 54)
                                   cal_value = 103;
		    else if(level >= 54 && level < 56)
                                   cal_value = 104;
                  else if(level >= 56 && level < 61)
                                   cal_value = 105;
                  else if(level >= 61 && level < 68)
                                   cal_value = 107;
                  else if(level >= 68 && level < 75)
                                   cal_value = 109;
                  else if(level >= 75 && level < 82)
                                   cal_value = 110;
                  else if(level >= 82 && level < 83)
                                   cal_value = 111;
                 else if(level >= 83 && level < 85)
                                   cal_value = 112;
                  else if(level == 85)
                                   cal_value = 113;
                  else if(level >85)
                                   cal_value = (level - 51) * (MAX_BRIGHTNESS - 107) / 105 + 107;

#ifdef CONFIG_LGE_PM_FACTORY_CURRENT_DOWN
    if((usb_cable_info == 6) ||(usb_cable_info == 7)||(usb_cable_info == 11))
    {
	    cal_value = 25;
	}
#endif
	if(cal_value > 0x7B) cal_value = 0x7B;
		lm3537_write_reg(client, 0xA0, cal_value);
	if(cal_value==123)
		lm3537_write_reg(main_lm3537_dev->client, 0x20, 0x3c);
	mdelay(1);
}

//seungkwan.jung
extern int lge_bd_rev;

void lm3537_init(void)
{
#if defined(lm3537_DBG)
	printk(" %s()\n ", __func__);
#endif
	lm3537_write_reg(main_lm3537_dev->client, 0x00, 0x04);   //group A eanble
	mdelay(1);
	lm3537_write_reg(main_lm3537_dev->client, 0x10, 0xff);	// device enable with 19mA full scale.
	mdelay(1);
	lm3537_write_reg(main_lm3537_dev->client, 0x20, 0x3d);
	mdelay(1);
	lm3537_write_reg(main_lm3537_dev->client, 0x30, 0x1B);	 //speed -slow !!!!
if(lge_bd_rev ==LGE_REV_C){
	mdelay(1);
	lm3537_write_reg(main_lm3537_dev->client, 0xc1, 0x0c);	 //LDO1 VOUT
	mdelay(1);
	lm3537_write_reg(main_lm3537_dev->client, 0xC0, 0x01);	 //LDO ENABLE
	}
}

extern int pm8058_set_led_current(enum pmic8058_leds id, unsigned mA);

void lm3537_backlight_on(int level)
{
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_CMD_WVGA_PT)
	lm3537_hreset();
#endif
	if(backlight_status == BL_OFF)
	{
		lm3537_init();
		backlight_status = BL_ON;	
	}
    pm8058_set_led_current(PMIC8058_ID_LED_KB_LIGHT,20); //max brightness
	lm3537_set_main_current_level(main_lm3537_dev->client, level);

#if defined(CONFIG_LGE_KEY_BACKLIGHT_ALC)
#if defined(lm3537_DBG)
       printk("lm3537_backlight_on  key_light_luxValue : %d \n",key_light_luxValue);
#endif
       if(key_light_luxValue > 100)
               pm8058_set_led_current(PMIC8058_ID_LED_KB_LIGHT,0);
       else
               pm8058_set_led_current(PMIC8058_ID_LED_KB_LIGHT,15*20); //max brightness
#endif


	
#if defined(lm3537_DBG)
	printk(" %s()  level : %d : \n", __func__,level);
#endif

	return;
}
EXPORT_SYMBOL(lm3537_backlight_on); //using testmode only...

void lm3537_backlight_off(void)
{
	saved_main_lcd_level = cur_main_lcd_level;
	lm3537_set_main_current_level(main_lm3537_dev->client, 0);
	mdelay(1);
	lm3537_write_reg(main_lm3537_dev->client, 0x00, 0x00);	 //group A disable
    pm8058_set_led_current(PMIC8058_ID_LED_KB_LIGHT,0); //max brightness

#if defined(lm3537_DBG)
	printk(" %s()\n ", __func__);
#endif
	backlight_status = BL_OFF;	

	return;
}
EXPORT_SYMBOL(lm3537_backlight_off); //using testmode only...


void lm3537_sw_reset(void)
{
	lm3537_write_reg(main_lm3537_dev->client, 0x00, 0x01);	 //sw_reset!!
	mdelay(1);
}

//seungkwan.jung
void lm3537_initialization_ldo(void)
{
	static int initial = 0;
	if(initial == 0)
	{
		initial =1;
		lm3537_hreset();
		lm3537_init();
	}	
}

void lm3537_ldo1_on(void)
{	
	if(main_lm3537_dev!=NULL)
	{
		lm3537_write_reg(main_lm3537_dev->client, 0xC0, 0x01);   //LDO ENABLE
		mdelay(1);		
	}

}
EXPORT_SYMBOL(lm3537_ldo1_on);

void lm3537_ldo1_off(void)
{
	if(main_lm3537_dev!=NULL)
	{
		lm3537_write_reg(main_lm3537_dev->client, 0xC0, 0x00);   //LDO disable
	}
}
EXPORT_SYMBOL(lm3537_ldo1_off);

void lm3537_lcd_backlight_set_level( int level)
{

	if (level > MAX_BRIGHTNESS)
		level = MAX_BRIGHTNESS;

	if(lm3537_i2c_client!=NULL )
	{		
		if(level == 0) {
			lm3537_backlight_off();
		}
		else {
			lm3537_backlight_on(level);
		}
#if defined(lm3537_DBG)
	printk("%s() : level is : %d\n", __func__, level);
#endif

	}else{
		printk("%s(): No client\n",__func__);
	}
}
EXPORT_SYMBOL(lm3537_lcd_backlight_set_level);

static int bl_set_intensity(struct backlight_device *bd)
{
	struct i2c_client *client = to_i2c_client(bd->dev.parent);

	lm3537_set_main_current_level(client, bd->props.brightness);
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

	lm3537_set_main_current_level(client, level);
	cur_main_lcd_level = level; 
	
	return count;
}

static ssize_t lcd_backlight_show_powersave(struct device *dev, struct device_attribute *attr, char *buf)
	{
		int r;

		if(alc_mode == POWERSAVE_MODE)
				r = snprintf(buf, PAGE_SIZE, "%d\n",0);
		else if(alc_mode == OPTIMIZE_MODE)
				r = snprintf(buf, PAGE_SIZE, "%d\n",1);
		else if(alc_mode == ALC_MANUAL_MODE)
				r = snprintf(buf, PAGE_SIZE, "%d\n",2);
		else
				r = snprintf(buf, PAGE_SIZE, "%s\n","N/A");
	
		return r;
	}

static ssize_t lcd_backlight_store_powersave(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
	{
		int value = 2;		
		
		if (!count) {
			return -EINVAL;
		}
		value = simple_strtoul(buf, NULL, 10);
#if defined(lm3537_DBG)
		printk("%s() current mode is %d   0-POWERSAVE_MODE 1-OPTIMIZE_MODE 2-MANUAL_MODE\n", __func__, value);
#endif

		if (value == 0) {
			alc_mode = POWERSAVE_MODE;
		}
		else if(value==1) 
		{
			alc_mode = OPTIMIZE_MODE;
		}
		else if(value==2) 
		{
			alc_mode = ALC_MANUAL_MODE;
		}
		else
		{
			printk("==lcd_backlight_store_powersave==value is not valid \n");
			return -EINVAL;
		}	

		return count;
	}


static int lm3537_bl_resume(struct i2c_client *client);
static int lm3537_bl_suspend(struct i2c_client *client, pm_message_t state);

static int lm3537_bl_resume(struct i2c_client *client)
{
	mdelay(50); // td isuue fix - emergency call lock- unlock
		lm3537_backlight_on(cur_main_lcd_level);    
	return 0;
}

static int lm3537_bl_suspend(struct i2c_client *client, pm_message_t state)
{
    printk(KERN_INFO"%s: new state: %d\n",__func__, state.event);
	if(lge_bd_rev ==LGE_REV_C){
		printk(KERN_INFO"%s: REV.C suspend group A disable\n",__func__);
		lm3537_write_reg(main_lm3537_dev->client, 0x00, 0x00);   //group A disable
	}
	else{
		lm3537_hreset();
	}
	backlight_status = BL_OFF;	
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
	
#if defined(lm3537_DBG)
	printk("%s received (prev backlight_status: %s)\n", __func__, backlight_status?"ON":"OFF");
#endif
	on_off = simple_strtoul(buf, NULL, 10);
	
	printk(KERN_ERR "%d",on_off);
	
	if(on_off == 1){
		lm3537_bl_resume(client);
	}else if(on_off == 0)
	    lm3537_bl_suspend(client, PMSG_SUSPEND);
	
	return count;

}
DEVICE_ATTR(lm3537_level, 0664, lcd_backlight_show_level, lcd_backlight_store_level);
DEVICE_ATTR(lm3537_powersave, 0666, lcd_backlight_show_powersave, lcd_backlight_store_powersave);
DEVICE_ATTR(lm3537_backlight_on_off, 0666, lcd_backlight_show_on_off, lcd_backlight_store_on_off);

static struct backlight_ops lm3537_bl_ops = {
	.update_status = bl_set_intensity,
	.get_brightness = bl_get_intensity,
};

//static int __init lm3537_probe(struct i2c_client *i2c_dev, const struct i2c_device_id *id)
static int lm3537_probe(struct i2c_client *i2c_dev, const struct i2c_device_id *id)
{
	struct lm3537_device *dev;
	struct backlight_device *bl_dev;
	struct backlight_properties props;
	int err;

	printk(KERN_INFO"%s: i2c probe start\n", __func__);

	lm3537_i2c_client = i2c_dev;

	dev = kzalloc(sizeof(struct lm3537_device), GFP_KERNEL);
	if(dev == NULL) {
		dev_err(&i2c_dev->dev,"fail alloc for lm3537_device\n");
		return 0;
	}

	main_lm3537_dev = dev;

	memset(&props, 0, sizeof(struct backlight_properties));
	props.max_brightness = MAX_BRIGHTNESS;
	
	bl_dev = backlight_device_register(I2C_BL_NAME, &i2c_dev->dev, NULL, &lm3537_bl_ops, &props);
	bl_dev->props.max_brightness = MAX_BRIGHTNESS;
	bl_dev->props.brightness = DEFAULT_BRIGHTNESS;
	bl_dev->props.power = FB_BLANK_UNBLANK;
	
	dev->bl_dev = bl_dev;
	dev->client = i2c_dev;
	i2c_set_clientdata(i2c_dev, dev);
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT)

	lm3537_initialization_ldo();

	lm3537_backlight_on(DEFAULT_BRIGHTNESS);
#endif
	err = device_create_file(&i2c_dev->dev, &dev_attr_lm3537_level);
	err = device_create_file(&i2c_dev->dev, &dev_attr_lm3537_powersave);
	err = device_create_file(&i2c_dev->dev, &dev_attr_lm3537_backlight_on_off);

	return 0;
}

static int lm3537_remove(struct i2c_client *i2c_dev)
{
	struct lm3537_device *dev;

    unregister_early_suspend(&dev->early_suspend);
	gpio_free(LCD_DCDC_EN);
 	device_remove_file(&i2c_dev->dev, &dev_attr_lm3537_level);
	device_remove_file(&i2c_dev->dev, &dev_attr_lm3537_powersave);
 	device_remove_file(&i2c_dev->dev, &dev_attr_lm3537_backlight_on_off);
	dev = (struct lm3537_device *)i2c_get_clientdata(i2c_dev);
	backlight_device_unregister(dev->bl_dev);
	i2c_set_clientdata(i2c_dev, NULL);

	return 0;
}	

static int lm3537_suspend(struct i2c_client *client, pm_message_t state)
{
	return 0;
}

static int lm3537_resume(struct i2c_client *client)
{
	return 0;
}

static void lm3537_shutdown(struct i2c_client *client)
{
	printk("lm3537_shutdown\n");
	lm3537_backlight_off();
	lm3537_sw_reset();
	lm3537_power_off=1;
}

static struct i2c_driver main_lm3537_driver = {
	.probe = lm3537_probe,
	.remove = lm3537_remove,
	.suspend = lm3537_suspend,
	.shutdown = lm3537_shutdown,
	.resume = lm3537_resume,
	.id_table = lm3537_bl_id, 
	.driver = {
		.name = I2C_BL_NAME,
		.owner = THIS_MODULE,
	},
};


static int __init lcd_backlight_init(void)
{
	static int err=0;

	err = i2c_add_driver(&main_lm3537_driver);

	return err;
}
 
module_init(lcd_backlight_init);

MODULE_DESCRIPTION("LM3537 Backlight Control");
MODULE_AUTHOR("Jaeseong Gim <jaeseong.gim@lge.com>");
MODULE_LICENSE("GPL");
