/* lge/com_device/mhl/sii9244.c 
*
* SiI9244 Mobile High-definition Link(MHL) Transmitter 
*  
* Copyright (C) 2011-2012 LGE Inc.  
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

#include <linux/interrupt.h>
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/irq.h>
#include <linux/miscdevice.h>
#include <asm/gpio.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/workqueue.h>
#include <linux/freezer.h>
#include <linux/delay.h>
#include <linux/syscalls.h> 
#include <linux/fcntl.h> 
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/device.h>
#include <mach/board_lge.h>
#include "Common_Def.h"
#include "sii9244_driver.h"
#include <linux/interrupt.h>
#include <linux/msm_adc.h>

#define SUBJECT "MHL_DRIVER"
#define SII_DEV_DBG(format,...)\
	printk ("[ "SUBJECT " (%s,%d) ] " format "\n", __func__, __LINE__, ## __VA_ARGS__);

#define byte u8

extern void hdmi_common_send_uevent(char *buf);
extern void hdmi_common_set_hpd(int on);

#define MHL_PWRON_DELAY_MS   0//50 //5000
#define MHL_WORKREQ_PWROFF  (1 << 0)
#define MHL_WORKREQ_PWRON   (1 << 1)
#define MHL_WORKREQ_IRQ     (1 << 2)
static int mhl_workreq = 0;

bool old_adc_mhl_detected = false;
int  adc_detect_safe_count = 0;

struct mhl_client {
  struct i2c_driver *driver;
  struct i2c_client *client;
  int probed;
};

struct mhl_rcp_dev{
	char *name;
	struct device *dev;
	unsigned char code;
};

struct mhl_data_info {
  struct mutex lock;
  struct mhl_platform_data *pdata;
  struct mhl_client i2c[4];
  struct regulator *ldo3v3;
  struct regulator *ldo1v8;
  struct regulator *ldo1v2;
  struct delayed_work dwork;
  struct workqueue_struct *wq;

  int initialized;
  int power;
  int irq_pin;
  int hpd_power_enable;    // MSM

  bool on;
  int workfunc_run;
  int is_suspend;
};

static struct mhl_data_info mhl_data;

#ifdef CONFIG_LGE_PM
#define MSM_CHARGER_GAUGE_MISSING_TEMP_ADC 1000
#define MSM_CHARGER_GAUGE_MISSING_TEMP       35
#define MSM_PMIC_ADC_READ_TIMEOUT          3000
#define CHANNEL_ADC_ACC_MISSING            2200
extern int32_t pm8058_xoadc_clear_recentQ(void);
#endif
static int read_adc_acc(int channel, int *mv_reading)
{
	int ret;
	void *h;
	struct adc_chan_result adc_chan_result;
	struct completion  conv_complete_evt;
#ifdef CONFIG_LGE_PM
    int wait_ret;
#endif

	pr_debug("%s: called for %d\n", __func__, channel);
	ret = adc_channel_open(channel, &h);
	if (ret) {
		pr_err("%s: couldnt open channel %d ret=%d\n",
					__func__, channel, ret);
		goto out;
	}
	init_completion(&conv_complete_evt);
	ret = adc_channel_request_conv(h, &conv_complete_evt);
	if (ret) {
		pr_err("%s: couldnt request conv channel %d ret=%d\n",
						__func__, channel, ret);
		goto out;
	}
#ifdef CONFIG_LGE_PM
    wait_ret = wait_for_completion_timeout(&conv_complete_evt, msecs_to_jiffies(MSM_PMIC_ADC_READ_TIMEOUT));
    if(wait_ret <= 0)
    {
		printk(KERN_ERR "===%s: failed to adc wait for completion!===\n",__func__);
        goto sanity_out;
    }
#else
	wait_for_completion(&conv_complete_evt);
#endif

	ret = adc_channel_read_result(h, &adc_chan_result);
	if (ret) {
		pr_err("%s: couldnt read result channel %d ret=%d\n",
						__func__, channel, ret);
		goto out;
	}
	ret = adc_channel_close(h);
	if (ret) {
		pr_err("%s: couldnt close channel %d ret=%d\n",
						__func__, channel, ret);
	}
	if (mv_reading)
		*mv_reading = adc_chan_result.measurement;

	pr_debug("%s: done for %d\n", __func__, channel);
	return adc_chan_result.physical;
out:
#ifdef CONFIG_LGE_PM
    if(ret == -EBUSY)
        adc_channel_close(h);
#endif    
	pr_debug("%s: done for %d\n", __func__, channel);
	return -EINVAL;

#ifdef CONFIG_LGE_PM
sanity_out:

    pm8058_xoadc_clear_recentQ();

	ret = adc_channel_close(h);
	if (ret) {
		pr_err("%s: couldnt close channel %d ret=%d\n",
						__func__, channel, ret);
	}
    
    if(channel == CHANNEL_ADC_BATT_THERM)
    {
        printk(KERN_ERR "============== batt temp adc read fail so default temp ===============\n");
	    if (mv_reading)
		    *mv_reading = MSM_CHARGER_GAUGE_MISSING_TEMP_ADC;
        return MSM_CHARGER_GAUGE_MISSING_TEMP;
    }
    else if(channel == CHANNEL_ADC_ACC)
    {
        printk(KERN_ERR "============== ACC adc read fail so default usb ===============\n");
        return CHANNEL_ADC_ACC_MISSING;
    }
    else
    {
        printk(KERN_ERR "============== adc read fail  ===============\n");
	    return -EINVAL;
    }
#endif

}

void sii9244_cfg_power(bool on)
{
  if(mhl_data.initialized == 0)
  {
    pr_err("%s: mhl_data.initialized = %d\n",__func__,mhl_data.initialized);
    return;
  }

  if(mhl_data.power == on)
  {
    pr_info("%s : alread %s\n",__func__,(mhl_data.power ? "on" : "off"));
    return;
  }

  mhl_data.power = on ? 1 : 0;
  mhl_data.pdata->power(on);

  pr_info("%s : amhl_data.power=%d\n",__func__,mhl_data.power);

  return;
  
}


void MHL_On(bool on)
{
   pr_err("MHL_On(%d)\n", on);

  if(mhl_data.initialized == 0)
  {
    pr_err("%s: mhl_data.initialized = %d\n",__func__,mhl_data.initialized);
    return;
  }

 // mutex_lock(&mhl_data.lock);

  if(mhl_data.on != on)
  {
    mhl_data.on = on;
    
    if(on == 1) 
    {
      gpio_set_value(mhl_data.pdata->reset_pin,0);
      gpio_set_value(mhl_data.pdata->select_pin,1);
      sii9244_cfg_power(1);
      msleep(50);
      gpio_set_value(mhl_data.pdata->reset_pin,1);
      msleep(30);
      SiI9244_init();
      enable_irq(mhl_data.irq_pin);	
    } 
    else 
    {
      disable_irq(mhl_data.irq_pin);
      sii9244_cfg_power(0); 
      gpio_set_value(mhl_data.pdata->select_pin,0); 
      gpio_set_value(mhl_data.pdata->reset_pin,0); 
    }
  }
  else
  {
    pr_info("%s : alread %s\n",__func__,(mhl_data.on ? "on" : "off"));
  }
  //mutex_unlock(&mhl_data.lock);
  
}

void mhl_pwroff_request(void)
{
  if(!mhl_data.initialized)
  {
    pr_err("%s: return [mhl_data.initialized = %d]\n",__func__,mhl_data.initialized);
    return;
  }

  if(mhl_workreq & MHL_WORKREQ_PWROFF)
  {
    pr_err("%s: return [mhl_workreq & MHL_WORKREQ_PWROFF]\n",__func__);
    return;
  }
  
  mutex_lock(&mhl_data.lock);
  mhl_workreq |= MHL_WORKREQ_PWROFF;
  mutex_unlock(&mhl_data.lock);
  queue_delayed_work(mhl_data.wq,&mhl_data.dwork,0);

  pr_info("%s\n",__func__);
}

EXPORT_SYMBOL(mhl_pwroff_request);

void mhl_delayed_pwron_request(unsigned int delay_ms)
{
  if(!mhl_data.initialized)
  {
    pr_err("%s: return [mhl_data.initialized = %d]\n",__func__,mhl_data.initialized);
    return;
  }

  if(mhl_workreq & MHL_WORKREQ_PWRON)
  {
    pr_err("%s: return [mhl_workreq & MHL_WORKREQ_PWRON]\n",__func__);
    return;
  }

  if(mhl_data.power)
  {
    pr_err("%s: return [mhl_data.power = %d]\n",__func__,mhl_data.power);
    return;
  }
 
  mutex_lock(&mhl_data.lock);
  mhl_workreq |= MHL_WORKREQ_PWRON;
  mutex_unlock(&mhl_data.lock);
  queue_delayed_work(mhl_data.wq,&mhl_data.dwork,msecs_to_jiffies(delay_ms));
  
}
EXPORT_SYMBOL(mhl_delayed_pwron_request);

void mhl_pwron_request(void)
{
  if(mhl_data.initialized)
  {
    mhl_delayed_pwron_request(MHL_PWRON_DELAY_MS);
  }
}

EXPORT_SYMBOL(mhl_pwron_request);

void mhl_pwroff_request_vbus_removed(void)
{
  pr_info("%s:\n",__func__);
  mhl_pwroff_request();
}

EXPORT_SYMBOL(mhl_pwroff_request_vbus_removed);


int mhl_power_on(void)
{
	return mhl_data.hpd_power_enable;
}

EXPORT_SYMBOL(mhl_power_on);

struct i2c_client* get_sii9244_client(u8 device_id)
{
  int i;

  if(mhl_data.initialized == 0)
  {
    pr_err("%s: mhl_data.initialized = %d\n",__func__,mhl_data.initialized);
    return NULL;
  }

  for(i = 0; i < 4; ++i)
  {
    if((device_id >> 1) == (u8) mhl_data.i2c[i].client->addr)
      return mhl_data.i2c[i].client;
  }

  return NULL;
}
EXPORT_SYMBOL(get_sii9244_client);

u8 sii9244_i2c_read(struct i2c_client *client, u8 reg)
{
  int ret;

  if(mhl_data.initialized == 0)
  {
    pr_err("%s: mhl_data.initialized = %d\n",__func__,mhl_data.initialized);
    return -1;
  }
  if(mhl_data.power == 0)
  {
    pr_err("%s: mhl_data.power = %d\n",__func__,mhl_data.power);
    return -1;
  }

  ret = i2c_smbus_write_byte(client, reg);
  ret = i2c_smbus_read_byte(client);
 
  if (ret < 0)
  {
    SII_DEV_DBG("i2c read fail\n");
    return -EIO;
  }
  return ret;
}


int sii9244_i2c_write(struct i2c_client *client, u8 reg, u8 data)
{
  if(mhl_data.initialized == 0)
  {
    pr_err("%s: mhl_data.initialized = %d\n",__func__,mhl_data.initialized);
    return -1;
  }
  if(mhl_data.power == 0)
  {
    pr_err("%s: mhl_data.power = %d\n",__func__,mhl_data.power);
    return -1;
  }
  
  return i2c_smbus_write_byte_data(client, reg, data);

}

void sii9244_workfunc_pwroff(struct work_struct *p)
{
  pr_info("%s\n",__func__);
  MHL_On(0);
   
  mutex_lock(&mhl_data.lock);	
  hdmi_common_set_hpd(0);	
  mhl_data.hpd_power_enable = 0;	
  mutex_unlock(&mhl_data.lock);  
  mhl_delayed_pwron_request(100);  
}
void sii9244_workfunc_pwron(struct work_struct *p)
{
  int   acc_adc;
  int   retry;


  for(retry = 0; retry < 1; retry++)
  {
    if(retry)
    {
      //pr_info("%s: retry = %d\n",__func__,retry);
      mdelay(50);
    }
    acc_adc = read_adc_acc(CHANNEL_ADC_ACC, NULL);
    //pr_info("%s: acc_adc = %d\n",__func__,acc_adc);

    if((acc_adc >= -100 && acc_adc <= 100) && (acc_adc != -EINVAL))
    {
      pr_info("%s: MHL Cable Detected : MHL_PWRON_DELAY_MS[%d]... retry[%d]\n",__func__,MHL_PWRON_DELAY_MS,retry);

      mutex_lock(&mhl_data.lock); 
      mhl_data.hpd_power_enable = 1;  
      hdmi_common_set_hpd(1);
      mutex_unlock(&mhl_data.lock);

      sii9244_clear_rsen_incorrect();
      MHL_On(1);	   
    }
    else if(acc_adc > 1900) // open
    {
      if(check_usb_online() && sii9244_get_last_rsen_incorrect())
      {
        pr_info("%s: in rsen incorrect state ###########\n",__func__);
        mhl_delayed_pwron_request(100);
      }
      else
        sii9244_clear_rsen_incorrect();

  	}
    else
        sii9244_clear_rsen_incorrect();
  }
}

void sii9244_workfunc_main(struct work_struct *p)
{
  int temp_workreq;

  mhl_data.workfunc_run = 1;

  pr_info("%s called : mhl_workreq = %X\n",__func__,mhl_workreq);

  mutex_lock(&mhl_data.lock);
  temp_workreq = mhl_workreq;
  mhl_workreq = 0;
  mutex_unlock(&mhl_data.lock);

  if(temp_workreq & MHL_WORKREQ_PWROFF)
  {
#if 0
    mutex_lock(&mhl_data.lock);
    temp_workreq &= ~(MHL_WORKREQ_PWROFF|MHL_WORKREQ_IRQ);
    mutex_unlock(&mhl_data.lock);
#else
    temp_workreq &= ~(MHL_WORKREQ_IRQ);
#endif
    sii9244_workfunc_pwroff(p); 
  }
 
  if(temp_workreq & MHL_WORKREQ_IRQ)
  {
#if 0
    mutex_lock(&mhl_data.lock);
    temp_workreq &= ~MHL_WORKREQ_IRQ;
    mutex_unlock(&mhl_data.lock);
#endif
    if(mhl_data.power)
    {
      SiI9244_interrupt_event();
    }
  }
 
  if(temp_workreq & MHL_WORKREQ_PWRON)
  {
#if 0
    mutex_lock(&mhl_data.lock);
    temp_workreq &= ~MHL_WORKREQ_PWRON;
    mutex_unlock(&mhl_data.lock);
#endif
    sii9244_workfunc_pwron(p);
  }
}
void sii9244_Pwrctrl_work(struct work_struct *p)
{
  printk("SiI9244_Pwrctrl_work() is called\n");
  SiI9244_interrupt_event();
}

void mhl_int_irq_handler_sched(void)
{
  mutex_lock(&mhl_data.lock);
  mhl_workreq |= MHL_WORKREQ_IRQ;
  mutex_unlock(&mhl_data.lock);
  queue_delayed_work(mhl_data.wq,&mhl_data.dwork,0);
}

irqreturn_t mhl_int_irq_handler(int irq, void *dev_id)
{
  mhl_int_irq_handler_sched();
  return IRQ_HANDLED;
}

void rcp_cbus_uevent(u8 rcpCode)	
{
	char env_buf[120];
	u8 code= 0x0;


	memset(env_buf, 0, sizeof(env_buf));
	printk("%s : RCP Message Recvd , rcpCode =0x%x\n",__func__,rcpCode);

	switch(rcpCode)
	{
	case 0x60: // Play Function
		code = 0x44;
		break;
	case 0x61: //Pause_Play Func
		code =  0x46;
		break;
	case 0x64://Stop Function
		code = 0x45;
		break;
	default:
		code = rcpCode;
		break;
	}
		
	sprintf(env_buf, "MHL_RCP=%d", code);	

       hdmi_common_send_uevent(env_buf);
	return;
}
EXPORT_SYMBOL(rcp_cbus_uevent);


static int sii9244_probed(void)
{
  int ret = 0;
	
    mutex_init(&mhl_data.lock);
	
   gpio_set_value(mhl_data.pdata->reset_pin,0); 
   gpio_set_value(mhl_data.pdata->select_pin,0);

    mhl_data.wq = create_singlethread_workqueue("mhl_sii9244_wq");
    INIT_DELAYED_WORK(&mhl_data.dwork,sii9244_workfunc_main);
    mhl_data.irq_pin = gpio_to_irq(mhl_data.pdata->interrupt_pin);
    ret = request_threaded_irq(mhl_data.irq_pin, 
                               NULL, 
                               mhl_int_irq_handler, 
                               IRQF_TRIGGER_FALLING |IRQF_ONESHOT, 
                               "mhl_int",NULL);
    if (ret < 0) 
    {
      pr_err("%s: unable to request irq mhl_int err:: %d\n", __func__,ret);
      return ret;
    }
	
    disable_irq(mhl_data.irq_pin);

   mhl_data.pdata->power_config();
   sii9244_cfg_power(0);
  
  	mhl_data.initialized = 1;
  	mhl_data.hpd_power_enable = 0;

   return ret;
   
}

static int __devinit sii9244_p0_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
    mhl_data.i2c[0].client = client;
    i2c_set_clientdata(client, &mhl_data);

    mhl_data.i2c[0].probed = 1;

    return 0;
}
static int __devinit sii9244_p1_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
   	mhl_data.i2c[1].client = client;
	i2c_set_clientdata(client, &mhl_data);

   	mhl_data.i2c[1].probed = 1;

   	return 0;
}
static int __devinit sii9244_p2_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	mhl_data.i2c[2].client = client;
   	i2c_set_clientdata(client, &mhl_data);

  	mhl_data.i2c[2].probed = 1;

  	return 0;
}

static int __devinit sii9244_p3_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
  	mhl_data.i2c[3].client = client;
  	i2c_set_clientdata(client, &mhl_data);

	mhl_data.i2c[3].probed = 1;

       return 0;
}

static struct i2c_device_id sii9244_p0_id[] = {
  {"sii9244_i2c_page0", 0},
  {}
};

struct i2c_driver sii9244_p0_i2c_driver = {
  .driver = {
    .owner = THIS_MODULE,
    .name = "sii9244_i2c_page0",
  },
  .id_table = sii9244_p0_id,
  .probe    = sii9244_p0_i2c_probe,
};

static struct i2c_device_id sii9244_p1_id[] = {
  {"sii9244_i2c_page1", 0},
  {}
};

struct i2c_driver sii9244_p1_i2c_driver = {
  .driver = {
    .owner = THIS_MODULE,
    .name = "sii9244_i2c_page1",
  },
  .id_table = sii9244_p1_id,
  .probe    = sii9244_p1_i2c_probe,
};

static struct i2c_device_id sii9244_p2_id[] = {
  {"sii9244_i2c_page2", 0},
  {}
};

struct i2c_driver sii9244_p2_i2c_driver = {
  .driver = {
    .owner = THIS_MODULE,
    .name = "sii9244_i2c_page2",
  },
  .id_table = sii9244_p2_id,
  .probe    = sii9244_p2_i2c_probe,
};

static struct i2c_device_id sii9244_p3_id[] = {
  {"sii9244_i2c_page3", 0},
  {}
};

struct i2c_driver sii9244_p3_i2c_driver = {
  .driver = {
    .owner = THIS_MODULE,
    .name = "sii9244_i2c_page3",
  },
  .id_table = sii9244_p3_id,
  .probe    = sii9244_p3_i2c_probe,
};

static int __devinit sii9244_probe(struct platform_device *pdev)
{	
	int i;
	int ret = 0;
       struct i2c_driver *pi2cdrv;

	mhl_data.pdata = pdev->dev.platform_data;

	if(mhl_data.pdata->is_support == 0)
		return 0;

	mhl_data.i2c[0].driver = &sii9244_p0_i2c_driver;
	mhl_data.i2c[1].driver = &sii9244_p1_i2c_driver;
	mhl_data.i2c[2].driver = &sii9244_p2_i2c_driver;
	mhl_data.i2c[3].driver = &sii9244_p3_i2c_driver;
	
	for(i = 0; i < 4; ++i){
		pi2cdrv = mhl_data.i2c[i].driver;
		ret = i2c_add_driver(pi2cdrv);
	
		if (ret != 0)
		{
		  pr_err("%s: can't add i2c driver : %s\n",__func__,pi2cdrv->driver.name);
		  goto sii9244_init_end;
		}
		else
		{
		   pr_info("%s: add i2c driver : %s\n",__func__,pi2cdrv->driver.name);
		}
	 }
  
   	sii9244_probed();
	
sii9244_init_end:
	  return ret;
}

static int __devexit sii9244_remove(struct platform_device *pdev)
{
	int i;

	if(mhl_data.pdata->is_support == 0)
		return 0;
	
	for(i = 0; i < 4; ++i)
	{
		if(mhl_data.i2c[i].driver != NULL)
		{
			i2c_del_driver(mhl_data.i2c[i].driver);
		}
	}
	  
	return 0;
}

#ifdef CONFIG_PM
static int sii9244_suspend(struct platform_device *pdev,
		pm_message_t state)
{
	if(mhl_data.pdata->is_support == 0)
		return 0;

	if(mhl_data.power == 0)
	{
    		cancel_delayed_work_sync(&mhl_data.dwork);
	}
  
	mhl_data.is_suspend	= 1;
	return 0;
}

static int sii9244_resume(struct platform_device *pdev)
{
	if(mhl_data.pdata->is_support == 0)
		return 0;

	mhl_data.is_suspend	= 0;

	return 0;
}
#else
#define sii9244_suspend NULL
#define sii9244_resume NULL
#endif

static struct platform_driver sii9244_driver = {
	.probe = sii9244_probe,
	.remove = __devexit_p(sii9244_remove),
	.suspend = sii9244_suspend,
	.resume = sii9244_resume,
	.driver = {
		.name = "sii9244_driver",
		.owner = THIS_MODULE,
	}
};

static int __init sii9244_init(void)
{
	return platform_driver_register(&sii9244_driver);
}

late_initcall(sii9244_init);
static void __exit sii9244_exit(void)
{
	platform_driver_unregister(&sii9244_driver);
}

module_exit(sii9244_exit);

MODULE_DESCRIPTION("Sii9244 MHL driver");
MODULE_LICENSE("GPL");

