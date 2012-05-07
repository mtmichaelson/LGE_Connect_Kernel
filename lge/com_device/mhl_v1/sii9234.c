/********************************************************************************
* (C) COPYRIGHT 2010 SAMSUNG ELECTRONICS				*
* Silicon Image MHL(Mobile HD Link) Transmitter device driver		*
*									*
* File Name : sii9234.c							*
*									*
* Author    : Aakash Manik 						*
* 			aakash.manik@samsung.com			*
*						 			*
*									*
* Version   : V1							*
* Date      : 11/NOV/2010						*
*				Draft under Review			*
*									*
*									*
* Description: Source file for MHL SiI9234 Transciever 			* 
*									*
* Version info								*
* v0.9 : SGH-I997 Project Primitive MHL Driver				*
*		-  Author Kyungrok Min					*
*				<gyoungrok.min@samsung.com>		*
* Version info								*
* v1.0 : 11/Nov/2010 - Driver Restructuring and  			*
* 			Integration for Dempsey Project			*
*									*
********************************************************************************/
/*===========================================================================

                      EDIT HISTORY FOR FILE

when              who                         what, where, why
--------        ---                        ----------------------------------------------------------
2011/04/06    Rajkumar c m            Added support for qualcomm msm8060
===========================================================================*/

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
#include <asm/uaccess.h> 
#include <linux/types.h>
#include <linux/miscdevice.h>

#include <linux/syscalls.h> 
#include <linux/fcntl.h> 
#include <asm/uaccess.h> 


#include "Common_Def.h"
#include "sii9234_driver.h"
#include <linux/interrupt.h>

//#define TIMER_ACC_ADC

#ifdef TIMER_ACC_ADC 
#include <linux/msm_adc.h>
#include <linux/hrtimer.h>
#endif

#define SUBJECT "MHL_DRIVER"


#define SII_DEV_DBG(format,...)\
	printk ("[ "SUBJECT " (%s,%d) ] " format "\n", __func__, __LINE__, ## __VA_ARGS__);

#define byte u8

/* 
	- Required by fsa9480 for calling sii9234 initialization
*/
static int SII9234_i2cprobe_status = 0;
static int SII9234A_i2cprobe_status = 0;
static int SII9234B_i2cprobe_status = 0;
static int SII9234C_i2cprobe_status = 0;
int SII9234_i2c_status = 0;

#ifdef TIMER_ACC_ADC 
static struct hrtimer sii9234_adc_timer;
static struct workqueue_struct *sii9234_adc_wq;
static struct work_struct sii9234_adc_work;
#endif

static struct regulator *l25; 		//VSIL_1.2A & VSIL_1.2C Connected to PM8058
static struct regulator *l2;		//VCC_3.3V_MHL Connected to PM8901
static struct regulator *mvs0;	//VCC_1.8V_MHL Connected to PM8901
EXPORT_SYMBOL(SII9234_i2c_status);

struct work_struct SiI9234_int_work;
struct workqueue_struct *sii9234_wq = NULL;


struct i2c_driver SII9234_i2c_driver;
struct i2c_client *SII9234_i2c_client = NULL;

struct i2c_driver SII9234A_i2c_driver;
struct i2c_client *SII9234A_i2c_client = NULL;

struct i2c_driver SII9234B_i2c_driver;
struct i2c_client *SII9234B_i2c_client = NULL;

struct i2c_driver SII9234C_i2c_driver;
struct i2c_client *SII9234C_i2c_client = NULL;

static struct i2c_device_id SII9234_id[] = {
	{"SII9234", 0},
	{}
};

static struct i2c_device_id SII9234A_id[] = {
	{"SII9234A", 0},
	{}
};

static struct i2c_device_id SII9234B_id[] = {
	{"SII9234B", 0},
	{}
};

static struct i2c_device_id SII9234C_id[] = {
	{"SII9234C", 0},
	{}
};

int MHL_i2c_init = 0;


struct SII9234_state {
	struct i2c_client *client;
};

#define MHL_SWITCH_TEST	1

#ifdef MHL_SWITCH_TEST
void sii9234_cfg_power(bool on);
//static void sii9234_cfg_gpio(void);
extern bool SiI9234_startTPI(void);
static int __init sii9234_init(void);
struct class *sec_mhl;
EXPORT_SYMBOL(sec_mhl);

struct device *mhl_switch;
EXPORT_SYMBOL(mhl_switch);

bool old_adc_mhl_detected = false;
int  adc_detect_safe_count = 0;

static ssize_t check_MHL_command(struct device *dev, struct device_attribute *attr, char *buf)
{
	int count;
	int res;

	printk(KERN_ERR "[MHL]: check_MHL_command\n");
	sii9234_cfg_power(1);
	res = SiI9234_startTPI();
	count = sprintf(buf,"%d\n", res );
	sii9234_cfg_power(0);
	return count;

}

static ssize_t change_switch_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	char *after;
	unsigned long value = simple_strtoul(buf, &after, 10);
	int i;
	printk(KERN_ERR "[MHL_SWITCH] Change the switch: %ld\n", value);

	if (value == 0) {
		for (i = 0; i <1; i++) {
			printk(KERN_ERR "[MHL] try %d\n", i+1);
			msleep(500);
		}

		gpio_set_value(GPIO_MHL_SEL, 1); 
		sii9234_cfg_power(1);
		SiI9234_init();
	} else {
		sii9234_cfg_power(0);
		gpio_set_value(GPIO_MHL_SEL, 0); 
	}
	return size;
}
		
void MHL_On(bool on)
{
	printk("MHL_On(%d)\n", on);
	if (on == 1) {
	  gpio_set_value(GPIO_MHL_SEL, 1);
		sii9234_cfg_power(1);
		SiI9234_init();
	} else {
	  gpio_set_value(GPIO_MHL_RST, 0); 
		sii9234_cfg_power(0);
		gpio_set_value(GPIO_MHL_SEL, 0); 
#ifdef TIMER_ACC_ADC 
		old_adc_mhl_detected = false;
  	hrtimer_start(&sii9234_adc_timer,
		ns_to_ktime(250000000/*500ms*/), HRTIMER_MODE_REL);
#endif
	}

}
EXPORT_SYMBOL(MHL_On);


//static DEVICE_ATTR(mhl_sel, S_IRUGO | S_IWUSR | S_IXOTH, check_MHL_command, change_switch_store);
static DEVICE_ATTR(mhl_sel, 0666, check_MHL_command, change_switch_store);
#endif


static ssize_t MHD_check_read(struct device *dev, struct device_attribute *attr, char *buf)
{
	int count;
	int res=0;
	#if 0

	s3c_gpio_setpull(GPIO_MHL_SEL, S3C_GPIO_PULL_UP);	//MHL_SEL

	s3c_gpio_setpin(GPIO_MHL_SEL, 1);
	

	//TVout_LDO_ctrl(true);
	
	if(!MHD_HW_IsOn())
	{
		sii9234_tpi_init();
		res = MHD_Read_deviceID();
		MHD_HW_Off();		
	}
	else
	{
		sii9234_tpi_init();
		res = MHD_Read_deviceID();
	}

	I2C_WriteByte(0x72, 0xA5, 0xE1);
	res = 0;
	res = I2C_ReadByte(0x72, 0xA5);

	printk("A5 res %x",res);

	res = 0;
	res = I2C_ReadByte(0x72, 0x1B);

	printk("Device ID res %x",res);

	res = 0;
	res = I2C_ReadByte(0x72, 0x1C);

	printk("Device Rev ID res %x",res);

	res = 0;
	res = I2C_ReadByte(0x72, 0x1D);

	printk("Device Reserved ID res %x",res);

	printk("\n####HDMI_EN1 %x MHL_RST %x GPIO_MHL_SEL %x\n",gpio_get_value(GPIO_HDMI_EN1),gpio_get_value(GPIO_MHL_RST),gpio_get_value(GPIO_MHL_SEL));

	res = I2C_ReadByte(0x7A, 0x3D);

	res = I2C_ReadByte(0x7A, 0xFF);
		
	s3c_gpio_setpull(GPIO_MHL_SEL, S3C_GPIO_PULL_NONE);	//MHL_SEL

	s3c_gpio_setpin(GPIO_MHL_SEL, 0);

#endif
	count = sprintf(buf,"%d\n", res );
	//TVout_LDO_ctrl(false);
	return count;
}

static ssize_t MHD_check_write(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	printk("input data --> %s\n", buf);

	return size;
}

static DEVICE_ATTR(MHD_file, S_IRUGO | S_IWUSR | S_IWOTH | S_IXOTH, MHD_check_read, MHD_check_write);


struct i2c_client* get_sii9234_client(u8 device_id)
{

	struct i2c_client* client_ptr;

	if(device_id == 0x72)
		client_ptr = SII9234_i2c_client;
	else if(device_id == 0x7A)
		client_ptr = SII9234A_i2c_client;
	else if(device_id == 0x92)
		client_ptr = SII9234B_i2c_client;
	else if(device_id == 0xC8)
		client_ptr = SII9234C_i2c_client;
	else
		client_ptr = NULL;

	return client_ptr;
}
EXPORT_SYMBOL(get_sii9234_client);

u8 SII9234_i2c_read(struct i2c_client *client, u8 reg)
{
	int ret;
	
	if(!MHL_i2c_init)
	{
		SII_DEV_DBG("I2C not ready\n");
		return 0;
	}


	ret = i2c_smbus_write_byte(client, reg);
	ret = i2c_smbus_read_byte(client);
	//printk("#######Read reg %x data %x\n", reg, ret);
	if (ret < 0)
	{
		SII_DEV_DBG("i2c read fail\n");
		return -EIO;
	}
	return ret;

}
EXPORT_SYMBOL(SII9234_i2c_read);


int SII9234_i2c_write(struct i2c_client *client, u8 reg, u8 data)
{
	if(!MHL_i2c_init)
	{
		SII_DEV_DBG("I2C not ready\n");
		return 0;
	}

	//printk("#######Write reg %x data %x\n", reg, data);
	return i2c_smbus_write_byte_data(client, reg, data);

}
EXPORT_SYMBOL(SII9234_i2c_write);


void SiI9234_interrupt_event_work(struct work_struct *p)
{

	printk("SiI9234_interrupt_event_work() is called\n");

	SiI9234_interrupt_event();
}


void mhl_int_irq_handler_sched(void)
{

	printk("mhl_int_irq_handler_sched() is called\n");
	queue_work(sii9234_wq,&SiI9234_int_work);		
}


irqreturn_t mhl_int_irq_handler(int irq, void *dev_id)
{

	printk("mhl_int_irq_handler() is called\n");
	mhl_int_irq_handler_sched();
	return IRQ_HANDLED;
}

irqreturn_t mhl_wakeup_int_irq_handler(int irq, void *dev_id)
{
	printk("mhl_int_irq_wakeup_handler() is called\n");
	mhl_int_irq_handler_sched();
	//SiI9234_interrupt_event();
	return IRQ_HANDLED;
}

irqreturn_t mhl_hpd_irq_handler(int irq, void *dev_id)
{
	printk("mhl_wake_up_irq_handler() is called\n");
	return IRQ_HANDLED;
}

 
irqreturn_t mhl_wake_up_irq_handler(int irq, void *dev_id)
{

	printk("mhl_wake_up_irq_handler() is called\n");

	mhl_int_irq_handler_sched();
	
	return IRQ_HANDLED;
}

#ifdef TIMER_ACC_ADC
#ifdef CONFIG_LGE_PM
#define MSM_CHARGER_GAUGE_MISSING_TEMP_ADC 1000
#define MSM_CHARGER_GAUGE_MISSING_TEMP       35
#define MSM_PMIC_ADC_READ_TIMEOUT          3000
#define CHANNEL_ADC_ACC_MISSING            2200
extern int32_t pm8058_xoadc_clear_recentQ(void);
#endif
static int batt_read_adc(int channel, int *mv_reading)
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


static enum hrtimer_restart sii9234_adctimer_func(struct hrtimer *timer)
{
	queue_work(sii9234_adc_wq, &sii9234_adc_work);
	return HRTIMER_NORESTART;
}


static void sii9234_adc_work_func(struct work_struct *work)
{
  int   acc_adc;
  bool  adc_mhl_detected;
  
	acc_adc = batt_read_adc(CHANNEL_ADC_ACC, NULL);
	pr_info("%s: acc_adc=%d\n", __func__, acc_adc);

	if(acc_adc >= 0 && acc_adc <= 70)
	{
	  adc_mhl_detected = true;
	}
	else
	{
	  adc_mhl_detected = false;
	}

	if(old_adc_mhl_detected != adc_mhl_detected)
	{
	  pr_info("%s: adc_mhl_detected=%d,%d\n", __func__, adc_mhl_detected,adc_detect_safe_count);
	  
    if(++adc_detect_safe_count > 2)
    {
      old_adc_mhl_detected = adc_mhl_detected;
      adc_detect_safe_count = 0;

      if(adc_mhl_detected)
      {
        //MHL_On(true);
      }
      else
      {
        //MHL_On(false);
      }
    }
  }
  else
  {
    adc_detect_safe_count = 0;
  }

  if(!old_adc_mhl_detected)
	hrtimer_start(&sii9234_adc_timer,
		ns_to_ktime(250000000/*500ms*/), HRTIMER_MODE_REL);
}
#endif


static int SII9234_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	//SII_DEV_DBG("");
	//int retval;

	struct SII9234_state *state;

	struct class *mhl_class;
	struct device *mhl_dev;
	int usb_switch;

	state = kzalloc(sizeof(struct SII9234_state), GFP_KERNEL);
	if (state == NULL) {		
		printk("failed to allocate memory \n");
		return -ENOMEM;
	}
	
	state->client = client;
	i2c_set_clientdata(client, state);


	
	/* rest of the initialisation goes here. */
	
	printk("SII9234 attach success!!!\n");

	SII9234_i2c_client = client;

	MHL_i2c_init = 1;

	mhl_class = class_create(THIS_MODULE, "mhl");
	if (IS_ERR(mhl_class))
	{
		pr_err("Failed to create class(mhl)!\n");
	}

	mhl_dev = device_create(mhl_class, NULL, 0, NULL, "mhl_dev");
	if (IS_ERR(mhl_dev))
	{
		pr_err("Failed to create device(mhl_dev)!\n");
	}

	if (device_create_file(mhl_dev, &dev_attr_MHD_file) < 0)
		printk("Failed to create device file(%s)!\n", dev_attr_MHD_file.attr.name);

	SII9234_i2cprobe_status = 1;
	if(( SII9234_i2cprobe_status == 1) && ( SII9234A_i2cprobe_status == 1) 
		&& ( SII9234B_i2cprobe_status == 1) && ( SII9234C_i2cprobe_status == 1))
	{
		SII9234_i2c_status = 1;
		MHL_On(false);
	}

	printk("ksw sii9234_i2c_read(sii9234_i2c_client, 0x02) = %x\n", SII9234_i2c_read(SII9234_i2c_client, 0x02));
	usb_switch = gpio_get_value(GPIO_MHL_SEL);
	printk("ksw mhl_sel_gpio_value = 0x%x\n", usb_switch);
	


	
	return 0;

}



static int __devexit SII9234_remove(struct i2c_client *client)
{
	struct SII9234_state *state = i2c_get_clientdata(client);
	kfree(state);

	return 0;
}

static int SII9234A_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	//SII_DEV_DBG("");

	struct SII9234_state *state;

	state = kzalloc(sizeof(struct SII9234_state), GFP_KERNEL);
	if (state == NULL) {		
		printk("failed to allocate memory \n");
		return -ENOMEM;
	}
	
	state->client = client;
	i2c_set_clientdata(client, state);
	
	/* rest of the initialisation goes here. */
	
	printk("SII9234A attach success!!!\n");

	SII9234A_i2c_client = client;

	SII9234A_i2cprobe_status = 1;
	if(( SII9234_i2cprobe_status == 1) && ( SII9234A_i2cprobe_status == 1) 
		&& ( SII9234B_i2cprobe_status == 1) && ( SII9234C_i2cprobe_status == 1))
	{
		SII9234_i2c_status = 1;
		MHL_On(false);
	}

	printk("ksw sii9234_i2c_read(sii9234_i2c_client, 0x02) = %x\n", SII9234_i2c_read(SII9234A_i2c_client, 0x3D));
	
	return 0;

}



static int __devexit SII9234A_remove(struct i2c_client *client)
{
	struct SII9234_state *state = i2c_get_clientdata(client);
	kfree(state);
	return 0;
}

static int SII9234B_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	//SII_DEV_DBG("");

	struct SII9234_state *state;

	state = kzalloc(sizeof(struct SII9234_state), GFP_KERNEL);
	if (state == NULL) {		
		printk("failed to allocate memory \n");
		return -ENOMEM;
	}
	
	state->client = client;
	i2c_set_clientdata(client, state);
	
	/* rest of the initialisation goes here. */
	
	printk("SII9234B attach success!!!\n");

	SII9234B_i2c_client = client;

	SII9234B_i2cprobe_status = 1;
	if(( SII9234_i2cprobe_status == 1) && ( SII9234A_i2cprobe_status == 1) 
		&& ( SII9234B_i2cprobe_status == 1) && ( SII9234C_i2cprobe_status == 1))
	{
		SII9234_i2c_status = 1;
		MHL_On(false);
	}

	printk("ksw sii9234_i2c_read(sii9234_i2c_client, 0x02) = %x\n", SII9234_i2c_read(SII9234B_i2c_client, 0x4C));
	
	return 0;

}



static int __devexit SII9234B_remove(struct i2c_client *client)
{
	struct SII9234_state *state = i2c_get_clientdata(client);
	kfree(state);
	return 0;
}

static void mhl_i2c_client_info(void)
{
	printk("SII9234_i2c_client name = %s, device_id = 0x%x\n", SII9234_i2c_client->name, SII9234_i2c_client->addr);
	printk("SII9234A_i2c_client name = %s, device_id = 0x%x\n", SII9234A_i2c_client->name, SII9234A_i2c_client->addr);
	printk("SII9234B_i2c_client name = %s, device_id = 0x%x\n", SII9234B_i2c_client->name, SII9234B_i2c_client->addr);
	printk("SII9234C_i2c_client name = %s, device_id = 0x%x\n", SII9234C_i2c_client->name, SII9234C_i2c_client->addr);
}

static int SII9234C_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	int ret;
	//SII_DEV_DBG("");

	struct SII9234_state *state;

	state = kzalloc(sizeof(struct SII9234_state), GFP_KERNEL);
	if (state == NULL) {		
		printk("failed to allocate memory \n");
		return -ENOMEM;
	}
	
	state->client = client;
	i2c_set_clientdata(client, state);
	
	/* rest of the initialisation goes here. */
	
	printk("SII9234C attach success!!!\n");

	SII9234C_i2c_client = client;

	SII9234C_i2cprobe_status = 1;
	if(( SII9234_i2cprobe_status == 1) && ( SII9234A_i2cprobe_status == 1) 
		&& ( SII9234B_i2cprobe_status == 1) && ( SII9234C_i2cprobe_status == 1))
	{
		SII9234_i2c_status = 1;
		MHL_On(false);
	}
#if 0
	/* Initialize GPIO 30 (IRQ_MHL_INT).
	* Check if other driver already occupied it.
	*/
	ret = gpio_request(IRQ_MHL_INT, "IRQ MHL INT");
	if(ret < 0){
		printk(KERN_INFO "[MHL] GPIO 30 IRQ_MHL_INT is already occupied by other driver!\n");
		return -ENOSYS;
	}

	/* Initialize GPIO direction before use or IRQ setting */
	ret = gpio_direction_input(IRQ_MHL_INT);
	if(ret < 0){
		printk(KERN_INFO "[MHL] GPIO 30 IRQ_MHL_INT direction initialization failed!\n");
		return -ENOSYS;
	}
#endif
	sii9234_wq = create_singlethread_workqueue("sii9234_wq");
	INIT_WORK(&SiI9234_int_work,SiI9234_interrupt_event_work);

	set_irq_type(IRQ_MHL_INT, IRQ_TYPE_EDGE_FALLING);
	ret = request_threaded_irq( IRQ_MHL_INT , 
		NULL, mhl_int_irq_handler, IRQF_DISABLED	, "mhl_int", (void*)state);
	if (ret < 0) 
	{
		printk("unable to request irq mhl_int err:: %d\n", ret);
		return ret;
	}		
	
	sii9234_wq = create_singlethread_workqueue("sii9234_wq");
	INIT_WORK(&SiI9234_int_work,SiI9234_interrupt_event_work);

/*
	ret = request_irq(IRQ_MHL_WAKE_UP, mhl_wake_up_irq_handler, IRQF_DISABLED, "mhl_wake_up", (void *) state); // check and study here...
	if (ret) 
	{
		printk("unable to request irq mhl_wake_up err:: %d\n", ret);
		return ret;
	}		
	

	ret = request_irq(IRQ_MHL_HPD, mhl_hpd_irq_handler, IRQ_TYPE_EDGE_BOTH  , "mhl_hpd", mhl_hpd_irq_handler);  
	if (ret) 
	{
		printk("unable to request irq mhl_int err:: %d\n", ret);
		return ret;
	}		
	printk("MHL HPD request successful \n");
*/
	//sii9234_cfg_power(1); Unnecessary supply  the current during boot up time.
	mhl_i2c_client_info();
	printk("ksw sii9234_i2c_read(sii9234_i2c_client, 0x02) = %x\n", SII9234_i2c_read(SII9234C_i2c_client, 0x07));

#ifdef TIMER_ACC_ADC 
  hrtimer_init(&sii9234_adc_timer,CLOCK_MONOTONIC,HRTIMER_MODE_REL);
  sii9234_adc_timer.function = sii9234_adctimer_func;
  sii9234_adc_wq = create_singlethread_workqueue("sii9234_adc_wq");

  if (!sii9234_adc_wq) {
		pr_err("%s: could not create workqueue sii9234_adc_wq\n", __func__);
	}
  INIT_WORK(&sii9234_adc_work,sii9234_adc_work_func);
	hrtimer_start(&sii9234_adc_timer,
		ns_to_ktime(500000000/*500ms*/), HRTIMER_MODE_REL);

#endif
	
	return 0;

}



static int __devexit SII9234C_remove(struct i2c_client *client)
{
	struct SII9234_state *state = i2c_get_clientdata(client);
	kfree(state);
	return 0;
}


struct i2c_driver SII9234_i2c_driver = {
	.driver = {
		.owner	= THIS_MODULE,
		.name	= "SII9234",
	},
	.id_table	= SII9234_id,
	.probe	= SII9234_i2c_probe,
	.remove	= __devexit_p(SII9234_remove),
	.command = NULL,
};

struct i2c_driver SII9234A_i2c_driver = {
	.driver = {
		.owner	= THIS_MODULE,
		.name	= "SII9234A",
	},
	.id_table	= SII9234A_id,
	.probe	= SII9234A_i2c_probe,
	.remove	= __devexit_p(SII9234A_remove),
	.command = NULL,
};

struct i2c_driver SII9234B_i2c_driver = {
	.driver = {
		.owner	= THIS_MODULE,
		.name	= "SII9234B",
	},
	.id_table	= SII9234B_id,
	.probe	= SII9234B_i2c_probe,
	.remove	= __devexit_p(SII9234B_remove),
	.command = NULL,
};

struct i2c_driver SII9234C_i2c_driver = {
	.driver = {
		.owner	= THIS_MODULE,
		.name	= "SII9234C",
	},
	.id_table	= SII9234C_id,
	.probe	= SII9234C_i2c_probe,
	.remove	= __devexit_p(SII9234C_remove),
	.command = NULL,
};


static int  sii9234_pre_cfg_power(void)
{
		int rc;
		
		l25 = regulator_get(NULL, "8058_l23");

		if (IS_ERR(l25)) {
			rc = PTR_ERR(l25);
			pr_err("%s: l25 get failed (%d)\n", __func__, rc);
			return rc;
		}
		rc = regulator_set_voltage(l25, 1200000, 1200000);
		if (rc) {
			pr_err("%s: l25 set level failed (%d)\n", __func__, rc);
			return rc;
		}


		l2 = regulator_get(NULL, "8058_l3");

		if (IS_ERR(l2)) {
			rc = PTR_ERR(l2);
			pr_err("%s: l2 get failed (%d)\n", __func__, rc);
			return rc;
		}
		rc = regulator_set_voltage(l2, 3300000, 3300000);
		if (rc) {
			pr_err("%s: l2 set level failed (%d)\n", __func__, rc);
			return rc;
		}

		mvs0 = regulator_get(NULL, "8058_l12");

		if (IS_ERR(mvs0)) {
			rc = PTR_ERR(mvs0);
			pr_err("%s: mvs0 get failed (%d)\n", __func__, rc);
			return rc;
		}

	
		rc = regulator_set_voltage(mvs0, 1800000, 1800000);
		if (rc) {
			pr_err("%s: mvs0 set level failed (%d)\n", __func__, rc);
			return rc;
		}

		return 0;

}


void sii9234_cfg_power(bool on)
{

	int rc;
        static bool sii_power_state = 0;
	if (sii_power_state == on) //Rajucm: Avoid unbalanced voltage regulator onoff
	{
		printk("sii_power_state is already %s ", sii_power_state?"on":"off");
		return;
	}
	sii_power_state = on;

	if(on)
	{
		rc = regulator_enable(l25);		//VSIL_1.2A & VSIL_1.2C 	
		if (rc) {
			pr_err("%s: l25 vreg enable failed (%d)\n", __func__, rc);
			return;
		}

		rc = regulator_enable(l2);		//VCC_3.3V_MHL
		if (rc) {
			pr_err("%s: l2 vreg enable failed (%d)\n", __func__, rc);
			return;
		}


		rc = regulator_enable(mvs0);		//VCC_1.8V_MHL
		if (rc) {
			pr_err("%s: l2 vreg enable failed (%d)\n", __func__, rc);
			return;
		}

	
/*
	gpio_set_value_cansleep(GPIO_MHL_RST, 0);
	msleep(200);
	gpio_set_value_cansleep(GPIO_MHL_RST, 1);
*/
	printk("sii9234_cfg_power on\n");
	}
	else
	{
		rc = regulator_disable(l25);		//VSIL_1.2A & VSIL_1.2C 	
		if (rc) {
			pr_err("%s: l25 vreg enable failed (%d)\n", __func__, rc);
			return;
		}


		rc = regulator_disable(l2);		//VCC_3.3V_MHL
		if (rc) {
			pr_err("%s: l2 vreg enable failed (%d)\n", __func__, rc);
			return;
		}


		rc = regulator_disable(mvs0);		//VCC_1.8V_MHL
		if (rc) {
			pr_err("%s: l2 vreg enable failed (%d)\n", __func__, rc);
			return;
		}
		printk("sii9234_cfg_power off\n");
	}
	return;

}

#if 0
static void sii9234_cfg_gpio()
{
	//int ret;
	printk( "sii9234_cfg_gpio: request reset gpio \n");
	//Handled in Board specific file
	//gpio_tlmm_config(GPIO_CFG(64/*GPIO_MHL_SDA*/, 0, GPIO_CFG_OUTPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_4MA),GPIO_CFG_ENABLE);
	//gpio_tlmm_config(GPIO_CFG(65/*GPIO_MHL_SCL*/, 0, GPIO_CFG_OUTPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_4MA),GPIO_CFG_ENABLE);	

	gpio_set_value_cansleep(GPIO_MHL_SEL, 0);

}
#endif

static int mhl_open(struct inode *ip, struct file *fp)
{
	printk("[%s] \n",__func__);
	return 0;

}

static int mhl_release(struct inode *ip, struct file *fp)
{
	
	printk("[%s] \n",__func__);
	return 0;
}


static int mhl_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	printk("[%s] \n",__func__);

	//byte data;

	switch(cmd)
	{
#if 0
//Disabling //NAGSM_Android_SEL_Kernel_Aakash_20101206
		case MHL_READ_RCP_DATA:
			data = GetCbusRcpData();
			ResetCbusRcpData();
			put_user(data,(byte *)arg);
			printk("MHL_READ_RCP_DATA read");
			break;
#endif
		default:
		break;
	}
		
	return 0;
}


static struct file_operations mhl_fops = {
	.owner  = THIS_MODULE,
	.open   = mhl_open,
    	.release = mhl_release,
    	.ioctl = mhl_ioctl,
};
                 
static struct miscdevice mhl_device = {
    .minor  = MISC_DYNAMIC_MINOR,
    .name   = "mhl",
    .fops   = &mhl_fops,
};


static int __init sii9234_init(void)
{
	int ret;

	printk("ksw mhl_usb_sel_gpio = 0x%x\n", gpio_get_value(GPIO_MHL_SEL));
	//gpio_set_value(GPIO_MHL_SEL, 1);
	//msleep(10);
	//printk("ksw mhl_usb_sel_gpio = 0x%x\n", gpio_get_value(GPIO_MHL_SEL));
	
	sii9234_pre_cfg_power();
	//sii9234_cfg_gpio();
	/* sii9234_cfg_power(1);	//Turn On power to SiI9234 
	*/
	//gpio_set_value(GPIO_MHL_SEL, 1); 
#ifdef MHL_SWITCH_TEST
	sec_mhl = class_create(THIS_MODULE, "sec_mhl");
	if (IS_ERR(sec_mhl))
		printk(KERN_ERR "[MHL] Failed to create class (sec_mhl)\n");

	mhl_switch = device_create(sec_mhl, NULL, 0, NULL, "switch");
	if (IS_ERR(mhl_switch))
		printk(KERN_ERR "[MHL] Failed to create device (mhl_switch)\n");
	if (device_create_file(mhl_switch, &dev_attr_mhl_sel) < 0)
		printk(KERN_ERR "[MHL] Failed to create file (mhl_sel)");
#endif

	ret = misc_register(&mhl_device);
	if(ret) {
		pr_err(KERN_ERR "misc_register failed - mhl \n");
	}

	ret = i2c_add_driver(&SII9234_i2c_driver);
	if (ret != 0)
		printk("[MHL SII9234] can't add i2c driver\n");	
	else
		printk("[MHL SII9234] add i2c driver\n");
	ret = i2c_add_driver(&SII9234A_i2c_driver);
	if (ret != 0)
		printk("[MHL SII9234A] can't add i2c driver\n");	
	else
		printk("[MHL SII9234A] add i2c driver\n");
	ret = i2c_add_driver(&SII9234B_i2c_driver);
	if (ret != 0)
		printk("[MHL SII9234B] can't add i2c driver\n");	
	else
		printk("[MHL SII9234B] add i2c driver\n");
	ret = i2c_add_driver(&SII9234C_i2c_driver);
	if (ret != 0)
		printk("[MHL SII9234C] can't add i2c driver\n");	
	else
		printk("[MHL SII9234C] add i2c driver\n");


	return ret;	
}
late_initcall(sii9234_init);			
static void __exit sii9234_exit(void)
{
	i2c_del_driver(&SII9234_i2c_driver);
	i2c_del_driver(&SII9234A_i2c_driver);
	i2c_del_driver(&SII9234B_i2c_driver);	
	i2c_del_driver(&SII9234C_i2c_driver);
	
};
module_exit(sii9234_exit);

MODULE_DESCRIPTION("Sii9234 MHL driver");
MODULE_AUTHOR("Aakash Manik");
MODULE_LICENSE("GPL");
