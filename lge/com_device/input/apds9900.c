/*
 *  apds9900.c - Linux kernel modules for ambient light + proximity sensor
 *
 *  Copyright (C) 2010 Lee Kai Koon <kai-koon.lee@avagotech.com>
 *  Copyright (C) 2010 Avago Technologies
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/input.h>

#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <apds9900.h>

#define APDS9900_DRV_NAME       "apds9900"
#define DRIVER_VERSION          "1.0.4"

#define APDS9900_USE_MUTEX  
#define APDS990x_PS_DETECTION_THRESHOLD		600
#define APDS990x_PS_HSYTERESIS_THRESHOLD	500

/* Change History 
 *
 * 1.0.1	Functions apds990x_show_rev(), apds990x_show_id() and apds990x_show_status()
 *			have missing CMD_BYTE in the i2c_smbus_read_byte_data(). APDS-990x needs
 *			CMD_BYTE for i2c write/read byte transaction.
 *
 *
 * 1.0.2	Include PS switching threshold level when interrupt occurred
 *
 *
 * 1.0.3	Implemented ISR and delay_work, correct PS threshold storing
 *
 * 1.0.4	Added Input Report Event
 */

/*
 * Defines
 */
#define APDS9900_ENABLE_REG     0x00
#define APDS9900_ATIME_REG      0x01
#define APDS9900_PTIME_REG      0x02
#define APDS9900_WTIME_REG      0x03
#define APDS9900_AILTL_REG      0x04
#define APDS9900_AILTH_REG      0x05
#define APDS9900_AIHTL_REG      0x06
#define APDS9900_AIHTH_REG      0x07
#define APDS9900_PILTL_REG      0x08
#define APDS9900_PILTH_REG      0x09
#define APDS9900_PIHTL_REG      0x0A
#define APDS9900_PIHTH_REG      0x0B
#define APDS9900_PERS_REG       0x0C
#define APDS9900_CONFIG_REG     0x0D
#define APDS9900_PPCOUNT_REG    0x0E
#define APDS9900_CONTROL_REG    0x0F
#define APDS9900_REV_REG        0x11
#define APDS9900_ID_REG         0x12
#define APDS9900_STATUS_REG     0x13
#define APDS9900_CDATAL_REG     0x14
#define APDS9900_CDATAH_REG     0x15
#define APDS9900_IRDATAL_REG    0x16
#define APDS9900_IRDATAH_REG    0x17
#define APDS9900_PDATAL_REG     0x18
#define APDS9900_PDATAH_REG     0x19

#define CMD_BYTE                0x80
#define CMD_WORD                0xA0
#define CMD_SPECIAL             0xE0

#define CMD_CLR_PS_INT          0xE5
#define CMD_CLR_ALS_INT         0xE6
#define CMD_CLR_PS_ALS_INT      0xE7

#define ALS_SENSOR_NAME         "apds9900"
#define PROXI_NAME              "proximity"
#define LIGHT_NAME              "light"
/*
 * Structs
 */

struct apds9900_data 
{
    struct i2c_client *client;
#ifdef APDS9900_USE_MUTEX
    struct mutex lock;
#else
	spinlock_t update_lock;
#endif
    struct delayed_work poswork;
    struct input_dev *input_dev_proxi;
    struct input_dev *input_dev_light;
    
    unsigned int enable;
    unsigned int atime;
    unsigned int ptime;
    unsigned int wtime;
    unsigned int ailt;
    unsigned int aiht;
    unsigned int pilt;
    unsigned int piht;
    unsigned int pers;
    unsigned int config;
    unsigned int ppcount;
    unsigned int control;

	/* control flag from HAL */
	unsigned int enable_ps_sensor;
	unsigned int enable_als_sensor;

    /* PS parameters */
    unsigned int ps_threshold;
	unsigned int ps_hysteresis_threshold; /* always lower than ps_threshold */
    unsigned int ps_detection;      /* 0 = near-to-far; 1 = far-to-near */
    unsigned int ps_data;           /* to store PS data */

    /* ALS parameters */
    unsigned int als_threshold_l;   /* low threshold */
    unsigned int als_threshold_h;   /* high threshold */
    unsigned int als_data;          /* to store ALS data */
	
    unsigned int irq;
	unsigned int als_gain;			/* needed for Lux calculation */
	unsigned int als_poll_delay;		/* needed for light sensor polling : micro-second (us) */
	unsigned int als_atime;			/* storage for als integratiion time */
};

#define ABS_LIGHT       0x29

struct apds9900_data *papds9900_data;
static struct workqueue_struct *apds9900_workqueue ;

#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>

static struct early_suspend apds9900_sensor_early_suspend;
static void apds9900_early_suspend(struct early_suspend *h);
static void apds9900_late_resume(struct early_suspend *h);
#endif

#ifdef CONFIG_PM
static int apds9900_suspend(struct device *device);
static int apds9900_resume(struct device *device);
#endif
 
static int apds9900_check_reliablility(struct i2c_client *client );
static int apds9900_device_parameter_init(struct i2c_client *client);
static int apds9900_device_init(struct i2c_client *client);

/*
 * DEBUG MASK
 */

#define APDS9900_DEBUG_PRINT  (1)
#if defined(APDS9900_DEBUG_PRINT)
#define DEBUG_MSG(fmt, args...) \
                        printk(KERN_INFO "[APDS9900] [%s %d] " \
                                fmt, __FUNCTION__, __LINE__, ##args);
#else
#define DEBUG_MSG(fmt, args...)     {};
#endif

/* Debug mask value
 * usage: echo [debug_mask] > /sys/module/apds9900/parameters/debug_mask
 * All			: 63
 * No msg		: 0
 * default		: 1
 */
enum 
{
		APDS9900_DEBUG_ERROR_CHECK	= 1U << 0,
		APDS9900_DEBUG_FUNC_TRACE 	= 1U << 1,
		APDS9900_DEBUG_DEV_STATUS 	= 1U << 2,
		APDS9900_DEBUG_DEV_DEBOUNCE	= 1U << 3,
		APDS9900_DEBUG_GEN_INFO		= 1U << 4,
		APDS9900_DEBUG_INTR_INFO	= 1U << 5,
};

static unsigned int apds9900_debug_mask = APDS9900_DEBUG_ERROR_CHECK;

module_param_named(debug_mask, apds9900_debug_mask, int,
                S_IRUGO | S_IWUSR );

/*
 * Management functions
 */
static int apds9900_set_command(struct i2c_client *client, int command)
{
	int ret = 0;
	int clearInt = 0;
	
	if (command == 0)
		clearInt = CMD_CLR_PS_INT;
	else if (command == 1)
		clearInt = CMD_CLR_ALS_INT;
	else
		clearInt = CMD_CLR_PS_ALS_INT;
	
	ret = i2c_smbus_write_byte(client, clearInt);
	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
		return ret;
	}

	return ret;
}

static void apds9900_change_ps_threshold(struct i2c_client *client)
{
	int irdata=0;
	int ret = 0;
    struct apds9900_data *data = i2c_get_clientdata(client);
   
    data->ps_data =	i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_PDATAL_REG);
	if (data->ps_data < 0) {
		dev_err(&client->dev,
			"%s: i2c read fail: can't read from %02x: %d\n",__func__, CMD_WORD|APDS9900_PDATAL_REG, data->ps_data);
		return;
	} 

	irdata = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_IRDATAL_REG);
	if (irdata < 0) {
		dev_err(&client->dev,
			"%s: i2c read fail: can't read from %02x: %d\n",__func__, CMD_WORD|APDS9900_IRDATAL_REG, irdata);
		return;
	} 

	if ( (data->ps_data > data->pilt) && (data->ps_data >= data->piht) && (irdata != (100*(1024*(256-data->atime)))/100)) 
	{
		/* FAR-to-NEAR */
		data->ps_detection = 1;

        input_report_abs(data->input_dev_proxi, ABS_DISTANCE, 3); // fix to 3cm when near
		input_sync(data->input_dev_proxi);

		ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PILTL_REG, data->ps_hysteresis_threshold);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
				data->ps_hysteresis_threshold, CMD_WORD|APDS9900_PILTL_REG, ret);
			return;
		}		
		ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PIHTL_REG, 1023);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
				1023, CMD_WORD|APDS9900_PIHTL_REG, ret);
			return;
		}

		data->pilt = data->ps_hysteresis_threshold;
		data->piht = 1023;
		
#ifdef APDS9900_USE_MUTEX
#else
		set_irq_wake(data->irq, 1);
#endif
		if (apds9900_debug_mask & APDS9900_DEBUG_FUNC_TRACE)
        	DEBUG_MSG("### far-to-near detected\n");		
	}
	else if ( (data->ps_data <= data->pilt) && (data->ps_data < data->piht) ) 
	{
		/* NEAR-to-FAR */
		data->ps_detection = 0;

        input_report_abs(data->input_dev_proxi, ABS_DISTANCE, 10); // fix to 10cm when far
		input_sync(data->input_dev_proxi);

		ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PILTL_REG, 0);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
				0, CMD_WORD|APDS9900_PILTL_REG, ret);
			return;
		}		
		ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PIHTL_REG, data->ps_threshold);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
				data->ps_threshold, CMD_WORD|APDS9900_PIHTL_REG, ret);
			return;
		}	

		data->pilt = 0;
		data->piht = data->ps_threshold;

#ifdef APDS9900_USE_MUTEX
#else
		set_irq_wake(data->irq, 0);
#endif
		if (apds9900_debug_mask & APDS9900_DEBUG_FUNC_TRACE)
        	DEBUG_MSG("### near-to-far detected\n");
	}
	else if ( (irdata == (100*(1024*(256-data->atime)))/100) && (data->ps_detection == 1) ) 
	{
		/* under strong ambient light*/
		/*NEAR-to-FAR */
		data->ps_detection = 0;

        input_report_abs(data->input_dev_proxi, ABS_DISTANCE, 10); // fix to 10cm when far
		input_sync(data->input_dev_proxi);

//		i2c_smbus_write_word_data(client, CMD_WORD|APDS990x_PILTL_REG, 0);
//		i2c_smbus_write_word_data(client, CMD_WORD|APDS990x_PIHTL_REG, data->ps_threshold);

//		data->pilt = 0;
//		data->piht = data->ps_threshold;

		/*Keep the threshold NEAR condition to prevent the frequent Interrupt under strong ambient light*/
		ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PILTL_REG, data->ps_hysteresis_threshold);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
				data->ps_hysteresis_threshold, CMD_WORD|APDS9900_PILTL_REG, ret);
			return;
		}	

		ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PIHTL_REG, 1023);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
				1023, CMD_WORD|APDS9900_PIHTL_REG, ret);
			return;
		}				
		data->pilt = data->ps_hysteresis_threshold;
		data->piht = 1023;
		
#ifdef APDS9900_USE_MUTEX
#else
		set_irq_wake(data->irq, 0);
#endif
		if (apds9900_debug_mask & APDS9900_DEBUG_FUNC_TRACE)
		{
        	DEBUG_MSG("### near-to-far detected\n");
			DEBUG_MSG("* Set PS Threshold NEAR condition to prevent the frequent Interrupt under strong ambient light *\n");
		}
		
	}
	
	else if ( (data->pilt == 1023) && (data->piht == 0) )
	{
		/* this is the first near-to-far forced interrupt */
		data->ps_detection = 0;

        input_report_abs(data->input_dev_proxi, ABS_DISTANCE, 10); // fix to 10cm when far
		input_sync(data->input_dev_proxi);

		ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PILTL_REG, 0);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
				0, CMD_WORD|APDS9900_PILTL_REG, ret);
			return;
		}			
		ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PIHTL_REG, data->ps_threshold);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
				data->ps_threshold, CMD_WORD|APDS9900_PIHTL_REG, ret);
			return;
		}	

		data->pilt = 0;
		data->piht = data->ps_threshold;

		//set_irq_wake(data->irq, 0);
		if (apds9900_debug_mask & APDS9900_DEBUG_FUNC_TRACE)
        	DEBUG_MSG("### near-to-far detected\n");

	}
}

static void apds9900_change_als_threshold(struct i2c_client *client)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
	struct apds9900_platform_data* pdata = client->dev.platform_data;
    
    int iac1, iac2, iac = 0;
	unsigned int ch0data, ch1data = 0;
	int luxValue=0;
	int ret = 0;

	ch0data = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_CDATAL_REG);
	if (ch0data < 0) {
		dev_err(&client->dev,
			"%s: i2c read fail: can't read from %02x: %d\n",  __func__,  CMD_WORD|APDS9900_CDATAL_REG, ch0data);
		return;
	} 

	ch1data = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_IRDATAL_REG);
	if (ch1data < 0) {
		dev_err(&client->dev,
			"%s: i2c read fail: can't read from %02x: %d\n", __func__, CMD_WORD|APDS9900_IRDATAL_REG, ch1data);
		return;
	}
    
    iac1 = ch0data -((pdata->B*ch1data)/1000);
    iac2 = (ch0data*pdata->C)/1000 - (ch1data*pdata->D)/1000;

    if((iac1 < 0) && (iac2<0))
   	{
   	  if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
        	DEBUG_MSG("[LUX] iac: set to 0\n");
		iac = 0;
   	}
    else if(iac1 > iac2)
   	{
   	  if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
       		DEBUG_MSG("[LUX] iac: set to iac1, due to (iac1 > iac2)\n");
        iac = iac1;
   	}
    else
   	{
   	  if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
        	DEBUG_MSG("[LUX] iac: set to iac2, due to else\n");   	
        iac = iac2;
   	}
    
    if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
    {
       	DEBUG_MSG("[LUX] ch0data = %d, ch1data = %d\n",ch0data, ch1data);
		DEBUG_MSG("[LUX] iac1 = %d, iac2 = %d\n",iac1, iac2);
        DEBUG_MSG("[LUX] iac = %d\n",iac);
    }
    luxValue = data->als_data =(unsigned int)((iac*pdata->ga_value*pdata->df_value)/(pdata->alsit));
	luxValue = luxValue>0 ? luxValue : 0;
	luxValue = luxValue<10000 ? luxValue : 10000;

    if(ch0data==(1024*(256-data->atime)))//under the direct sunlight, the luxvalue is fixed to 10000
		luxValue = 10000;

    if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
        DEBUG_MSG("[LUX] als_data = %d\n",luxValue);

    input_report_abs(data->input_dev_light, ABS_LIGHT, luxValue); //report als data
    input_sync(data->input_dev_light);
    
    data->als_threshold_l = (ch0data * (100 - pdata->als_threshold_hsyteresis)) /100;
    data->als_threshold_h = (ch0data * (100 + pdata->als_threshold_hsyteresis)) /100;
        
	if (data->als_threshold_h >= 65535) data->als_threshold_h = 65535;
    ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_AILTL_REG, data->als_threshold_l);
	if (ret < 0) {
		dev_err(&client->dev,
			"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
			data->als_threshold_l, CMD_WORD|APDS9900_AILTL_REG, ret);
		return;
	}		
    ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_AIHTL_REG, data->als_threshold_h);
	if (ret < 0) {
		dev_err(&client->dev,
			"%s: i2c write fail: can't write %02x to %02x: %d\n", __func__,
			data->als_threshold_h, CMD_WORD|APDS9900_AIHTL_REG, ret);
		return;
	}	

}

static void apds9900_reschedule_work(struct apds9900_data *data, unsigned long delay)
{
#ifdef APDS9900_USE_MUTEX
#else
    unsigned long flags = 0;
    
    spin_lock_irqsave(&data->update_lock, flags);
#endif
    
  /*
     * If work is already scheduled then subsequent schedules will not
     * change the scheduled time that's why we have to cancel it first.
     */
    __cancel_delayed_work(&data->poswork);
#if 1
    queue_delayed_work(apds9900_workqueue,&data->poswork, delay);
#else
    schedule_delayed_work(&data->poswork, delay);
#endif    
#ifdef APDS9900_USE_MUTEX
#else
    spin_unlock_irqrestore(&data->update_lock, flags);
#endif
}

static void apds9900_event_work(struct work_struct *work)
{
    struct apds9900_data *data = container_of(work, struct apds9900_data, poswork.work);
    struct i2c_client *client=data->client;
	int status = 0;
	int irdata=0;
	int ret = 0;
	
#ifdef APDS9900_USE_MUTEX
    mutex_lock(&data->lock); 
#endif
    status = i2c_smbus_read_byte_data(client, CMD_BYTE|APDS9900_STATUS_REG);
	if (status < 0) {
		dev_err(&client->dev, "%s: i2c error %d in reading reg 0x%x\n", __func__, status, CMD_BYTE|APDS9900_STATUS_REG);
#ifdef APDS9900_USE_MUTEX
		goto err_i2c_fail;
#else
		return;
#endif
	}

    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_ENABLE_REG, 1);	/* disable 9900's ADC first */
	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
#ifdef APDS9900_USE_MUTEX
		goto err_i2c_fail;
#else
		return;
#endif
	}


    if ((status & data->enable & 0x30) == 0x30)
    {
		/* both PS and ALS are interrupted */
		apds9900_change_als_threshold(client);
		
		/* check if this is triggered by background ambient noise */	
		irdata = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_IRDATAL_REG);
		if (irdata < 0) {
			dev_err(&client->dev,
				"%s: i2c read fail: can't read from %02x: %d\n", __func__, CMD_WORD|APDS9900_IRDATAL_REG, irdata);
#ifdef APDS9900_USE_MUTEX
			goto err_i2c_fail;
#else
			return;
#endif
		} 

		if (irdata != (100*(1024*(256-data->atime)))/100)
			apds9900_change_ps_threshold(client);
		else 
		{
			if (data->ps_detection == 1) 
			{
				apds9900_change_ps_threshold(client);			
				if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
				{
					DEBUG_MSG("* Triggered by background ambient noise\n");	
					DEBUG_MSG("\n ===> near-to-FAR\n");
				}
			}
			else 
			{
				/*Keep the threshold NEAR condition to prevent the frequent Interrup under strong ambient light*/
				ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PILTL_REG, data->ps_hysteresis_threshold);
				if (ret < 0) {
					dev_err(&client->dev, "%s: failed reading register, %d\n", __func__, ret);
#ifdef APDS9900_USE_MUTEX
					goto err_i2c_fail;
#else
					return;
#endif
				}				
				ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PIHTL_REG, 1023);
				if (ret < 0) {
					dev_err(&client->dev, "%s: failed reading register, %d\n", __func__, ret);
#ifdef APDS9900_USE_MUTEX
					goto err_i2c_fail;
#else
					return;
#endif
				}				
				data->pilt = data->ps_hysteresis_threshold;
				data->piht = 1023;
				if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
				{
      				DEBUG_MSG("* Set PS Threshold NEAR condition to prevent the frequent Interrup under strong ambient light\n");
      				DEBUG_MSG("* Triggered by background ambient noise\n\n");
      				DEBUG_MSG("\n ==> maintain FAR \n\n");
				}
			}
		}

		apds9900_set_command(client, 2);	/* 2 = CMD_CLR_PS_ALS_INT */
    }
    else if ((status & data->enable & 0x20) == 0x20)
    {
		/* only PS is interrupted */
		
		/* check if this is triggered by background ambient noise */
		irdata = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_IRDATAL_REG);	
		if (irdata < 0) {
			dev_err(&client->dev,
				"%s: i2c read fail: can't read from %02x: %d\n", __func__, CMD_WORD|APDS9900_IRDATAL_REG, irdata);
#ifdef APDS9900_USE_MUTEX
			goto err_i2c_fail;
#else
			return;
#endif
		} 		
		if (irdata != (100*(1024*(256-data->atime)))/100)
			apds9900_change_ps_threshold(client);
		else 
		{
			if (data->ps_detection == 1) 
			{
				apds9900_change_ps_threshold(client);			
				if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
				{	
    		        DEBUG_MSG("* Triggered by background ambient noise\n");	
    				DEBUG_MSG("\n ===> near-to-FAR\n");
				}					
			}
			else 
			{
				/*Keep the threshold NEAR condition to prevent the frequent Interrup under strong ambient light*/
				ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PILTL_REG, data->ps_hysteresis_threshold);
				if (ret < 0) {
					dev_err(&client->dev, "%s: failed reading register, %d\n", __func__, ret);
#ifdef APDS9900_USE_MUTEX
					goto err_i2c_fail;
#else
					return;
#endif
				}				
				ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PIHTL_REG, 1023);
				if (ret < 0) {
					dev_err(&client->dev, "%s: failed reading register, %d\n", __func__, ret);
#ifdef APDS9900_USE_MUTEX
					goto err_i2c_fail;
#else
					return;
#endif
				}				
				data->pilt = data->ps_hysteresis_threshold;
				data->piht = 1023;
				if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
				{
					DEBUG_MSG("* Set PS Threshold NEAR condition to prevent the frequent Interrup under strong ambient light\n");
					DEBUG_MSG("* Triggered by background ambient noise\n");
					DEBUG_MSG("\n ==> maintain FAR \n\n");
				}
			}
		}
		
		apds9900_set_command(client, 0);	/* 0 = CMD_CLR_PS_INT */
    }
    else if ((status & data->enable & 0x10) == 0x10)
    {
		/* only ALS is interrupted */	
		apds9900_change_als_threshold(client);

		if(data->enable_ps_sensor==1)
		{
			/* check if this is triggered by background ambient noise */
			irdata = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_IRDATAL_REG);
			if (irdata < 0) {
				dev_err(&client->dev,
					"%s: i2c read fail: can't read from %02x: %d\n", __func__, CMD_WORD|APDS9900_IRDATAL_REG, irdata);
#ifdef APDS9900_USE_MUTEX
				goto err_i2c_fail;
#else
				return;
#endif
			} 				
			if (irdata != (100*(1024*(256-data->atime)))/100)
				apds9900_change_ps_threshold(client);			
			else 
			{								 
				if (data->ps_detection == 1) 
				{
					apds9900_change_ps_threshold(client);			
			
					if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
					{
						printk("* Triggered by background ambient noise\n");
						printk("\n ===> near-to-FAR\n");
					}
				}
				else 
				{			
					/*Keep the threshold NEAR condition to prevent the frequent Interrup under strong ambient light*/
					ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PILTL_REG, data->ps_hysteresis_threshold);
					if (ret < 0) {
						dev_err(&client->dev, "%s: failed reading register, %d\n", __func__, ret);
#ifdef APDS9900_USE_MUTEX
						goto err_i2c_fail;
#else
						return;
#endif
					}						
					ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PIHTL_REG, 1023);
					if (ret < 0) {
						dev_err(&client->dev, "%s: failed reading register, %d\n", __func__, ret);
#ifdef APDS9900_USE_MUTEX
						goto err_i2c_fail;
#else
						return;
#endif
					}									
					data->pilt = data->ps_hysteresis_threshold;
					data->piht = 1023;
					if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
					{
						printk("* Set PS Threshold NEAR condition to prevent the frequent Interrup under strong ambient light\n");
						printk("* Triggered by background ambient noise\n");
						printk("\n ==> maintain FAR \n\n");
					}
				}
			}
		}
		
		apds9900_set_command(client, 1);	/* 1 = CMD_CLR_ALS_INT */
    }

    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_ENABLE_REG, data->enable);
	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
#ifdef APDS9900_USE_MUTEX
		goto err_i2c_fail;
#else
		return;
#endif
	}	
#ifdef APDS9900_USE_MUTEX
err_i2c_fail:
	mutex_unlock(&data->lock);
	return;	
#endif
}

/* assume this is ISR */
static irqreturn_t apds9900_isr(int irq, void *dev_id)
{
    struct apds9900_data *data = dev_id;
    
    if(apds9900_debug_mask & APDS9900_DEBUG_DEV_STATUS)
        DEBUG_MSG("### apds9900_interrupt\n");
    apds9900_reschedule_work(data, 0);
    
    return IRQ_HANDLED;
}

static int apds9900_set_atime(struct i2c_client *client, int atime)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_ATIME_REG, atime);
	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
		return ret;
	}

    data->atime = atime;
    
    return ret;
}

static int apds9900_set_ptime(struct i2c_client *client, int ptime)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_PTIME_REG, ptime);
    
    data->ptime = ptime;
    
    return ret;
}

static int apds9900_set_wtime(struct i2c_client *client, int wtime)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_WTIME_REG, wtime);
 	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
		return ret;
	}   
    data->wtime = wtime;
    
    return ret;
}

static int apds9900_set_ailt(struct i2c_client *client, int threshold)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_AILTL_REG, threshold);
 	if (ret < 0) {
		dev_err(&client->dev, "%s: failed reading register, %d\n", __func__, ret);
		return ret;
	}   
    data->ailt = threshold;
    
    return ret;
}

static int apds9900_set_aiht(struct i2c_client *client, int threshold)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_AIHTL_REG, threshold);
  	if (ret < 0) {
		dev_err(&client->dev, "%s: failed reading register, %d\n", __func__, ret);
		return ret;
	}    
    data->aiht = threshold;
    
    return ret;
}

static int apds9900_set_pilt(struct i2c_client *client, int threshold)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PILTL_REG, threshold);
    
    data->pilt = threshold;
    
    return ret;
}

static int apds9900_set_piht(struct i2c_client *client, int threshold)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_word_data(client, CMD_WORD|APDS9900_PIHTL_REG, threshold);
    
    data->piht = threshold;
    data->ps_threshold = threshold;

    return ret;
}

static int apds9900_set_pers(struct i2c_client *client, int pers)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_PERS_REG, pers);
 	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
		return ret;
	}   
    data->pers = pers;
    
    return ret;
}

static int apds9900_set_config(struct i2c_client *client, int config)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_CONFIG_REG, config);
	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
		return ret;
	}    
    data->config = config;
    
    return ret;
}

static int apds9900_set_ppcount(struct i2c_client *client, int ppcount)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_PPCOUNT_REG, ppcount);
 	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
		return ret;
	}   
    data->ppcount = ppcount;
    
    return ret;
}

static int apds9900_set_control(struct i2c_client *client, int control)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int ret = 0;
    
    ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_CONTROL_REG, control);
	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
		return ret;
	}   
    data->control = control;
    
    return ret;
}

static int apds9900_check_reliablility(struct i2c_client *client )
{
    struct apds9900_data *data = i2c_get_clientdata(client);
    int control = 0;
    
    control = i2c_smbus_read_byte_data(client, CMD_BYTE|APDS9900_CONTROL_REG);
	if (control < 0) {
		dev_err(&client->dev, "%s: i2c error %d in reading reg 0x%x\n",  __func__, control, CMD_BYTE|APDS9900_CONTROL_REG);
		return control;
	}    
    if(data->control != control)
    {
    	if(apds9900_debug_mask & APDS9900_DEBUG_ERROR_CHECK)
        	DEBUG_MSG("### apds9900_check_reliablility fail!! reinit device !! control reg(%x),buf(%x)\n", control,data->control);
        return 0;
    }
    else
    {
        return 1;
    }
}

static int apds9900_set_enable(struct i2c_client *client, int enable)
{
    struct apds9900_data *data = i2c_get_clientdata(client);
	
    int ret = 0;
    int retry_count = 0;

	if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
		DEBUG_MSG("### apds9900_set_enable papds9900_data->enable=%d, data->enable=%d, enable=%d\n", papds9900_data->enable, data->enable, enable);

    // Reliability check
    if(data->enable != enable)
    {
        if(enable != 0)
        {
            for(retry_count = 0; retry_count <= 2; retry_count++)
            {
                if(apds9900_check_reliablility(client) == 0) // fail
                    apds9900_device_parameter_init(client);
                else
                    break;
            }
			if(((data->enable &0x20)==0)&&((enable &0x20)==1))
			{
                apds9900_set_pilt(client, 1023);	// to force first Near-to-Far interrupt
                apds9900_set_piht(client, 0);
                papds9900_data->ps_detection = 1;			// we are forcing Near-to-Far interrupt, so this is defaulted to 1
                papds9900_data->ps_threshold = APDS990x_PS_DETECTION_THRESHOLD;
                papds9900_data->ps_hysteresis_threshold = APDS990x_PS_HSYTERESIS_THRESHOLD;
				
				if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
					DEBUG_MSG("### apds9900_set_enable initialize ps_threshold\n");
			}
        }
		ret = i2c_smbus_write_byte_data(client, CMD_BYTE|APDS9900_ENABLE_REG, enable);
		if (ret < 0) {
			dev_err(&client->dev, "%s: i2c write fail err %d\n", __func__, ret);
			return ret;
		}		
        data->enable = enable;
    }
    
	if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
		DEBUG_MSG("### apds9900_set_enable data->enable=%d, papds9900_data->enable=%d\n", data->enable, papds9900_data->enable);

    return ret;
}

/*
 * SysFS support
 */

static ssize_t apds9900_store_command(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;

    if (val < 0 || val > 2)
        return -EINVAL;
    
    ret = apds9900_set_command(client, val);
    
    if (ret < 0)
        return ret;
    
    return count;
}
static DEVICE_ATTR(command, S_IWUSR, NULL, apds9900_store_command);

static ssize_t apds9900_show_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    
    return sprintf(buf, "%x\n", data->enable);
}

static ssize_t apds9900_store_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;
    
    ret = apds9900_set_enable(client, val);
    
    if (ret < 0)
        return ret;
    
    return count;
}
static DEVICE_ATTR(enable, S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_enable, apds9900_store_enable);

static ssize_t apds9900_show_atime(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    
    return sprintf(buf, "%x\n", data->atime);
}

static ssize_t apds9900_store_atime(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;
    
    ret = apds9900_set_atime(client, val);
    
    if (ret < 0)
        return ret;
    
    return count;
}
static DEVICE_ATTR(atime,  S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_atime, apds9900_store_atime);

static ssize_t apds9900_show_ptime(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    
    return sprintf(buf, "%x\n", data->ptime);
}

static ssize_t apds9900_store_ptime(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;
    
    ret = apds9900_set_ptime(client, val);
    
    if (ret < 0)
        return ret;
    
    return count;
}
static DEVICE_ATTR(ptime, S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_ptime, apds9900_store_ptime);

static ssize_t apds9900_show_wtime(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    
    return sprintf(buf, "%x\n", data->wtime);
}

static ssize_t apds9900_store_wtime(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;
    
    ret = apds9900_set_wtime(client, val);

    if (ret < 0)
        return ret;

    return count;
}
static DEVICE_ATTR(wtime,  S_IWUSR | S_IRUGO  | S_IRGRP | S_IROTH , apds9900_show_wtime, apds9900_store_wtime);

static ssize_t apds9900_show_ailt(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    
    return sprintf(buf, "%x\n", data->ailt);
}

static ssize_t apds9900_store_ailt(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;
    
    ret = apds9900_set_ailt(client, val);
    
    if (ret < 0)
        return ret;
    
    return count;
}
static DEVICE_ATTR(ailt,  S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_ailt, apds9900_store_ailt);

static ssize_t apds9900_show_aiht(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    
    return sprintf(buf, "%x\n", data->aiht);
}

static ssize_t apds9900_store_aiht(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;

    ret = apds9900_set_aiht(client, val);

    if (ret < 0)
        return ret;
    
    return count;
}
static DEVICE_ATTR(aiht,  S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_aiht, apds9900_store_aiht);

static ssize_t apds9900_show_pilt(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    
    return sprintf(buf, "%x\n", data->pilt);
}

static ssize_t apds9900_store_pilt(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;
    
    ret = apds9900_set_pilt(client, val);
    
    if (ret < 0)
        return ret;
    
    return count;
}
static DEVICE_ATTR(pilt, S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_pilt, apds9900_store_pilt);

static ssize_t apds9900_show_piht(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    
    return sprintf(buf, "%x\n", data->piht);
}

static ssize_t apds9900_store_piht(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;

    ret = apds9900_set_piht(client, val);

    if (ret < 0)
        return ret;

    return count;
}
static DEVICE_ATTR(piht,  S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_piht, apds9900_store_piht);

static ssize_t apds9900_show_pers(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);

    return sprintf(buf, "%x\n", data->pers);
}

static ssize_t apds9900_store_pers(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;

    ret = apds9900_set_pers(client, val);

    if (ret < 0)
        return ret;

    return count;
}
static DEVICE_ATTR(pers, S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_pers, apds9900_store_pers);

static ssize_t apds9900_show_config(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);

    return sprintf(buf, "%x\n", data->config);
}

static ssize_t apds9900_store_config(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;

    ret = apds9900_set_config(client, val);

    if (ret < 0)
        return ret;

    return count;
}
static DEVICE_ATTR(config,  S_IWUSR | S_IRUGO|S_IRGRP |S_IROTH, apds9900_show_config, apds9900_store_config);

static ssize_t apds9900_show_ppcount(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);

    return sprintf(buf, "%x\n", data->ppcount);
}

static ssize_t apds9900_store_ppcount(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;

    ret = apds9900_set_ppcount(client, val);

    if (ret < 0)
        return ret;

    return count;
}
static DEVICE_ATTR(ppcount,  S_IWUSR | S_IRUGO |S_IRGRP |S_IROTH, apds9900_show_ppcount, apds9900_store_ppcount);

static ssize_t apds9900_show_control(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    int control = 0;

    control = i2c_smbus_read_byte_data(client, CMD_BYTE|APDS9900_CONTROL_REG);
	if (control < 0) {
		dev_err(&client->dev, "%s: i2c error %d in reading reg 0x%x\n",  __func__, control, CMD_BYTE|APDS9900_CONTROL_REG);
		return control;
	} 

    //return sprintf(buf, "%x\n", data->control);
    return sprintf(buf, "reg(%x),buf(%x)\n", control,data->control);
}

static ssize_t apds9900_store_control(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct i2c_client *client = to_i2c_client(dev);
    unsigned long val = simple_strtoul(buf, NULL, 10);
    int ret = 0;

    ret = apds9900_set_control(client, val);

    if (ret < 0)
        return ret;

    return count;
}
static DEVICE_ATTR(control,  S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_control, apds9900_store_control);

static ssize_t apds9900_show_rev(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    int rev = 0;

    rev = i2c_smbus_read_byte_data(client, CMD_BYTE|APDS9900_REV_REG);
	if (rev < 0) {
		dev_err(&client->dev, "%s: i2c error %d in reading reg 0x%x\n", __func__, rev, CMD_BYTE|APDS9900_REV_REG);
		return rev;
	} 

    return sprintf(buf, "%x\n", rev);
}
static DEVICE_ATTR(rev, S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_rev, NULL);

static ssize_t apds9900_show_id(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    int id = 0;

    id = i2c_smbus_read_byte_data(client, CMD_BYTE|APDS9900_ID_REG);
	if (id < 0) {
		dev_err(&client->dev, "%s: i2c error %d in reading reg 0x%x\n", __func__, id, CMD_BYTE|APDS9900_ID_REG);
		return id;
	}

    return sprintf(buf, "%x\n", id);
}
static DEVICE_ATTR(id, S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_id, NULL);

static ssize_t apds9900_show_status(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    int status = 0;

    status = i2c_smbus_read_byte_data(client, CMD_BYTE|APDS9900_STATUS_REG);
	if (status < 0) {
		dev_err(&client->dev, "%s: i2c error %d in reading reg 0x%x\n", __func__, status, CMD_BYTE|APDS9900_STATUS_REG);
		return status;
	}

    return sprintf(buf, "%x\n", status);
}
static DEVICE_ATTR(status, S_IRUGO |S_IRGRP | S_IROTH, apds9900_show_status, NULL);

static ssize_t apds9900_show_cdata(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    int cdata = 0;

    cdata = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_CDATAL_REG);
	if (cdata < 0) {
		dev_err(&client->dev,
			"%s: i2c read fail: can't read from %02x: %d\n", __func__, CMD_WORD|APDS9900_CDATAL_REG, cdata);
		return -EAGAIN;
	} 

    return sprintf(buf, "%x\n", cdata);
}
static DEVICE_ATTR(cdata, S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_cdata, NULL);

static ssize_t apds9900_show_irdata(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    int irdata = 0;

    irdata = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_IRDATAL_REG);
	if (irdata < 0) {
		dev_err(&client->dev,
			"%s: i2c read fail: can't read from %02x: %d\n", __func__, CMD_WORD|APDS9900_IRDATAL_REG, irdata);
		return -EAGAIN;
	} 

    return sprintf(buf, "%x\n", irdata);
}
static DEVICE_ATTR(irdata, S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_irdata, NULL);

static ssize_t apds9900_show_pdata(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    int pdata = 0;

    pdata = i2c_smbus_read_word_data(client, CMD_WORD|APDS9900_PDATAL_REG);
	if (pdata < 0) {
		dev_err(&client->dev,
			"%s: i2c read fail: can't read from %02x: %d\n", __func__, CMD_WORD|APDS9900_PDATAL_REG, pdata);
		return -EAGAIN;
	} 

    return sprintf(buf, "%x\n", pdata);
}
static DEVICE_ATTR(pdata, S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_pdata, NULL);

/* kwangdo.yi@lge.com 10.08.31
 * added to inform LgHiddenMenu of Near/Far
 */
static ssize_t apds9900_show_prox(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    int pdata = 0;
    pdata = data->ps_detection;

    return sprintf(buf, "%x\n", pdata);
}
static DEVICE_ATTR(prox, S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_prox, NULL);

static ssize_t apds9900_show_enable1(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);

    return sprintf(buf, "%x\n", data->enable);
}

static ssize_t apds9900_store_enable1(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct apds9900_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
 
    int ret = 0;
    unsigned int value = 0;

    sscanf(buf, "%d\n", &value);

    if (value == 0)
        ret = apds9900_set_enable(client, 0); 
    else if (value ==1)
        ret = apds9900_set_enable(client, 0x2F); 
    else
    {
    	if(apds9900_debug_mask & APDS9900_DEBUG_ERROR_CHECK)
            DEBUG_MSG("0 : off, 1 : on \n");
    }

    if (ret < 0)
        return ret;

    return count;
}

static ssize_t apds9900_show_proximity_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct apds9900_data *data = dev_get_drvdata(dev);
	unsigned int enable = 0;

	if((data->enable==0x3f)||(data->enable==0x2f))
		enable = 1;
	else
		enable = 0;

    return sprintf(buf, "%x\n", enable);
}

static ssize_t apds9900_store_proximity_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct apds9900_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;

 
    int ret = 0;
    
    unsigned long value = simple_strtoul(buf, NULL, 10);

	if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
	    DEBUG_MSG(KERN_INFO "### apds9900_store_proximity_enable value=%d\n", (int)value);


    if (value == 0)
        ret = apds9900_set_enable(client, (data->enable & 0x10)?0x1f:0); 
    else if (value ==1)
        ret = apds9900_set_enable(client, 0x2F|data->enable); 
    else
	{
		if(apds9900_debug_mask & APDS9900_DEBUG_ERROR_CHECK)
			DEBUG_MSG("0 : off, 1 : on \n");
	}

    if (ret < 0)
        return ret;

    return count;
}

static ssize_t apds9900_show_als_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct apds9900_data *data = dev_get_drvdata(dev);
	unsigned int enable = 0;

	if((data->enable==0x3f)||(data->enable==0x1f))
		enable = 1;
	else
		enable = 0;

    return sprintf(buf, "%x\n", enable);

}

static ssize_t apds9900_store_als_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct apds9900_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;

    int ret = 0;
    
    unsigned long value = simple_strtoul(buf, NULL, 10);

	if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
	    DEBUG_MSG(KERN_INFO "### apds9900_store_als_enable value=%d\n", (int)value);

    if (value == 0)
        ret = apds9900_set_enable(client, (data->enable & 0x20)?0x2f:0); 
    else if (value ==1)
        ret = apds9900_set_enable(client, 0x1F|data->enable); 
    else
	{
		if(apds9900_debug_mask & APDS9900_DEBUG_ERROR_CHECK)
			DEBUG_MSG("0 : off, 1 : on \n");
	}

    if (ret < 0)
        return ret;

    return count;
}

static ssize_t apds9900_show_als_data(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct apds9900_data *data = dev_get_drvdata(dev);

    return sprintf(buf, "%x\n", data->als_data);
}

static ssize_t apds9900_store_als_data(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)											 
{
	struct apds9900_data *data = dev_get_drvdata(dev);
	
    unsigned int value = 0;

    sscanf(buf, "%d\n", &value);
    input_report_abs(data->input_dev_light, ABS_LIGHT, value); //report als data
    input_sync(data->input_dev_light);

    return count;
}


static DEVICE_ATTR(enable1, S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_enable1, apds9900_store_enable1);

static DEVICE_ATTR(proximity_enable, S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_proximity_enable, apds9900_store_proximity_enable);

static DEVICE_ATTR(light_enable, S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_als_enable, apds9900_store_als_enable);

static DEVICE_ATTR(als, S_IWUSR | S_IRUGO | S_IRGRP | S_IROTH , apds9900_show_als_data, apds9900_store_als_data);

static ssize_t apds9900_show_proximity(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct i2c_client *client = to_i2c_client(dev);
    struct apds9900_data *data = i2c_get_clientdata(client);
    int pdata = 0;
    
    pdata = data->ps_detection;
    
    if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
		DEBUG_MSG("[%s]  pdata = %d \n",__func__, pdata);
        
    return sprintf(buf, "%x\n", pdata);
}
static DEVICE_ATTR(proximity, S_IRUGO | S_IRGRP | S_IROTH, apds9900_show_proximity, NULL);

static struct attribute *apds9900_attributes[] =
{
    &dev_attr_command.attr,
    &dev_attr_enable.attr,
    &dev_attr_atime.attr,
    &dev_attr_ptime.attr,
    &dev_attr_wtime.attr,
    &dev_attr_ailt.attr,
    &dev_attr_aiht.attr,
    &dev_attr_pilt.attr,
    &dev_attr_piht.attr,
    &dev_attr_pers.attr,
    &dev_attr_config.attr,
    &dev_attr_ppcount.attr,
    &dev_attr_control.attr,
    &dev_attr_rev.attr,
    &dev_attr_id.attr,
    &dev_attr_status.attr,
    &dev_attr_cdata.attr,
    &dev_attr_irdata.attr,
    &dev_attr_pdata.attr,
    &dev_attr_prox.attr,
    &dev_attr_enable1.attr,
    &dev_attr_proximity.attr,
    &dev_attr_als.attr,
    NULL
};

static const struct attribute_group apds9900_attr_group =
{
    .attrs = apds9900_attributes,
};

/*
 * Initialization function
 */
static int apds9900_device_parameter_init(struct i2c_client *client)
{
	struct apds9900_platform_data* pdata = client->dev.platform_data;
	
    if(apds9900_debug_mask & APDS9900_DEBUG_DEV_STATUS)
	    DEBUG_MSG("apds9900 device paremeter (re)init .\n");

    apds9900_set_wtime(client, 0xFF);   /* 0xFF : WAIT=2.72ms */
    apds9900_set_control(client, 0x20); /* 100mA, IR-diode, 1X PGAIN,  1X AGAIN */
    apds9900_set_config(client, 0x00);  /* unless they need to use wait time more than > 700ms */

    /* ALS tuning */
    apds9900_set_atime(client, 0xDE);   /* ALS = 100ms , MAX count = 37888 */

    /* proximity tuning */
    apds9900_set_ptime(client, 0xFF);   /* recommended value. don't change it unless there's proper reason PTIME = 2.72ms, MAX count = 1023 */
    apds9900_set_ppcount(client, pdata->ppcount);  /* use 8-pulse should be enough for evaluation */

    /* interrupt tuning */
	//apds9900_set_pers(client, 0x33);	// 3 consecutive Interrupt persistence
	apds9900_set_pers(client, 0x14);	// 1 consecutive Interrupt persistence
	apds9900_set_pilt(client, 1023);	// to force first Near-to-Far interrupt
	apds9900_set_piht(client, 0);
	papds9900_data->ps_detection = 1;			// we are forcing Near-to-Far interrupt, so this is defaulted to 1
	papds9900_data->ps_threshold = APDS990x_PS_DETECTION_THRESHOLD;
	papds9900_data->ps_hysteresis_threshold = APDS990x_PS_HSYTERESIS_THRESHOLD;
	// sensor is in disabled mode but all the configurations are preset
    return 0;
}

static int apds9900_device_init(struct i2c_client *client)
{
    apds9900_set_enable(client, 0);
    
    apds9900_device_parameter_init(client);
    
  /* kwangdo.yi@lge.com 2010.08.31
     * leave out to UI scenario, turn apds on/off from app, telephony etc.
     */
	if(apds9900_debug_mask & APDS9900_DEBUG_DEV_STATUS)
	    DEBUG_MSG("apds9900 device (re)init finished.\n");
    
    return 0;
}

/* kwangdo.yi@lge.com 10.09.17 S
 * add to support ioctl to sensor HAL 
 */

static int apds_open(struct inode *inode, struct file *file)
{
	if(apds9900_debug_mask & APDS9900_DEBUG_DEV_STATUS)
	    DEBUG_MSG("### apds open \n");

    return 0;
}

static int apds_release(struct inode *inode, struct file *file)
{
	if(apds9900_debug_mask & APDS9900_DEBUG_DEV_STATUS)
	    DEBUG_MSG("### apds release \n");

    return 0;
}

static struct file_operations apds_fops =
{
    .owner = THIS_MODULE,
    .open = apds_open,
    .release = apds_release,
};

static struct miscdevice apds_device =
{
    .minor = MISC_DYNAMIC_MINOR,
    .name = "apds9900",
    .fops = &apds_fops,
};

/*
 * I2C init/probing/exit functions
 */
static struct i2c_driver apds9900_driver;
static int __devinit apds9900_probe(struct i2c_client *client,
                                    const struct i2c_device_id *id)
{
    struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
    struct apds9900_platform_data* pdata = client->dev.platform_data;
	int err = 0;
    int irq;

    if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE))
    {
        err = -EIO;
        goto exit;
    }
    
    papds9900_data = kzalloc(sizeof(struct apds9900_data), GFP_KERNEL);
    if (!papds9900_data)
    {
        err = -ENOMEM;
        goto exit;
    }
    
    papds9900_data->client = client;
    i2c_set_clientdata(client, papds9900_data);
    
#ifdef APDS9900_USE_MUTEX
    mutex_init(&papds9900_data->lock);
#endif
    papds9900_data->enable = 0;	/* default mode is standard */
    papds9900_data->ps_detection = 0; /* default to no detection == far */    
	papds9900_data->ps_threshold = 0;
	papds9900_data->ps_hysteresis_threshold = 0;
	
    dev_info(&client->dev, "enable = %s\n", papds9900_data->enable ? "1" : "0");

    pdata->power(1);
	mdelay(10);


    err = sysfs_create_group(&client->dev.kobj, &apds9900_attr_group);
    if (err)
        goto exit_kfree;

    dev_info(&client->dev, "support ver. %s enabled\n", DRIVER_VERSION);

    INIT_DELAYED_WORK(&papds9900_data->poswork, apds9900_event_work);
    
    err = gpio_request(pdata->irq_num, "apds_irq");
    if (err)
    {
        printk(KERN_ERR"Unable to request GPIO.\n");
        goto exit_kfree;
    }
    
    gpio_tlmm_config(GPIO_CFG(pdata->irq_num, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_UP, GPIO_CFG_2MA), GPIO_CFG_ENABLE); 
    gpio_direction_input(pdata->irq_num);
    irq = gpio_to_irq(pdata->irq_num);
    
    if (irq < 0)
    {
        err = irq;
        printk(KERN_ERR"Unable to request gpio irq. err=%d\n", err);
        gpio_free(pdata->irq_num);
        
        goto exit_kfree;
    }
    
    papds9900_data->irq = irq;
    err = request_irq(papds9900_data->irq, apds9900_isr, IRQF_TRIGGER_FALLING, ALS_SENSOR_NAME, papds9900_data);
    if (err)
    {
        printk(KERN_ERR"Unable to request irq.\n");
        
        goto exit_kfree;
    }

    papds9900_data->input_dev_proxi = input_allocate_device();
    if (!papds9900_data->input_dev_proxi)
    {
        err = -ENOMEM;
        printk("### apds9900_probe: Failed to allocate input device\n");
    }
    
    set_bit(EV_ABS, papds9900_data->input_dev_proxi->evbit);
    
    /* distance data  */
    input_set_abs_params(papds9900_data->input_dev_proxi, ABS_DISTANCE, 0, 10, 0, 0);

    /* add light input event */	
    papds9900_data->input_dev_proxi->name = "proximity";
    
    err = input_register_device(papds9900_data->input_dev_proxi);
    if (err) 
        printk("### apds9900_probe: Unable to register input device: %s\n",papds9900_data->input_dev_proxi->name);

    papds9900_data->input_dev_light = input_allocate_device();
    if (!papds9900_data->input_dev_light)
    {
        err = -ENOMEM;
        printk("### apds9900_probe: Failed to allocate input device\n");
    }
    
    set_bit(EV_ABS, papds9900_data->input_dev_light->evbit);
    input_set_abs_params(papds9900_data->input_dev_light, ABS_LIGHT, 0, ABS_MAX, 0, 0);

    /* add light input event */	
    papds9900_data->input_dev_light->name = "light";
    
    err = input_register_device(papds9900_data->input_dev_light);
    if (err) 
        printk("### apds9900_probe: Unable to register input device: %s\n",papds9900_data->input_dev_light->name);
       
    err = misc_register(&apds_device);
    if (err)
    {
        printk("### apds_probe: apds_device misc_register failed\n");
    }

	err = device_create_file(&papds9900_data->input_dev_proxi->dev, &dev_attr_proximity_enable);
	err = device_create_file(&papds9900_data->input_dev_proxi->dev, &dev_attr_proximity);
	
	if (err) {
		printk("### apds_probe: Proximity device_create_file failed\n");
		goto  exit_kfree;
	}

	input_set_drvdata(papds9900_data->input_dev_proxi, papds9900_data);
	dev_set_drvdata(&papds9900_data->input_dev_proxi->dev, papds9900_data);

	if (err) {
		printk("### apds_probe: Proximity device_create_file failed\n");
		goto  exit_kfree;
	}
	
	err = device_create_file(&papds9900_data->input_dev_light->dev, &dev_attr_light_enable);
	err = device_create_file(&papds9900_data->input_dev_light->dev, &dev_attr_als);
		
	if (err) {
		printk("### apds_probe: light device_create_file failed\n");
		goto  exit_kfree;
	}
	
	input_set_drvdata(papds9900_data->input_dev_light, papds9900_data);
	dev_set_drvdata(&papds9900_data->input_dev_light->dev, papds9900_data);

	apds9900_device_init(client);

#ifdef CONFIG_HAS_EARLYSUSPEND
	apds9900_sensor_early_suspend.suspend = apds9900_early_suspend;
	apds9900_sensor_early_suspend.resume = apds9900_late_resume;
	apds9900_sensor_early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN - 45;
	register_early_suspend(&apds9900_sensor_early_suspend);
#endif

	device_init_wakeup(&client->dev, 1);
	enable_irq_wake(papds9900_data->irq);

    return 0;

exit_kfree:
    kfree(papds9900_data);
exit:
    return err;
}

static int __devexit apds9900_remove(struct i2c_client *client)
{
    struct apds9900_data *data = i2c_get_clientdata(client);

	disable_irq_wake(client->irq);
	free_irq(client->irq, data);
	cancel_work_sync(&data->poswork.work);

    sysfs_remove_group(&client->dev.kobj, &apds9900_attr_group);
	device_remove_file(&papds9900_data->input_dev_proxi->dev, &dev_attr_proximity_enable);
	device_remove_file(&papds9900_data->input_dev_proxi->dev, &dev_attr_proximity);
	device_remove_file(&papds9900_data->input_dev_light->dev, &dev_attr_light_enable);
	device_remove_file(&papds9900_data->input_dev_light->dev, &dev_attr_als);
	
	input_unregister_device(papds9900_data->input_dev_proxi);
	input_unregister_device(papds9900_data->input_dev_light);

    /* Power down the device */
    apds9900_set_enable(client, 0);

    kfree(i2c_get_clientdata(client));

    return 0;
}

#ifdef CONFIG_HAS_EARLYSUSPEND
unsigned int apds9900_enable_backup = 0;

static void apds9900_early_suspend(struct early_suspend * h)
{
   // Temporary for current consumption, ALC is not controlled by Frameworks
	if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
		DEBUG_MSG("### %s, do nothing..\n", __func__);
}

static void apds9900_late_resume(struct early_suspend * h)
{
  // Temporary for current consumption, ALC is not controlled by Frameworks
	if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
		DEBUG_MSG("### %s, do nothoing..\n", __func__);
}
#endif /* CONFIG_HAS_EARLYSUSPEND */

#ifdef CONFIG_PM
static int apds9900_suspend(struct device *device)
{
	struct apds9900_platform_data* pdata = (struct apds9900_platform_data* )device->platform_data;

	if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
		DEBUG_MSG("### apds9900_suspend, papds9900_data->enable=%d\n", papds9900_data->enable);

#ifdef APDS9900_USE_MUTEX
#else
	set_irq_wake(papds9900_data->client->irq, 0);
	disable_irq(papds9900_data->client->irq);
#endif

	apds9900_enable_backup = papds9900_data->enable;

	if(papds9900_data->enable == 0x3F || papds9900_data->enable == 0x2F)
	{
		apds9900_set_enable(papds9900_data->client, 0x2F);
	}
	else 
	{
		apds9900_set_enable(papds9900_data->client, 0);
		pdata->power(0);
	}

#ifdef APDS9900_USE_MUTEX
	mutex_lock(&papds9900_data->lock);
#endif
	return 0;
}

static int apds9900_resume(struct device *device)
{
	struct apds9900_platform_data* pdata = (struct apds9900_platform_data* )device->platform_data;
#ifdef APDS9900_USE_MUTEX
	mutex_unlock(&papds9900_data->lock);
#endif

	if(apds9900_debug_mask & APDS9900_DEBUG_GEN_INFO)
		DEBUG_MSG("### apds9900_resume, papds9900_data->enable=%d, enable_backup=%d\n", papds9900_data->enable,apds9900_enable_backup);

	if(papds9900_data->enable != 0x2F)
	{
		pdata->power(1);
		mdelay(10);
	}

	//if(papds9900_data->enable != apds9900_enable_backup)
	//if((papds9900_data->enable == 0x2F)||(papds9900_data->enable ==0))
	apds9900_set_enable(papds9900_data->client, apds9900_enable_backup);

#ifdef APDS9900_USE_MUTEX
#else
	enable_irq(papds9900_data->client->irq);
	set_irq_wake(papds9900_data->client->irq, 1);
#endif

	return 0;
}
#endif


static const struct i2c_device_id apds9900_id[] =
{
    { "apds9900", 0 },
    { }
};
MODULE_DEVICE_TABLE(i2c, apds9900_id);

#if defined(CONFIG_PM)
static struct dev_pm_ops apds9900_pm_ops = {
	.suspend = apds9900_suspend,
	.resume = apds9900_resume,
};
#endif


static struct i2c_driver apds9900_driver =
{
    .driver = 
    {
        .name   = APDS9900_DRV_NAME,
        .owner  = THIS_MODULE,
#if defined(CONFIG_PM)
	.pm = &apds9900_pm_ops,
#endif
        
    },
    .probe      = apds9900_probe,
    .remove     = __devexit_p(apds9900_remove),
    .id_table   = apds9900_id,
};

static int __init apds9900_init(void)
{
    apds9900_workqueue = create_workqueue("proximity_als");

    if(!apds9900_workqueue)
       return -ENOMEM;

    return i2c_add_driver(&apds9900_driver);
}

static void __exit apds9900_exit(void)
{
    if(apds9900_workqueue)
       destroy_workqueue(apds9900_workqueue);

    apds9900_workqueue = NULL;
    i2c_del_driver(&apds9900_driver);
}

MODULE_AUTHOR("Lee Kai Koon <kai-koon.lee@avagotech.com>");
MODULE_DESCRIPTION("APDS9900 ambient light + proximity sensor driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);

module_init(apds9900_init);
module_exit(apds9900_exit);
