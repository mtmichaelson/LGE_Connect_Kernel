/* 
 * Copyright (C) 2011 LGE, Inc.
 *
 *  * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <asm/div64.h>
#include <linux/delay.h>
#include <mach/board_lge.h>

#define FILE_OPS

/* k3g chip id */
#define DEVICE_ID	0xD3
/* k3g gyroscope registers */
#define WHO_AM_I	0x0F
#define CTRL_REG1	0x20  /* power control reg */
#define CTRL_REG2	0x21  /* power control reg */
#define CTRL_REG3	0x22  /* power control reg */
#define CTRL_REG4	0x23  /* interrupt control reg */
#define CTRL_REG5	0x24  /* interrupt control reg */
#define OUT_TEMP	0x26  /* Temperature data */
#define STATUS_REG	0x27
#define AXISDATA_REG	0x28
#define OUT_Y_L		0x2A
#define FIFO_CTRL_REG	0x2E
#define FIFO_SRC_REG	0x2F
#define PM_OFF		0x00
#define PM_NORMAL	0x08
#define ENABLE_ALL_AXES	0x07
#define BYPASS_MODE	0x00
#define FIFO_MODE	0x20

#define FIFO_EMPTY	0x20
#define FSS_MASK	0x1F
#define ODR_MASK	0xF0
#define ODR105_BW12_5	0x00  /* ODR = 105Hz; BW = 12.5Hz */
#define ODR105_BW25	0x10  /* ODR = 105Hz; BW = 25Hz   */
#define ODR210_BW12_5	0x40  /* ODR = 210Hz; BW = 12.5Hz */
#define ODR210_BW25	0x50  /* ODR = 210Hz; BW = 25Hz   */
#define ODR210_BW50	0x60  /* ODR = 210Hz; BW = 50Hz   */
#define ODR210_BW70	0x70  /* ODR = 210Hz; BW = 70Hz   */
#define ODR420_BW20	0x80  /* ODR = 420Hz; BW = 20Hz   */
#define ODR420_BW25	0x90  /* ODR = 420Hz; BW = 25Hz   */
#define ODR420_BW50	0xA0  /* ODR = 420Hz; BW = 50Hz   */
#define ODR420_BW110	0xB0  /* ODR = 420Hz; BW = 110Hz  */
#define ODR840_BW30	0xC0  /* ODR = 840Hz; BW = 30Hz   */
#define ODR840_BW35	0xD0  /* ODR = 840Hz; BW = 35Hz   */
#define ODR840_BW50	0xE0  /* ODR = 840Hz; BW = 50Hz   */
#define ODR840_BW110	0xF0  /* ODR = 840Hz; BW = 110Hz  */

#define MIN_ST		175
#define MAX_ST		875
#define AC		(1 << 7) /* register auto-increment bit */
#define MAX_ENTRY	1
#define MAX_DELAY	(MAX_ENTRY * 9523809LL)

#define SELF_TEST_ENABLED 
#ifdef SELF_TEST_ENABLED
#define TAG_ST			"k3g_self_test"
#define ZYXDA_MASK		0x08
#define OUT_X_L			0x28 /* X-axis acceleration data */
#define OUT_X_H			0x29
//#define OUT_Y_L			0x2A /* Y-axis acceleration data */
#define OUT_Y_H			0x2B
#define OUT_Z_L			0x2C /* Z-axis acceleration data */
#define OUT_Z_H			0x2D
#define SENSITIVITY		70	/*70 for 2000dps, 17.50 for 500dps, 8.75dps for 250dps */
#define MIN_ST_X			175
#define MAX_ST_X			875
#define MIN_ST_Y			MIN_ST_X
#define MAX_ST_Y			MAX_ST_X
#define MIN_ST_Z			MIN_ST_X
#define MAX_ST_Z			MAX_ST_X
#endif
#define DRV_NAME    "k3g"

/* LGE Debug mask value
	* usage: echo [mask_value] > /sys/module/k3dh/parameters/debug_mask
	* All      : 127
	* No msg   : 0
	* default  : 2
*/
enum {
	DEBUG_ERR_CHECK     = 1U << 0,
	DEBUG_USER_ERROR    = 1U << 1,
	DEBUG_FUNC_TRACE    = 1U << 2,
	DEBUG_DEV_STATUS    = 1U << 3,
	DEBUG_DEV_DEBOUNCE  = 1U << 4,
	DEBUG_GEN_INFO      = 1U << 5,
	DEBUG_INTR_INFO     = 1U << 6,
	DEBUG_DEBUG_SYSFS   = 1U << 7,
};

static unsigned int debug_mask = DEBUG_USER_ERROR;

module_param_named(debug_mask, debug_mask, int,
		       S_IRUGO | S_IWUSR | S_IWGRP);

/* default register setting for device init */
static const char default_ctrl_regs[] = {
	0x3F,	/* 105HZ, PM-normal, xyz enable */
	0x00,	/* normal mode */
	0x04,	/* fifo wtm interrupt on */
	0xA0,	/* block data update, 2000d/s */
	0x40,	/* fifo enable */
};

static const struct odr_delay {
	u8 odr; /* odr reg setting */
	u32 delay_ns; /* odr in ns */
} odr_delay_table[] = {
	{  ODR840_BW110, 1190476LL }, /* 840Hz */
	{  ODR420_BW110, 2380952LL }, /* 420Hz */
	{   ODR210_BW70, 4761904LL }, /* 210Hz */
	{   ODR105_BW25, 9523809LL }, /* 105Hz */
};

/*
 * K3G gyroscope data
 * brief structure containing gyroscope values for yaw, pitch and roll in
 * signed short
 */
struct k3g_t {
	s16 x;
	s16 y;
	s16 z;
};

struct k3g_data {
	struct i2c_client *client;
	struct input_dev *input_dev;
	struct mutex lock;
	struct workqueue_struct *k3g_wq;
	struct work_struct work;
	struct hrtimer timer;
	bool enable;
	bool drop_next_event;
	bool interruptible;	/* interrupt or polling? */
	int entries;		/* number of fifo entries */
	u8 ctrl_regs[5];	/* saving register settings */
	u32 time_to_read;	/* time needed to read one entry */
	ktime_t polling_delay;	/* polling time for timer */
};
static struct i2c_client *k3g_i2c_client = NULL;

#ifdef FILE_OPS
#define	K3G_IOCTL_BASE 80
/** The following define the IOCTL command values via the ioctl macros */
#define	K3G_IOCTL_READ_DATA_XYZ		_IOW(K3G_IOCTL_BASE, 0, int)

static int k3g_gyro_data[3];
#endif
static u32 report_cnt = 0;
static int k3g_read_fifo_status(struct k3g_data *k3g_data)
{
	int fifo_status;

	fifo_status = i2c_smbus_read_byte_data(k3g_data->client, FIFO_SRC_REG);

	if(DEBUG_DEV_STATUS & debug_mask || fifo_status < k3g_data->entries)
		printk(KERN_ERR "[k3g] #### fifo_status=%d, entries=%d\n", fifo_status, k3g_data->entries);

	if (fifo_status < 0) {
		pr_err("%s: failed to read fifo source register\n",	__func__);
		return fifo_status;
	}
	return (fifo_status & FSS_MASK) + !(fifo_status & FIFO_EMPTY);
}

static int k3g_restart_fifo(struct k3g_data *k3g_data)
{
	int res = 0;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);


	res = i2c_smbus_write_byte_data(k3g_data->client,
			FIFO_CTRL_REG, BYPASS_MODE);
	if (res < 0) {
		pr_err("%s : failed to set bypass_mode\n", __func__);
		return res;
	}

	res = i2c_smbus_write_byte_data(k3g_data->client,
			FIFO_CTRL_REG, FIFO_MODE | (k3g_data->entries - 1));

	if (res < 0)
		pr_err("%s : failed to set fifo_mode\n", __func__);

	return res;
}

static void set_polling_delay(struct k3g_data *k3g_data, int res)
{
	s64 delay_ns;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	delay_ns = k3g_data->entries + 1 - res;
	if (delay_ns < 0)
		delay_ns = 0;

	delay_ns = delay_ns * k3g_data->time_to_read;
	k3g_data->polling_delay = ns_to_ktime(delay_ns);
}

/* gyroscope data readout */
static int k3g_read_gyro_values(struct i2c_client *client,
				struct k3g_t *data, int total_read)
{
	int err;
	struct i2c_msg msg[2];
	u8 reg_buf;
	u8 gyro_data[sizeof(*data) * (total_read ? (total_read - 1) : 1)];
	struct k3g_platform_data *pdata;
	s16 tmp_xyz[3];

	pdata = client->dev.platform_data;
	if(pdata == NULL) 
	{
	    dev_err(&client->dev, "failed to read platform data\n");
		err = -ENODEV;
		return err;
	}

	msg[0].addr = client->addr;
	msg[0].buf = &reg_buf;
	msg[0].flags = 0;
	msg[0].len = 1;

	msg[1].addr = client->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].buf = gyro_data;

	if (total_read > 1) {
		reg_buf = AXISDATA_REG | AC;
		msg[1].len = sizeof(gyro_data);

		err = i2c_transfer(client->adapter, msg, 2);
		if (err != 2)
			return (err < 0) ? err : -EIO;
	}

	reg_buf = AXISDATA_REG;
	msg[1].len = 1;
	err = i2c_transfer(client->adapter, msg, 2);
	if (err != 2)
		return (err < 0) ? err : -EIO;

	reg_buf = OUT_Y_L | AC;
	msg[1].len = sizeof(*data);
	err = i2c_transfer(client->adapter, msg, 2);
	if (err != 2)
		return (err < 0) ? err : -EIO;

	tmp_xyz[1] = (gyro_data[1] << 8) | gyro_data[0];
	tmp_xyz[2] = (gyro_data[3] << 8) | gyro_data[2];
	tmp_xyz[0] = (gyro_data[5] << 8) | gyro_data[4];
	
	data->y = (pdata->negate_y) ? (-tmp_xyz[pdata->axis_map_y]) : (tmp_xyz[pdata->axis_map_y]);
	data->z = (pdata->negate_z) ? (-tmp_xyz[pdata->axis_map_z]) : (tmp_xyz[pdata->axis_map_z]);
	data->x = (pdata->negate_x) ? (-tmp_xyz[pdata->axis_map_x]) : (tmp_xyz[pdata->axis_map_x]);

	return 0;
}

static int k3g_report_gyro_values(struct k3g_data *k3g_data)
{
	int res;
	struct k3g_t data;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	res = k3g_read_gyro_values(k3g_data->client, &data,
				k3g_data->entries + k3g_data->drop_next_event);
	if (res < 0)
		return res;

	res = k3g_read_fifo_status(k3g_data);

	if(DEBUG_DEV_STATUS& debug_mask)
		printk(KERN_INFO "[k3g] read_fifo_status(%d)\n", res);

	k3g_data->drop_next_event = !res;

	if(DEBUG_DEV_STATUS& debug_mask)
		printk(KERN_INFO "[k3g] entries=%d\n", k3g_data->entries);
	if (res >= 31 - k3g_data->entries) {
		/* reset fifo to start again - data isn't trustworthy,
		 * our locked read might not have worked and we
		 * could have done i2c read in mid register update
		 */	
		if(DEBUG_DEV_STATUS& debug_mask)
			printk(KERN_INFO "[k3g] call restart_fifo, entries=%d\n", k3g_data->entries);
		return k3g_restart_fifo(k3g_data);
	}

#ifndef CONFIG_LGE_SENSOR_FUSION
	input_report_rel(k3g_data->input_dev, REL_RX, data.x);
	input_report_rel(k3g_data->input_dev, REL_RY, data.y);
	input_report_rel(k3g_data->input_dev, REL_RZ, data.z);
	input_sync(k3g_data->input_dev);
#else
	k3g_gyro_data[0] = (int) data.x;
	k3g_gyro_data[1] = (int) data.y;
	k3g_gyro_data[2] = (int) data.z;
#endif
	if(DEBUG_DEV_DEBOUNCE & debug_mask)
		printk(KERN_INFO "%s: [k3g] x(%d), y(%d), z(%d)\n", __func__, data.x, data.y, data.z);
	report_cnt++;
	return res;
}

static enum hrtimer_restart k3g_timer_func(struct hrtimer *timer)
{
	struct k3g_data *k3g_data = container_of(timer, struct k3g_data, timer);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	queue_work(k3g_data->k3g_wq, &k3g_data->work);
	return HRTIMER_NORESTART;
}

static void k3g_work_func(struct work_struct *work)
{
	int res;
	struct k3g_data *k3g_data = container_of(work, struct k3g_data, work);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	if(k3g_data->enable == 0)
	{
       return;
	}

	do {
		res = k3g_read_fifo_status(k3g_data);
		if (res < 0)
			return;

		if (res < k3g_data->entries) {
			pr_warn("%s: fifo entries are less than we want\n",
								__func__);
			goto timer_set;
		}

		res = k3g_report_gyro_values(k3g_data);
		if (res < 0)
			return;
timer_set:
		set_polling_delay(k3g_data, res);

	} while (!ktime_to_ns(k3g_data->polling_delay));

	hrtimer_start(&k3g_data->timer,
		k3g_data->polling_delay, HRTIMER_MODE_REL);
}

static irqreturn_t k3g_interrupt_thread(int irq, void *k3g_data_p)
{
	int res;
	struct k3g_data *k3g_data = k3g_data_p;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	res = k3g_report_gyro_values(k3g_data);
	if (res < 0)
	{
		pr_err("%s: failed to report gyro values\n", __func__);
    }

	return IRQ_HANDLED;
}

static ssize_t k3g_show_enable(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct k3g_data *k3g_data  = dev_get_drvdata(dev);
	if(DEBUG_DEBUG_SYSFS & debug_mask)
		printk(KERN_INFO "%s: enable(%d)\n", __func__, k3g_data->enable);

	return sprintf(buf, "%d\n", k3g_data->enable);
}

static ssize_t k3g_set_enable(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	int err = 0;
	struct k3g_platform_data *pdata;
	bool new_enable;
	struct k3g_data *k3g_data  = dev_get_drvdata(dev);
	struct i2c_client *client = to_i2c_client(dev);

	pdata = k3g_i2c_client->dev.platform_data;
	if(pdata == NULL) 
	{
	    dev_err(&client->dev, "failed to read platform data\n");
		err = -ENODEV;
		return err;
	}

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d - enable %s\n", __func__, __LINE__, buf);

	if (sysfs_streq(buf, "1"))
	{
		new_enable = true;
		if(DEBUG_FUNC_TRACE & debug_mask||DEBUG_DEBUG_SYSFS & debug_mask)		
			printk(KERN_INFO "%s: line %d - enable\n", __func__, __LINE__);
    }
	else if (sysfs_streq(buf, "0"))
	{
		new_enable = false;
		if(DEBUG_FUNC_TRACE & debug_mask||DEBUG_DEBUG_SYSFS & debug_mask)
			printk(KERN_INFO "%s: line %d - disable\n", __func__, __LINE__);
	}
	else 
	{
		pr_debug("%s: invalid value %d\n", __func__, *buf);
		return -EINVAL;
	}

	if (new_enable == k3g_data->enable)
	{
		return size;
	}

	mutex_lock(&k3g_data->lock);

	if (new_enable) 
	{
		if(pdata->power_on){
			if(DEBUG_FUNC_TRACE & debug_mask)
				printk(KERN_INFO "%s: line %d, call power_on", __func__, __LINE__);
			pdata->power_on(1<<SENSOR_TYPE_GYROSCOPE);
			mdelay(1);
		}
		/* turning on */
		err = i2c_smbus_write_i2c_block_data(k3g_data->client,
			CTRL_REG1 | AC, sizeof(k3g_data->ctrl_regs),
						k3g_data->ctrl_regs);
		if (err < 0) 
		{
			err = -EIO;
			if(DEBUG_FUNC_TRACE & debug_mask)
				printk(KERN_INFO "%s: line %d, failed turn on\n", __func__, __LINE__);
			
			goto unlock;
		}

		mdelay(300);
		
		/* reset fifo entries */
		err = k3g_restart_fifo(k3g_data);
		if (err < 0) 
		{
			err = -EIO;
			goto turn_off;
		}

		if (k3g_data->interruptible)
		{
			enable_irq(k3g_data->client->irq);
			if(DEBUG_FUNC_TRACE & debug_mask)
				printk(KERN_INFO "%s: line %d, enable interrupt\n", __func__, __LINE__);
		}
		else 
		{
			set_polling_delay(k3g_data, 0);
			hrtimer_start(&k3g_data->timer,
				k3g_data->polling_delay, HRTIMER_MODE_REL);
				if(DEBUG_FUNC_TRACE & debug_mask)
					printk(KERN_INFO "%s: line %d, set_polling_delay\n", __func__, __LINE__);
		}
		report_cnt = 0;
	}
	else 
	{
	
		if (k3g_data->interruptible)
		{
			printk(KERN_INFO "%s: line %d -disable_irq\n", __func__, __LINE__);
			disable_irq(k3g_data->client->irq);
		}
		else 
		{
			printk(KERN_INFO "%s: line %d - cancel timer\n", __func__, __LINE__);
			hrtimer_cancel(&k3g_data->timer);
			cancel_work_sync(&k3g_data->work);
			flush_workqueue(k3g_data->k3g_wq);
		}
		/* turning off */
		err = i2c_smbus_write_byte_data(k3g_data->client,
						CTRL_REG1, 0x00);
		if (err < 0)
		{	
			printk(KERN_INFO "%s: line %d - i2c error\n", __func__, __LINE__);
			goto unlock;
		}
	}
	k3g_data->enable = new_enable;

turn_off:
	if (err < 0)
		i2c_smbus_write_byte_data(k3g_data->client,
						CTRL_REG1, 0x00);
unlock:
	mutex_unlock(&k3g_data->lock);

	return err ? err : size;
}

#ifdef FILE_OPS
static int k3g_misc_open(struct inode *inode, struct file *file)
{
    int err;
	
    err = nonseekable_open(inode, file);
    if (err < 0)
	return err;

    if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line:%d",__func__, __LINE__);
	
    file->private_data = NULL;

    return 0;
}

static int k3g_misc_ioctl(struct inode *inode, struct file *file,
		unsigned int cmd, unsigned long arg)
{
    void __user *argp = (void __user *)arg;

    if(DEBUG_FUNC_TRACE & debug_mask)
	printk(KERN_INFO "%s: %s call with cmd 0x%x and arg 0x%x\n",
		DRV_NAME, __func__, cmd, (unsigned int)arg);

    switch (cmd) {
	case K3G_IOCTL_READ_DATA_XYZ:
		if (copy_to_user(argp, k3g_gyro_data, sizeof(int)*3)){
			printk(KERN_ERR "%s: %s error in copy_to_user \n",
					DRV_NAME, __func__);
			return -EINVAL;
		}
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static const struct file_operations k3g_misc_fops = {
		.owner = THIS_MODULE,
		.open = k3g_misc_open,
		.ioctl = k3g_misc_ioctl,
};

static struct miscdevice k3g_misc_device = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = DRV_NAME "_misc",
		.fops = &k3g_misc_fops,
};
#endif

static ssize_t k3g_show_gyro_data(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	char strbuf[256];
	struct k3g_data *k3g_data  = dev_get_drvdata(dev);
	if(DEBUG_DEBUG_SYSFS & debug_mask)
	{
		if(k3g_data->enable)	
			printk(KERN_INFO "%s: %d, %d, %d\n", __func__, k3g_gyro_data[0], k3g_gyro_data[1], k3g_gyro_data[2]);
		else
			printk(KERN_INFO "%s: %d, %d, %d\n", __func__, -1, -1, -1);	
	}
	if(k3g_data->enable)
		sprintf(strbuf, "%d %d %d", k3g_gyro_data[0], k3g_gyro_data[1], k3g_gyro_data[2]);
	else
		sprintf(strbuf, "%d %d %d", -1, -1, -1);
	return sprintf(buf, "%s\n", strbuf);
}
static ssize_t k3g_show_delay(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct k3g_data *k3g_data  = dev_get_drvdata(dev);
	u64 delay;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);
	delay = k3g_data->time_to_read * k3g_data->entries;
	delay = ktime_to_ns(ns_to_ktime(delay));

	return sprintf(buf, "%lld\n", delay);
}

static ssize_t k3g_set_delay(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct k3g_data *k3g_data  = dev_get_drvdata(dev);
	int odr_value = ODR105_BW25;
	int res = 0;
	int i;
	u64 delay_ns;
	u8 ctrl;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);
    
	res = strict_strtoll(buf, 10, &delay_ns);
	if (res < 0)
		return res;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	mutex_lock(&k3g_data->lock);
	if (!k3g_data->interruptible)
		hrtimer_cancel(&k3g_data->timer);
	else
		disable_irq(k3g_data->client->irq);

	/* round to the nearest supported ODR that is less than
	 * the requested value
	 */
	for (i = 0; i < ARRAY_SIZE(odr_delay_table); i++)
		if (delay_ns <= odr_delay_table[i].delay_ns) 
		{
			odr_value = odr_delay_table[i].odr;
			delay_ns = odr_delay_table[i].delay_ns;
			k3g_data->time_to_read = delay_ns;
			k3g_data->entries = 1;
			break;
		}

	if (delay_ns >= odr_delay_table[3].delay_ns) 
	{
		if (delay_ns >= MAX_DELAY) 
		{
			k3g_data->entries = MAX_ENTRY;
			delay_ns = MAX_DELAY;
		} 
		else 
		{
			do_div(delay_ns, odr_delay_table[3].delay_ns);
			k3g_data->entries = delay_ns;
		}
		k3g_data->time_to_read = odr_delay_table[3].delay_ns;
	}

	if (odr_value != (k3g_data->ctrl_regs[0] & ODR_MASK)) {
		ctrl = (k3g_data->ctrl_regs[0] & ~ODR_MASK);
		ctrl |= odr_value;
		k3g_data->ctrl_regs[0] = ctrl;
		res = i2c_smbus_write_byte_data(k3g_data->client,
						CTRL_REG1, ctrl);
	}

	/* we see a noise in the first sample or two after we
	 * change rates.  this delay helps eliminate that noise.
	 */
	msleep((u32)delay_ns * 2 / NSEC_PER_MSEC);

	/* (re)start fifo */
	k3g_restart_fifo(k3g_data);

	if (!k3g_data->interruptible) 
	{
		delay_ns = k3g_data->entries * k3g_data->time_to_read;
		k3g_data->polling_delay = ns_to_ktime(delay_ns);
		if (k3g_data->enable)
			hrtimer_start(&k3g_data->timer,
				k3g_data->polling_delay, HRTIMER_MODE_REL);
	} 
	else
	{
		enable_irq(k3g_data->client->irq);
    }

	mutex_unlock(&k3g_data->lock);

	return size;
}

#ifdef SELF_TEST_ENABLED
bool st_result = false;
static ssize_t k3g_show_st_result(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	if(DEBUG_DEV_STATUS & debug_mask)
		printk(KERN_INFO "%s: st_result(%d)\n", __func__, st_result);
	return sprintf(buf, "%d\n", st_result);
}
#define NUM_SAMPLE	5
#define K3G_ABS(a)	(((a)<0)?-(a):(a))
static ssize_t k3g_run_self_test(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	int err=0, i=0, j=0, tmp1=0, tmp2=0;
	bool ret=0;
	struct i2c_client *client = to_i2c_client(dev);
	struct k3g_data *k3g_data = i2c_get_clientdata(client);
	struct k3g_platform_data *pdata;
	int out_nost_x[NUM_SAMPLE], out_nost_y[NUM_SAMPLE], out_nost_z[NUM_SAMPLE];
	int avg_out_nost_x=0, avg_out_nost_y=0, avg_out_nost_z=0, sum_nost_x=0, sum_nost_y=0, sum_nost_z=0;
	int out_st_x[NUM_SAMPLE], out_st_y[NUM_SAMPLE], out_st_z[NUM_SAMPLE];
	int avg_out_st_x=0, avg_out_st_y=0, avg_out_st_z=0, sum_st_x=0, sum_st_y=0, sum_st_z=0;

	mutex_lock(&k3g_data->lock);

	pdata = client->dev.platform_data;
	if(pdata == NULL) {
	    dev_err(&client->dev,
		    "failed to read platform data\n");
		err = -ENOMEM;
		goto exit_self_test;
	}

	/* 1. Initialize/Turn on/enable Sensor - set BDU=1, ODR=200HZ, Cut-Off Freq=5-Hz, FS=2000dps*/
	err = i2c_smbus_write_byte_data(k3g_data->client,CTRL_REG1, 0x6f);
	if(err < 0){
		err = -EIO;
		printk(KERN_ERR "[%s, %d] Error during writing 0x6f on CTRL_REG1\n", TAG_ST, __LINE__);
		goto exit_self_test;
	}

	err = i2c_smbus_write_byte_data(k3g_data->client,CTRL_REG2, 0x00);
	if(err < 0){
		err = -EIO;
		printk(KERN_ERR "[%s, %d] Error during writing 0x00 on CTRL_REG2\n",TAG_ST, __LINE__);
		goto exit_self_test;
	}
	
	err = i2c_smbus_write_byte_data(k3g_data->client,CTRL_REG3, 0x00);
	if(err < 0){
		err = -EIO;
		printk(KERN_ERR "[%s, %d] Error during writing 0x00 on CTRL_REG3\n",TAG_ST, __LINE__);
		goto exit_self_test;
	}

	err = i2c_smbus_write_byte_data(k3g_data->client,CTRL_REG4, 0xa0);
	if(err < 0){
		err = -EIO;
		printk(KERN_ERR "[%s, %d] Error during writing 0xa0 on CTRL_REG4\n", TAG_ST,__LINE__);
		goto exit_self_test;
	}

	err = i2c_smbus_write_byte_data(k3g_data->client,CTRL_REG5, 0x02);
	if(err < 0){
		err = -EIO;
		printk(KERN_ERR "[%s, %d] Error during writing 0x02 on CTRL_REG5\n",TAG_ST,__LINE__);
		goto exit_self_test;
	}

	/* 2. Power up, wait for 800ms for stable output */	
	if(pdata->power_on){
		pdata->power_on(1<<SENSOR_TYPE_GYROSCOPE);
		mdelay(800);
	}

	while(i < NUM_SAMPLE)
	{
		tmp1=0;
		tmp2=0;
		if(i2c_smbus_read_byte_data(k3g_data->client, STATUS_REG) & ZYXDA_MASK){

			if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_INFO "[%s, %d] NOST read data #%d\n",TAG_ST,__LINE__,i);
			tmp1 = i2c_smbus_read_byte_data(k3g_data->client, OUT_X_L);
			tmp2 = i2c_smbus_read_byte_data(k3g_data->client, OUT_X_H);
			out_nost_x[i] = (tmp2 << 8) | tmp1;
			if(0x8000&out_nost_x[i])
				out_nost_x[i] = (0x10000 - out_nost_x[i])*(-1);

			tmp1 = i2c_smbus_read_byte_data(k3g_data->client, OUT_Y_L);
			tmp2 = i2c_smbus_read_byte_data(k3g_data->client, OUT_Y_H);
			out_nost_y[i] = (tmp2 << 8) | tmp1;
			if(0x8000&out_nost_y[i])
				out_nost_y[i] = (0x10000 - out_nost_y[i])*(-1);

			tmp1 = i2c_smbus_read_byte_data(k3g_data->client, OUT_Z_L);
			tmp2 = i2c_smbus_read_byte_data(k3g_data->client, OUT_Z_H);
			out_nost_z[i] = (tmp2 << 8) | tmp1;
			if(0x8000&out_nost_z[i])
				out_nost_z[i] = (0x10000 - out_nost_z[i])*(-1);

			i++;
		} else {
			if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_INFO "[%s, %d] NOST ZYXDA ready bit is not set\n",TAG_ST,__LINE__);
			mdelay(1);
		}
	}

	/* calculate avg values for nost */
	for(i=0; i<NUM_SAMPLE; i++)
	{
		sum_nost_x += out_nost_x[i];
		sum_nost_y += out_nost_y[i];
		sum_nost_z += out_nost_z[i];

		if(DEBUG_DEV_STATUS & debug_mask)
		{
			printk(KERN_INFO "[%s, %d] sum_nost_x=(%d), out_nost_x[%d]=(%d)\n", TAG_ST, __LINE__, sum_nost_x, i, out_nost_x[i]);
			printk(KERN_INFO "[%s, %d] sum_nost_y=(%d), out_nost_y[%d]=(%d)\n", TAG_ST, __LINE__, sum_nost_y, i, out_nost_y[i]);
			printk(KERN_INFO "[%s, %d] sum_nost_z=(%d), out_nost_z[%d]=(%d)\n", TAG_ST, __LINE__, sum_nost_z, i, out_nost_z[i]);
		}
	}
	
	avg_out_nost_x = sum_nost_x/NUM_SAMPLE;
	avg_out_nost_y = sum_nost_y/NUM_SAMPLE;
	avg_out_nost_z = sum_nost_z/NUM_SAMPLE;
	
	if(DEBUG_DEV_STATUS & debug_mask)
		printk(KERN_INFO "[%s, %d] avg_out_nost_x(%d), avg_out_nost_y(%d), avg_out_nost_z(%d)\n", TAG_ST, __LINE__, avg_out_nost_x, avg_out_nost_y, avg_out_nost_z);

	/* 3. Enable Self Test */
	err = i2c_smbus_write_byte_data(k3g_data->client,CTRL_REG4, 0xa2);
	if(err < 0){
		err = -EIO;
		printk(KERN_ERR "[%s, %d] Error during writing 0x02 on CTRL_REG5\n",TAG_ST,__LINE__);
		goto exit_self_test;
	}

	//wait for 3*ODR
	mdelay(50); //mdelay(15);

	while(j < NUM_SAMPLE)
	{
		tmp1=0;
		tmp2=0;
		if(i2c_smbus_read_byte_data(k3g_data->client, STATUS_REG) & ZYXDA_MASK){
			if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_INFO "[%s, %d] ST read data #%d\n",TAG_ST,__LINE__,j);
			tmp1 = i2c_smbus_read_byte_data(k3g_data->client, OUT_X_L);
			tmp2 = i2c_smbus_read_byte_data(k3g_data->client, OUT_X_H);
			out_st_x[j] = (tmp2 << 8) | tmp1;
			if(0x8000&out_st_x[j])
				out_st_x[j] = (0x10000 - out_st_x[j])*(-1);

			tmp1 = i2c_smbus_read_byte_data(k3g_data->client, OUT_Y_L);
			tmp2 = i2c_smbus_read_byte_data(k3g_data->client, OUT_Y_H);
			out_st_y[j] = (tmp2 << 8) | tmp1;
			if(0x8000&out_st_y[j])
				out_st_y[j] = (0x10000 - out_st_y[j])*(-1);

			tmp1 = i2c_smbus_read_byte_data(k3g_data->client, OUT_Z_L);
			tmp2 = i2c_smbus_read_byte_data(k3g_data->client, OUT_Z_H);
			out_st_z[j] = (tmp2 << 8) | tmp1;
			if(0x8000&out_st_z[j])
				out_st_z[j] = (0x10000 - out_st_z[j])*(-1);

			j++;
		} else {
			if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_INFO "[%s, %d] ST ZYXDA ready bit is not set\n",TAG_ST,__LINE__);
			mdelay(1);
		}
	}

	/* calculate avg values for st */
	for(j=0; j<NUM_SAMPLE; j++)
	{
		sum_st_x += out_st_x[j];
		sum_st_y += out_st_y[j];
		sum_st_z += out_st_z[j];
		if(DEBUG_DEV_STATUS & debug_mask)
		{
			printk(KERN_INFO "[%s, %d] sum_st_x=(%d), out_st_x[%d]=(%d)\n", TAG_ST, __LINE__, sum_st_x, j, out_st_x[j]);
			printk(KERN_INFO "[%s, %d] sum_st_y=(%d), out_st_y[%d]=(%d)\n", TAG_ST, __LINE__, sum_st_y, j, out_st_y[j]);
			printk(KERN_INFO "[%s, %d] sum_st_z=(%d), out_st_z[%d]=(%d)\n", TAG_ST, __LINE__, sum_st_z, j, out_st_z[j]);
		}
	}

	avg_out_st_x = sum_st_x/NUM_SAMPLE;
	avg_out_st_y = sum_st_y/NUM_SAMPLE;
	avg_out_st_z = sum_st_z/NUM_SAMPLE;
	
	if(DEBUG_DEV_STATUS & debug_mask)
		printk(KERN_INFO "[%s, %d] avg_out_st_x(%d), avg_out_st_y(%d), avg_ouot_st_z(%d)\n", 
				TAG_ST, __LINE__, avg_out_st_x, avg_out_st_y, avg_out_st_z);

	/* 4. decide pass/fail */
	{
		int tmpx=0, tmpy=0, tmpz=0;
		tmpx = K3G_ABS(avg_out_st_x - avg_out_nost_x)*SENSITIVITY/1000;
		if(DEBUG_DEV_STATUS & debug_mask)
			printk(KERN_INFO "[%s, %d] tmpx(%d)=(%d*0.001)*|avg_out_st_x(%d)-avg_out_nost_x(%d)|\n",
					TAG_ST,__LINE__, tmpx,SENSITIVITY, avg_out_st_x,avg_out_nost_x);
		if(MIN_ST_X <= tmpx && tmpx <= MAX_ST_X){
			if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_ERR "[%s, %d] Pass, ST_X, (%d)<=(%d)<=(%d)\n",TAG_ST,__LINE__, MIN_ST_X, tmpx, MAX_ST_X);
			ret = true;
		} else {
			printk(KERN_ERR "[%s, %d] False, ST_X, (%d)<=(%d)<=(%d)\n",TAG_ST,__LINE__, MIN_ST_X, tmpx, MAX_ST_X);
			ret = false;
			goto exit_self_test; 
		}
		
		tmpy = K3G_ABS(avg_out_st_y - avg_out_nost_y)*SENSITIVITY/1000;
		if(DEBUG_DEV_STATUS & debug_mask)
			printk(KERN_INFO "[%s, %d] tmpy(%d)=(%d*0.001)*|avg_out_st_y(%d)-avg_out_nost_y(%d)|\n",
					TAG_ST,__LINE__, tmpy,SENSITIVITY,avg_out_st_y,avg_out_nost_y);
		if(MIN_ST_Y <= tmpy && tmpy <= MAX_ST_Y){
			if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_ERR "[%s, %d] Pass, ST_Y, (%d)<=(%d)<=(%d)\n",TAG_ST,__LINE__, MIN_ST_Y, tmpy, MAX_ST_Y);
			ret = true;
		} else {
			printk(KERN_ERR "[%s, %d] False, ST_Y, (%d)<=(%d)<=(%d)\n",TAG_ST,__LINE__, MIN_ST_Y, tmpy, MAX_ST_Y);
			ret = false;
			goto exit_self_test; 
		} 

		tmpz = K3G_ABS(avg_out_st_z - avg_out_nost_z)*SENSITIVITY/1000;
		if(DEBUG_DEV_STATUS & debug_mask)
			printk(KERN_INFO "[%s, %d] tmpz(%d)=(%d*0.001)*|avg_out_st_z(%d)-avg_out_nost_z(%d)|\n",
					TAG_ST,__LINE__, tmpz, SENSITIVITY,avg_out_st_z,avg_out_nost_z);
		if(MIN_ST_Z <= tmpz && tmpz <=  MAX_ST_Z){
			if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_ERR "[%s, %d] Pass, ST_Z, (%d)<=(%d)<=(%d)\n",TAG_ST,__LINE__, MIN_ST_Z, tmpz, MAX_ST_Z);
			ret = true;
		} else {
			printk(KERN_ERR "[%s, %d] False, ST_Z, (%d)<=(%d)<=(%d)\n",TAG_ST,__LINE__, MIN_ST_Z, tmpz, MAX_ST_Z);
			ret = false;
			goto exit_self_test; 
		} 		
	}

	printk(KERN_INFO "[%s, %d] Finally Pass!!!\n",TAG_ST,__LINE__);
	ret = true;

exit_self_test:
	
	/* Disable Sensor */
	err = i2c_smbus_write_byte_data(k3g_data->client,CTRL_REG1, 0x00);
	if(err < 0){
		err = -EIO;
		printk(KERN_ERR "[%s, %d] exit: Error during writing 0x02 on CTRL_REG5\n",TAG_ST,__LINE__);
		//goto exit;
	}

	/* Disable Self Test */
	err = i2c_smbus_write_byte_data(k3g_data->client,CTRL_REG4, 0x00);
	if(err < 0){
		err = -EIO;
		printk(KERN_ERR "[%s, %d] exit: Error during writing 0x02 on CTRL_REG5\n",TAG_ST,__LINE__);
		//goto exit;
	}

	mutex_unlock(&k3g_data->lock);
	st_result = ret;
	return err ? err : size;
}
#endif
static ssize_t k3g_show_report_cnt(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct k3g_data *k3g_data  = dev_get_drvdata(dev);
	printk(KERN_INFO "%s: report_cnt: %d\n", __func__, report_cnt);
	if( k3g_data->enable)
		return sprintf(buf, "%d\n", report_cnt);
	else
		return sprintf(buf, "%d\n", -1);
}
static DEVICE_ATTR(enable, /*S_IRUGO | S_IWUSR | S_IWGRP,*/S_IRUGO|S_IWUSR,
			k3g_show_enable, k3g_set_enable);
static DEVICE_ATTR(poll_delay, /*S_IRUGO | S_IWUSR | S_IWGRP,*/S_IRUGO|S_IWUSR,
			k3g_show_delay, k3g_set_delay);
static DEVICE_ATTR(gyro_data, /*S_IRUGO | S_IWUSR | S_IWGRP,*/S_IRUGO|S_IWUSR,
			k3g_show_gyro_data, NULL);
static DEVICE_ATTR(gyro_cnt, /*S_IRUGO | S_IWUSR | S_IWGRP,*/S_IRUGO|S_IWUSR,
			k3g_show_report_cnt, NULL);

#ifdef SELF_TEST_ENABLED
static DEVICE_ATTR(self_test, S_IRUGO | S_IWUSR | S_IWGRP,
			k3g_show_st_result, k3g_run_self_test);
static struct attribute *k3g_attributes[] = 
{
	&dev_attr_enable.attr,
	&dev_attr_poll_delay.attr,
#ifdef SELF_TEST_ENABLED
	&dev_attr_self_test.attr,
#endif
	&dev_attr_gyro_data.attr,
	&dev_attr_gyro_cnt.attr,
	NULL
};

static const struct attribute_group k3g_attr_group = 
{
	.attrs = k3g_attributes,
};
#endif

static int k3g_probe(struct i2c_client *client,
			       const struct i2c_device_id *devid)
{
	int ret;
	int err = 0;
	struct k3g_data *data;
	struct k3g_platform_data *pdata;
	struct input_dev *input_dev;

	if (client->dev.platform_data == NULL) {
		dev_err(&client->dev, "platform data is NULL. exiting.\n");
		err = -ENODEV;
		goto exit;
	}

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d", __func__, __LINE__);

	k3g_i2c_client = client;

	/* device data setting */
	pdata = client->dev.platform_data;
	if(pdata == NULL) 
	{
	    dev_err(&client->dev,
		    "failed to read platform data\n");
		err = -ENOMEM;
		goto exit;
	}
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL) {
		dev_err(&client->dev,
			"failed to allocate memory for module data\n");
		err = -ENOMEM;
		goto exit;
	}

	data->client = client;

	if(pdata->power_on){

	if(DEBUG_FUNC_TRACE & debug_mask)
			printk(KERN_INFO "%s: line %d, call power_on", __func__, __LINE__);
	    pdata->power_on(1<<SENSOR_TYPE_GYROSCOPE);
	    mdelay(1);
	}

#ifdef SELF_TEST_ENABLED
	err = sysfs_create_group(&client->dev.kobj, &k3g_attr_group);
	if (err) {
		printk(KERN_ERR "Unable to do sysfs_create_group");
		goto exit;
	}
#endif

	/* read chip id */
	ret = i2c_smbus_read_byte_data(client, WHO_AM_I);
	if (ret != DEVICE_ID) {
		if (ret < 0) {
			pr_err("%s: i2c for reading chip id failed\n",
								__func__);
			err = ret;
		} else {
			pr_err("%s : Device identification failed\n",
								__func__);
			err = -ENODEV;
		}
		goto err_read_reg;
	}


	mutex_init(&data->lock);

	/* allocate gyro input_device */
	input_dev = input_allocate_device();
	if (!input_dev) {
		pr_err("%s: could not allocate input device\n", __func__);
		err = -ENOMEM;
		goto err_input_allocate_device;
	}

	data->input_dev = input_dev;
	input_set_drvdata(input_dev, data);
	input_dev->name = "gyroscope";
	/* X */
	input_set_capability(input_dev, EV_REL, REL_RX);
	input_set_abs_params(input_dev, REL_RX, -2048, 2047, 0, 0);
	/* Y */
	input_set_capability(input_dev, EV_REL, REL_RY);
	input_set_abs_params(input_dev, REL_RY, -2048, 2047, 0, 0);
	/* Z */
	input_set_capability(input_dev, EV_REL, REL_RZ);
	input_set_abs_params(input_dev, REL_RZ, -2048, 2047, 0, 0);

	err = input_register_device(input_dev);
	if (err < 0) 
	{
		pr_err("%s: could not register input device\n", __func__);
		input_free_device(data->input_dev);
		goto err_input_register_device;
	}

	memcpy(&data->ctrl_regs, &default_ctrl_regs, sizeof(default_ctrl_regs));
	if(pdata->power_off){
	    if(DEBUG_FUNC_TRACE & debug_mask)
			printk(KERN_INFO "%s: line %d, call power_off", __func__, __LINE__);
	    pdata->power_off(1<<SENSOR_TYPE_GYROSCOPE);
	}

	if (data->client->irq >= 0) 
	{ 
	    /* interrupt */
		data->interruptible = true;
		err = request_threaded_irq(data->client->irq, NULL,
			k3g_interrupt_thread, IRQF_TRIGGER_HIGH|IRQF_ONESHOT,
				"k3g", data);
		if (err < 0) {
			pr_err("%s: can't allocate irq.\n", __func__);
			goto err_request_irq;
		}
		disable_irq(data->client->irq);

	} 
	else 
	{ 
	    /* polling */
		u64 delay_ns;
		data->ctrl_regs[2] = 0x00; /* disable interrupt */
		/* hrtimer settings.  we poll for gyro values using a timer. */
		hrtimer_init(&data->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		data->polling_delay = ns_to_ktime(10 * NSEC_PER_MSEC);
		data->time_to_read = 10000000LL;
		delay_ns = ktime_to_ns(data->polling_delay);
		do_div(delay_ns, data->time_to_read);
		data->entries = delay_ns;
		data->timer.function = k3g_timer_func;

		/* the timer just fires off a work queue request.
		   We need a thread to read i2c (can be slow and blocking). */
		data->k3g_wq = create_singlethread_workqueue("k3g_wq");
		if (!data->k3g_wq) {
			err = -ENOMEM;
			pr_err("%s: could not create workqueue\n", __func__);
			goto err_create_workqueue;
		}
		/* this is the thread function we run on the work queue */
		INIT_WORK(&data->work, k3g_work_func);
	}

	if (device_create_file(&input_dev->dev,
				&dev_attr_enable) < 0) {
		pr_err("Failed to create device file(%s)!\n",
				dev_attr_enable.attr.name);
		goto err_device_create_file;
	}

	if (device_create_file(&input_dev->dev,
				&dev_attr_poll_delay) < 0) {
		pr_err("Failed to create device file(%s)!\n",
				dev_attr_poll_delay.attr.name);
		goto err_device_create_file2;
	}

	if (device_create_file(&input_dev->dev,
				&dev_attr_gyro_data) < 0) {
		pr_err("Failed to create device file(%s)!\n",
				dev_attr_gyro_data.attr.name);
		goto err_device_create_file4;
	}
	
	if (device_create_file(&input_dev->dev,
				&dev_attr_gyro_cnt) < 0) {
		pr_err("Failed to create device file(%s)!\n",
				dev_attr_gyro_cnt.attr.name);
		goto err_device_create_file4;
	}
#ifdef FILE_OPS
  	err = misc_register(&k3g_misc_device);
  	if (err < 0)
  	{
   	 	dev_err(&client->dev,
    	"misc device register failed\n");
    	goto err_device_create_file2;
  	}
#endif


#ifdef SELF_TEST_ENABLED
	if (device_create_file(&input_dev->dev,
				&dev_attr_self_test) < 0) {
		pr_err("Failed to create device file(%s)!\n",
				dev_attr_self_test.attr.name);
		goto err_device_create_file3;
	}
#endif

	i2c_set_clientdata(client, data);
	dev_set_drvdata(&input_dev->dev, data);

    return 0;

err_device_create_file4:
	device_remove_file(&input_dev->dev, &dev_attr_self_test);
#ifdef SELF_TEST_ENABLED
err_device_create_file3:
	device_remove_file(&input_dev->dev, &dev_attr_self_test);
#endif
err_device_create_file2:
	device_remove_file(&input_dev->dev, &dev_attr_enable);
err_device_create_file:
	if (data->interruptible) {
		enable_irq(data->client->irq);
		free_irq(data->client->irq, data);
	} else
		destroy_workqueue(data->k3g_wq);
	input_unregister_device(data->input_dev);
err_create_workqueue:
err_request_irq:
err_input_register_device:
err_input_allocate_device:
	mutex_destroy(&data->lock);
err_read_reg:
	kfree(data);
exit:
	return err;
}

static int k3g_remove(struct i2c_client *client)
{
	int err = 0;
	struct k3g_data *k3g_data = i2c_get_clientdata(client);

	device_remove_file(&k3g_data->input_dev->dev, &dev_attr_enable);
	device_remove_file(&k3g_data->input_dev->dev, &dev_attr_poll_delay);
	device_remove_file(&k3g_data->input_dev->dev, &dev_attr_gyro_data);
	device_remove_file(&k3g_data->input_dev->dev, &dev_attr_gyro_cnt);
#ifdef SELF_TEST_ENABLED
	device_remove_file(&k3g_data->input_dev->dev, &dev_attr_self_test); 
#endif

#ifdef FILE_OPS
	misc_deregister(&k3g_misc_device);
#endif

	if (k3g_data->enable)
		err = i2c_smbus_write_byte_data(k3g_data->client,
					CTRL_REG1, 0x00);
	if (k3g_data->interruptible) {
		if (!k3g_data->enable) /* no disable_irq before free_irq */
			enable_irq(k3g_data->client->irq);
		free_irq(k3g_data->client->irq, k3g_data);

	} else {
		hrtimer_cancel(&k3g_data->timer);
		cancel_work_sync(&k3g_data->work);
		destroy_workqueue(k3g_data->k3g_wq);
	}

	input_unregister_device(k3g_data->input_dev);
	mutex_destroy(&k3g_data->lock);
	kfree(k3g_data);

	return err;
}

static int k3g_suspend(struct device *dev)
{
	int err = 0;
	struct i2c_client *client = to_i2c_client(dev);
	struct k3g_data *k3g_data = i2c_get_clientdata(client);
	struct k3g_platform_data *pdata;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	pdata = client->dev.platform_data;

	if (k3g_data->enable) {
		mutex_lock(&k3g_data->lock);
		if (!k3g_data->interruptible) {
			hrtimer_cancel(&k3g_data->timer);
			cancel_work_sync(&k3g_data->work);
			flush_workqueue(k3g_data->k3g_wq);
		}
		err = i2c_smbus_write_byte_data(k3g_data->client,
						CTRL_REG1, 0x00);
		mutex_unlock(&k3g_data->lock);
	}
		if(pdata->power_off){
		//if(pdata->check_power_off_valid(SENSOR_TYPE_GYROSCOPE))
		{
			if(DEBUG_GEN_INFO & debug_mask)
				printk(KERN_INFO "%s: goes to suspend, power off\n", __func__);
			//k3g_data->enable = 0;
			pdata->power_off(1<<SENSOR_TYPE_GYROSCOPE);
		}	
	}	

	return err;
}

static int k3g_resume(struct device *dev)
{
	int err = 0;
	struct i2c_client *client = to_i2c_client(dev);
	struct k3g_data *k3g_data = i2c_get_clientdata(client);
	struct k3g_platform_data *pdata;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	pdata = client->dev.platform_data;	

	if (pdata->power_on){	
		if(DEBUG_GEN_INFO & debug_mask)
			printk(KERN_INFO "%s: goes to resume, power on\n", __func__);
		pdata->power_on(1<<SENSOR_TYPE_GYROSCOPE);
		mdelay(1);
	}

	if (k3g_data->enable) {
		mutex_lock(&k3g_data->lock);
		if (!k3g_data->interruptible)
			hrtimer_start(&k3g_data->timer,
				k3g_data->polling_delay, HRTIMER_MODE_REL);
		err = i2c_smbus_write_i2c_block_data(client,
				CTRL_REG1 | AC, sizeof(k3g_data->ctrl_regs),
							k3g_data->ctrl_regs);
		mutex_unlock(&k3g_data->lock);
	}

	return err;
}

static const struct dev_pm_ops k3g_pm_ops = {
	.suspend = k3g_suspend,
	.resume = k3g_resume
};

static const struct i2c_device_id k3g_id[] = {
	{ "k3g", 0 },
	{ }
};

MODULE_DEVICE_TABLE(i2c, k3g_id);

static struct i2c_driver k3g_driver = {
	.probe = k3g_probe,
	.remove = __devexit_p(k3g_remove),
	.id_table = k3g_id,
	.driver = {
		.pm = &k3g_pm_ops,
		.owner = THIS_MODULE,
		.name = "k3g"
	},
};

static int __init k3g_init(void)
{
	int ret;
	
	ret = i2c_add_driver(&k3g_driver);
	if ( ret != 0 ) {
		printk(KERN_INFO "can not add i2c driver\n");
	}
	return ret;
}

static void __exit k3g_exit(void)
{
	i2c_del_driver(&k3g_driver);
}

module_init(k3g_init);
module_exit(k3g_exit);

MODULE_DESCRIPTION("k3g digital gyroscope driver");
MODULE_AUTHOR("Tim SK Lee Samsung Electronics <tim.sk.lee@samsung.com>");
MODULE_LICENSE("GPL");
