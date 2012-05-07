/******************** (C) COPYRIGHT 2010 STMicroelectronics ********************
 *
 * File Name          : k3dh_acc.c
 * Authors            : MSH - Motion Mems BU - Application Team
 *		      : Carmine Iascone (carmine.iascone@st.com)
 *		      : Matteo Dameno (matteo.dameno@st.com)
 * Version            : V.1.0.5
 * Date               : 16/08/2010
 * Description        : K3DH accelerometer sensor API
 *
 *******************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THE PRESENT SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, FOR THE SOLE
 * PURPOSE TO SUPPORT YOUR APPLICATION DEVELOPMENT.
 * AS A RESULT, STMICROELECTRONICS SHALL NOT BE HELD LIABLE FOR ANY DIRECT,
 * INDIRECT OR CONSEQUENTIAL DAMAGES WITH RESPECT TO ANY CLAIMS ARISING FROM THE
 * CONTENT OF SUCH SOFTWARE AND/OR THE USE MADE BY CUSTOMERS OF THE CODING
 * INFORMATION CONTAINED HEREIN IN CONNECTION WITH THEIR PRODUCTS.
 *
 * THIS SOFTWARE IS SPECIFICALLY DESIGNED FOR EXCLUSIVE USE WITH ST PARTS.
 *
 ******************************************************************************
 Revision 1.0.0 05/11/09
 First Release
 Revision 1.0.3 22/01/2010
  Linux K&R Compliant Release;
 Revision 1.0.5 16/08/2010
 modified _get_acceleration_data function
 modified _update_odr function
 manages 2 interrupts

 ******************************************************************************/

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/input.h>
#include <linux/input-polldev.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#include <linux/workqueue.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <k3dh.h>
#include <mach/board_lge.h>

#if defined(CONFIG_HAS_EARLYSUSPEND)
#include <linux/earlysuspend.h>

struct early_suspend k3dh_sensor_early_suspend;

static void k3dh_acc_early_suspend(struct early_suspend *h);
static void k3dh_acc_late_resume(struct early_suspend *h);
#endif

#define NEW_DRIVER
#define USE_HR_TIMER 
#define K3DH_USER_CALIBRATION 

#define NO_ISR
#define	INTERRUPT_MANAGEMENT 1
#define	G_MAX		16000	/** Maximum polled-device-reported g value */
#ifdef USE_HR_TIMER
#define MS_TO_NS(x)	((x) * NSEC_PER_MSEC)
#endif
/*
#define	SHIFT_ADJ_2G		4
#define	SHIFT_ADJ_4G		3
#define	SHIFT_ADJ_8G		2
#define	SHIFT_ADJ_16G		1
*/

#define SENSITIVITY_2G    1   /**	mg/LSB	*/
#define SENSITIVITY_4G    2   /**	mg/LSB	*/
#define SENSITIVITY_8G    4   /**	mg/LSB	*/
#define SENSITIVITY_16G   12  /**	mg/LSB	*/


#define	HIGH_RESOLUTION   0x08

#define	AXISDATA_REG      0x28
#define WHOAMI_K3DH_ACC   0x33  /* Expctd content for WAI */

/* CONTROL REGISTERS */
#define WHO_AM_I      0x0F /* WhoAmI register		*/
#define TEMP_CFG_REG  0x1F /* temper sens control reg	*/
/* ctrl 1: ODR3 ODR2 ODR ODR0 LPen Zenable Yenable Zenable */
#define CTRL_REG1     0x20 /* control reg 1		*/
#define CTRL_REG2     0x21 /* control reg 2		*/
#define CTRL_REG3     0x22 /* control reg 3		*/
#define CTRL_REG4     0x23 /* control reg 4		*/
#define CTRL_REG5     0x24 /* control reg 5		*/
#define CTRL_REG6     0x25 /* control reg 6		*/

#define FIFO_CTRL_REG 0x2E /* FiFo control reg	*/

#define INT_CFG1      0x30 /* interrupt 1 config	*/
#define INT_SRC1      0x31 /* interrupt 1 source	*/
#define INT_THS1      0x32 /* interrupt 1 threshold	*/
#define INT_DUR1      0x33 /* interrupt 1 duration	*/

#define INT_CFG2      0x34 /* interrupt 2 config	*/
#define INT_SRC2      0x35 /* interrupt 2 source	*/
#define INT_THS2      0x36 /* interrupt 2 threshold	*/
#define INT_DUR2      0x37 /* interrupt 2 duration	*/

#define TT_CFG        0x38 /* tap config		*/
#define TT_SRC        0x39 /* tap source		*/
#define TT_THS        0x3A /* tap threshold		*/
#define TT_LIM        0x3B /* tap time limit		*/
#define TT_TLAT       0x3C /* tap time latency	*/
#define TT_TW         0x3D /* tap time window		*/
/* end CONTROL REGISTRES */


#define ENABLE_HIGH_RESOLUTION  1

#define K3DH_ACC_PM_OFF           0x00
#define K3DH_ACC_ENABLE_ALL_AXES  0x07

#define PMODE_MASK    0x08
#define ODR_MASK      0XF0

#define ODR1          0x10  /* 1Hz output data rate */
#define ODR10         0x20  /* 10Hz output data rate */
#define ODR25         0x30  /* 25Hz output data rate */
#define ODR50         0x40  /* 50Hz output data rate */
#define ODR100        0x50  /* 100Hz output data rate */
#define ODR200        0x60  /* 200Hz output data rate */
#define ODR400        0x70  /* 400Hz output data rate */
#define ODR1250       0x90  /* 1250Hz output data rate */



#define IA			0x40
#define ZH			0x20
#define ZL			0x10
#define YH			0x08
#define YL			0x04
#define XH			0x02
#define XL			0x01
/* */
/* CTRL REG BITS*/
#define	CTRL_REG3_I1_AOI1	0x40
#define	CTRL_REG6_I2_TAPEN	0x80
#define	CTRL_REG6_HLACTIVE	0x02
/* */

/* TAP_SOURCE_REG BIT */
#define	DTAP			0x20
#define	STAP			0x10
#define	SIGNTAP			0x08
#define	ZTAP			0x04
#define	YTAP			0x02
#define	XTAZ			0x01


#define	FUZZ			0
#define	FLAT			0
#define	I2C_RETRY_DELAY		5
#define	I2C_RETRIES		5
#define	I2C_AUTO_INCREMENT	0x80

/* RESUME STATE INDICES */
#define	RES_CTRL_REG1		0
#define	RES_CTRL_REG2		1
#define	RES_CTRL_REG3		2
#define	RES_CTRL_REG4		3
#define	RES_CTRL_REG5		4
#define	RES_CTRL_REG6		5

#define	RES_INT_CFG1		6
#define	RES_INT_THS1		7
#define	RES_INT_DUR1		8
#define	RES_INT_CFG2		9
#define	RES_INT_THS2		10
#define	RES_INT_DUR2		11

#define	RES_TT_CFG		12
#define	RES_TT_THS		13
#define	RES_TT_LIM		14
#define	RES_TT_TLAT		15
#define	RES_TT_TW		16

#define	RES_TEMP_CFG_REG	17
#define	RES_REFERENCE_REG	18
#define	RES_FIFO_CTRL_REG	19

#define	RESUME_ENTRIES		20
/* end RESUME STATE INDICES */

#define DRV_NAME    "k3dh"

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
  DEBUG_SYSFS_INFO    = 1U << 7,
};

static unsigned int debug_mask = DEBUG_USER_ERROR;

module_param_named(debug_mask, debug_mask, int, S_IRUGO | S_IWUSR | S_IWGRP);

struct {
  unsigned int cutoff_ms;
  unsigned int mask;
} k3dh_acc_odr_table[] = {
  { 1, ODR1250 },
  { 3, ODR400 },
  { 5, ODR200 },
  { 10, ODR100 },
  { 20, ODR50 },
  { 40, ODR25 },
  { 100, ODR10 },
  { 1000, ODR1 },
};


struct k3dh_acc_data {
  struct i2c_client *client;
  struct k3dh_acc_platform_data *pdata;

  struct mutex lock;
  struct delayed_work input_work;
#ifdef USE_HR_TIMER
	struct hrtimer htimer;
	ktime_t polling_ktime;
	struct work_struct hr_work;
	struct workqueue_struct *hr_work_q;
#endif
  struct input_dev *input_dev;
  struct input_dev *input_dev_flip;
  struct input_dev *input_dev_tap;

  int hw_initialized;
  /* hw_working=-1 means not tested yet */
  int hw_working;
  atomic_t enabled;
  unsigned int enable;
  unsigned int resume;
  int acc_poll_ms;
  int gesture_poll_ms;
  int on_before_suspend;
  int on_before_early_suspend;

  u8 sensitivity;

  u8 resume_state[RESUME_ENTRIES];

  int irq1;
  struct work_struct irq1_work;
  struct workqueue_struct *irq1_work_queue;
  int irq2;
  struct work_struct irq2_work;
  struct workqueue_struct *irq2_work_queue;
};

enum {
  ID_ACC  = 0,
  ID_FLIP,
  ID_TAP,
  ID_MAX,
  ID_RESUME,
};

#define ENA_MASK_ACC     (1 << 0)
#define ENA_MASK_FLIP    (1 << 1)
#define ENA_MASK_TAP     (1 << 2)

unsigned int ena_mask[ID_MAX] = { ENA_MASK_ACC, ENA_MASK_FLIP, ENA_MASK_TAP};

static int k3dh_xyz[3] = {0,};
static u32 report_cnt = 0;

/*
 * Because misc devices can not carry a pointer from driver register to
 * open, we keep this global.  This limits the driver to a single instance.
 */
struct k3dh_acc_data *k3dh_acc_misc_data;

static int k3dh_acc_i2c_read(struct k3dh_acc_data *acc, u8 * buf, int len)
{
	int err;
//	int tries = 0;

	struct i2c_msg	msgs[] = 
	{
		{
			.addr = acc->client->addr,
			//.flags = acc->client->flags & I2C_M_TEN,
			.flags = acc->client->flags,
			.len = 1,
			.buf = buf, 
		},
		{
			.addr = acc->client->addr,
			//.flags = (acc->client->flags & I2C_M_TEN) | I2C_M_RD,
			.flags = (acc->client->flags) | I2C_M_RD,
			.len = len,
			.buf = buf, 
		},
	};

//	do 
//	{
		err = i2c_transfer(acc->client->adapter, msgs, 2);
//		if (err != 2)
//			msleep_interruptible(I2C_RETRY_DELAY);
//	} while ((err != 2) && (++tries < I2C_RETRIES));

	if (err != 2) 
	{
		dev_err(&acc->client->dev, "read transfer error\n");
		err = -EIO;
	} else {
		err = 0;
	}

	return err;
}

static int k3dh_acc_i2c_write(struct k3dh_acc_data *acc, u8 * buf, int len)
{
	int err;
//	int tries = 0;

	struct i2c_msg msgs[] = {
		{
			.addr = acc->client->addr,
			//.flags = acc->client->flags & I2C_M_TEN,
			.flags = acc->client->flags,
			.len = len + 1,
			.buf = buf,
		},
	};

//	do 
//	{
		err = i2c_transfer(acc->client->adapter, msgs, 1);
//		if (err != 1)
//			msleep_interruptible(I2C_RETRY_DELAY);
//	} while ((err != 1) && (++tries < I2C_RETRIES));

	if (err != 1) 
	{
		dev_err(&acc->client->dev, "write transfer error\n");
		err = -EIO;
	} else {
		err = 0;
	}

	return err;
}

static int k3dh_acc_hw_init(struct k3dh_acc_data *acc)
{
	int err = -1;
	u8 buf[7];

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: hw init start\n", K3DH_ACC_DEV_NAME);

	buf[0] = WHO_AM_I;
	err = k3dh_acc_i2c_read(acc, buf, 1);
	if (err < 0)
		goto error_firstread;
	else
		acc->hw_working = 1;
	if (buf[0] != WHOAMI_K3DH_ACC) {
		err = -1; /* choose the right coded error */
		goto error_unknown_device;
	}

	buf[0] = CTRL_REG1;
	buf[1] = acc->resume_state[RES_CTRL_REG1];
	err = k3dh_acc_i2c_write(acc, buf, 1);
	if (err < 0)
		goto error1;

	buf[0] = TEMP_CFG_REG;
	buf[1] = acc->resume_state[RES_TEMP_CFG_REG];
	err = k3dh_acc_i2c_write(acc, buf, 1);
	if (err < 0)
		goto error1;

	buf[0] = FIFO_CTRL_REG;
	buf[1] = acc->resume_state[RES_FIFO_CTRL_REG];
	err = k3dh_acc_i2c_write(acc, buf, 1);
	if (err < 0)
		goto error1;

	buf[0] = (I2C_AUTO_INCREMENT | TT_THS);
	buf[1] = acc->resume_state[RES_TT_THS];
	buf[2] = acc->resume_state[RES_TT_LIM];
	buf[3] = acc->resume_state[RES_TT_TLAT];
	buf[4] = acc->resume_state[RES_TT_TW];
	err = k3dh_acc_i2c_write(acc, buf, 4);
	if (err < 0)
		goto error1;
	buf[0] = TT_CFG;
	buf[1] = acc->resume_state[RES_TT_CFG];
	err = k3dh_acc_i2c_write(acc, buf, 1);
	if (err < 0)
		goto error1;

	buf[0] = (I2C_AUTO_INCREMENT | INT_THS1);
	buf[1] = acc->resume_state[RES_INT_THS1];
	buf[2] = acc->resume_state[RES_INT_DUR1];
	err = k3dh_acc_i2c_write(acc, buf, 2);
	if (err < 0)
		goto error1;
	buf[0] = INT_CFG1;
	buf[1] = acc->resume_state[RES_INT_CFG1];
	err = k3dh_acc_i2c_write(acc, buf, 1);
	if (err < 0)
		goto error1;

	buf[0] = (I2C_AUTO_INCREMENT | INT_THS2);
	buf[1] = acc->resume_state[RES_INT_THS2];
	buf[2] = acc->resume_state[RES_INT_DUR2];
	err = k3dh_acc_i2c_write(acc, buf, 2);
	if (err < 0)
		goto error1;
	buf[0] = INT_CFG2;
	buf[1] = acc->resume_state[RES_INT_CFG2];
	err = k3dh_acc_i2c_write(acc, buf, 1);
	if (err < 0)
		goto error1;

	buf[0] = (I2C_AUTO_INCREMENT | CTRL_REG2);
	buf[1] = acc->resume_state[RES_CTRL_REG2];
	buf[2] = acc->resume_state[RES_CTRL_REG3];
	buf[3] = acc->resume_state[RES_CTRL_REG4];
	buf[4] = acc->resume_state[RES_CTRL_REG5];
	buf[5] = acc->resume_state[RES_CTRL_REG6];
	err = k3dh_acc_i2c_write(acc, buf, 5);
	if (err < 0)
		goto error1;

	acc->hw_initialized = 1;
	
	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: hw init done\n", K3DH_ACC_DEV_NAME);
	
	return 0;

error_firstread:
	acc->hw_working = 0;
	dev_warn(&acc->client->dev, "Error reading WHO_AM_I: is device "
		"available/working?\n");
	goto error1;
error_unknown_device:
	dev_err(&acc->client->dev,
		"device unknown. Expected: 0x%x,"
		" Replies: 0x%x\n", WHOAMI_K3DH_ACC, buf[0]);
error1:
	acc->hw_initialized = 0;
	dev_err(&acc->client->dev, "hw init error 0x%x,0x%x: %d\n", buf[0],
			buf[1], err);
	return err;
}

static void k3dh_acc_device_power_off(struct k3dh_acc_data *acc)
{
	int err;
	u8 buf[2] = { CTRL_REG1, K3DH_ACC_PM_OFF };

	err = k3dh_acc_i2c_write(acc, buf, 1);
	if (err < 0)
		dev_err(&acc->client->dev, "soft power off failed: %d\n", err);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

	if (acc->pdata->power_off) {
		if(acc->irq1)
			disable_irq_nosync(acc->irq1);
		if(acc->irq2)
			disable_irq_nosync(acc->irq2);
		acc->pdata->power_off(1<<SENSOR_TYPE_ACCELEROMETER);
		acc->hw_initialized = 0;
	}
	if (acc->hw_initialized) {
		if(acc->irq1)
			disable_irq_nosync(acc->irq1);
		if(acc->irq2)
			disable_irq_nosync(acc->irq2);
		acc->hw_initialized = 0;
	}

}

int k3dh_irq_enabled = 0;
static int k3dh_acc_enable_irq(struct k3dh_acc_data *acc)
{
  int err = -1;

  if(DEBUG_FUNC_TRACE & debug_mask)
    printk(KERN_INFO "%s: line: %d, irq=%d\n", __func__, __LINE__,k3dh_irq_enabled);

  if(!k3dh_irq_enabled)
  {
    enable_irq(acc->irq1);
    enable_irq(acc->irq2);
    k3dh_irq_enabled = 1;
    return 0;
  }
  return err;
}

static int k3dh_acc_device_power_on(struct k3dh_acc_data *acc)
{
	int err = -1;

  	if (acc->pdata->power_on) 
  	{
	    err = acc->pdata->power_on(1<<SENSOR_TYPE_ACCELEROMETER);
	    udelay(350);

  		if (err < 0) 
		{
    		dev_err(&acc->client->dev,
    		"power_on failed: %d\n", err);
    		return err;
  		}

  		if(acc->irq1 || acc->irq2)
    		k3dh_acc_enable_irq(acc);
	}

	if (!acc->hw_initialized)
	{
		err = k3dh_acc_hw_init(acc);
		if (acc->hw_working == 1 && err < 0) {
			k3dh_acc_device_power_off(acc);
			return err;
		}
	}
	
	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

	if (acc->hw_initialized) 
	{

		if(acc->irq1 || acc->irq2)
			k3dh_acc_enable_irq(acc);

		if(DEBUG_FUNC_TRACE & debug_mask)
			printk(KERN_INFO "%s: power on: irq enabled\n",	K3DH_ACC_DEV_NAME);
	}
	return 0;
}

static irqreturn_t k3dh_acc_isr1(int irq, void *dev)
{
	struct k3dh_acc_data *acc = dev;

	disable_irq_nosync(irq);
	queue_work(acc->irq1_work_queue, &acc->irq1_work);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: isr1 queued\n", K3DH_ACC_DEV_NAME);

	return IRQ_HANDLED;
}

static irqreturn_t k3dh_acc_isr2(int irq, void *dev)
{
	struct k3dh_acc_data *acc = dev;

	disable_irq_nosync(irq);
	queue_work(acc->irq2_work_queue, &acc->irq2_work);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: isr2 queued\n", K3DH_ACC_DEV_NAME);

	return IRQ_HANDLED;
}

static void k3dh_acc_irq1_work_func(struct work_struct *work)
{
	struct k3dh_acc_data *acc =
		container_of(work, struct k3dh_acc_data, irq1_work);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s, line: %d\n", __func__, __LINE__);

#if 0
	/* TODO  add interrupt service procedure.
		 ie:k3dh_acc_get_int1_source(acc); */
	;
	/*  */
	printk(KERN_INFO "%s: IRQ1 triggered\n", K3DH_ACC_DEV_NAME);
exit:
#endif
	enable_irq(acc->irq1);
}

static void k3dh_acc_irq2_work_func(struct work_struct *work)
{
	struct k3dh_acc_data *acc =
		container_of(work, struct k3dh_acc_data, irq2_work);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s, line: %d\n", __func__, __LINE__);

#if 0 
	/* TODO  add interrupt service procedure.
		 ie:k3dh_acc_get_tap_source(acc); */
	;
	/*  */

	printk(KERN_INFO "%s: IRQ2 triggered\n", K3DH_ACC_DEV_NAME);
exit:
#endif
	enable_irq(acc->irq2);
}

int k3dh_acc_update_g_range(struct k3dh_acc_data *acc, u8 new_g_range)
{
	int err;

	u8 sensitivity;
	u8 buf[2];
	u8 updated_val;
	u8 init_val;
	u8 new_val;
	u8 mask = K3DH_ACC_FS_MASK | HIGH_RESOLUTION;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d, new_g_range(%d)\n", __func__, __LINE__,new_g_range);
	
	switch (new_g_range) {
	case K3DH_ACC_G_2G:

		sensitivity = SENSITIVITY_2G;
		break;
	case K3DH_ACC_G_4G:

		sensitivity = SENSITIVITY_4G;
		break;
	case K3DH_ACC_G_8G:

		sensitivity = SENSITIVITY_8G;
		break;
	case K3DH_ACC_G_16G:

		sensitivity = SENSITIVITY_16G;
		break;
	default:
		dev_err(&acc->client->dev, "invalid g range requested: %u\n",
				new_g_range);
		return -EINVAL;
	}

	if (atomic_read(&acc->enabled)) 
	{
		/* Set configuration register 4, which contains g range setting
		 *  NOTE: this is a straight overwrite because this driver does
		 *  not use any of the other configuration bits in this
		 *  register.  Should this become untrue, we will have to read
		 *  out the value and only change the relevant bits --XX----
		 *  (marked by X) */
		buf[0] = CTRL_REG4;
		err = k3dh_acc_i2c_read(acc, buf, 1);
		if (err < 0)
			goto error;
		init_val = buf[0];
		acc->resume_state[RES_CTRL_REG4] = init_val;
		new_val = new_g_range | HIGH_RESOLUTION;
		updated_val = ((mask & new_val) | ((~mask) & init_val));
		buf[1] = updated_val;
		buf[0] = CTRL_REG4;
		err = k3dh_acc_i2c_write(acc, buf, 1);
		if (err < 0)
			goto error;
		acc->resume_state[RES_CTRL_REG4] = updated_val;
		acc->sensitivity = sensitivity;
	}


	return 0;
error:
	dev_err(&acc->client->dev, "update g range failed 0x%x,0x%x: %d\n",
			buf[0], buf[1], err);

	return err;
}

int k3dh_acc_update_odr(struct k3dh_acc_data *acc, int poll_interval_ms)
{
	int err = -1;
	int i;
	u8 config[2];

	if(DEBUG_FUNC_TRACE & debug_mask)
	    printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

	if(poll_interval_ms == 0)
	    poll_interval_ms = 1000;

	if(DEBUG_INTR_INFO & debug_mask)
	    pr_info("%s: poll_interval_ms=%d\n", __func__,poll_interval_ms);

	/* Convert the poll interval into an output data rate configuration
	 *  that is as low as possible.  The ordering of these checks must be
	 *  maintained due to the cascading cut off values - poll intervals are
	 *  checked from shortest to longest.  At each check, if the next lower
	 *  ODR cannot support the current poll interval, we stop searching */
	for (i = ARRAY_SIZE(k3dh_acc_odr_table) - 1; i >= 0; i--) {
	    if (k3dh_acc_odr_table[i].cutoff_ms <= poll_interval_ms)
		break;
	}

	if(DEBUG_INTR_INFO & debug_mask)
	    pr_info("k3dh odr val = 0x%02X\n", k3dh_acc_odr_table[i].mask);
    
	config[1] = k3dh_acc_odr_table[i].mask;
	config[1] |= K3DH_ACC_ENABLE_ALL_AXES;

#ifdef USE_HR_TIMER
	hrtimer_cancel(&acc->htimer);
#endif
	/* If device is currently enabled, we need to write new
	 *  configuration out to it */
	if (atomic_read(&acc->enabled)) 
	{
	    config[0] = CTRL_REG1;
	    err = k3dh_acc_i2c_write(acc, config, 1);
	    if (err < 0)
			goto error;
	    acc->resume_state[RES_CTRL_REG1] = config[1];
#ifdef USE_HR_TIMER
		acc->polling_ktime = ns_to_ktime(MS_TO_NS(poll_interval_ms));
	    if(acc->enable)
			hrtimer_start(&acc->htimer, acc->polling_ktime, HRTIMER_MODE_REL);
#endif
	}

	return 0;

error:
	dev_err(&acc->client->dev, "update odr failed 0x%x,0x%x: %d\n",
			config[0], config[1], err);

	return err;
}


static int k3dh_acc_register_write(struct k3dh_acc_data *acc, u8 *buf,
		u8 reg_address, u8 new_value)
{
	int err = -1;

	if (atomic_read(&acc->enabled)) {
		/* Sets configuration register at reg_address
		 *  NOTE: this is a straight overwrite  */
		buf[0] = reg_address;
		buf[1] = new_value;
		err = k3dh_acc_i2c_write(acc, buf, 1);
		if (err < 0)
			return err;
	}
	return err;
}

static int k3dh_acc_register_read(struct k3dh_acc_data *acc, u8 *buf,
		u8 reg_address)
{
	int err = -1;
	buf[0] = (reg_address);
	err = k3dh_acc_i2c_read(acc, buf, 1);
	return err;
}

static int k3dh_acc_register_update(struct k3dh_acc_data *acc, u8 *buf,
		u8 reg_address, u8 mask, u8 new_bit_values)
{
    int err = -1;
    u8 init_val;
    u8 updated_val;
	
    if(DEBUG_FUNC_TRACE & debug_mask)
	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

    err = k3dh_acc_register_read(acc, buf, reg_address);
    if (!(err < 0)) 
    {
		init_val = buf[1];
		updated_val = ((mask & new_bit_values) | ((~mask) & init_val));
		err = k3dh_acc_register_write(acc, buf, reg_address, updated_val);
    }
    return err;
}

static int k3dh_acc_get_acceleration_data(struct k3dh_acc_data *acc,int *xyz)
{
    int err = -1;
    /* Data bytes from hardware xL, xH, yL, yH, zL, zH */
    u8 acc_data[6];
    /* x,y,z hardware data */
    s16 hw_d[3] = { 0 };

    acc_data[0] = (I2C_AUTO_INCREMENT | AXISDATA_REG);
    err = k3dh_acc_i2c_read(acc, acc_data, 6);
    if (err < 0)
	return err;

    hw_d[0] = (((s16) ((acc_data[1] << 8) | acc_data[0])) >> 4);
    hw_d[1] = (((s16) ((acc_data[3] << 8) | acc_data[2])) >> 4);
    hw_d[2] = (((s16) ((acc_data[5] << 8) | acc_data[4])) >> 4);

    //k3dh_xyz[0] = (unsigned char)(hw_d[0] >> 4);
    //k3dh_xyz[1] = (unsigned char)(hw_d[1] >> 4);
    //k3dh_xyz[2] = (unsigned char)(hw_d[2] >> 4);

    hw_d[0] = hw_d[0] * acc->sensitivity;
    hw_d[1] = hw_d[1] * acc->sensitivity;
    hw_d[2] = hw_d[2] * acc->sensitivity;

    k3dh_xyz[0] = xyz[0] = ((acc->pdata->negate_x) ? (-hw_d[acc->pdata->axis_map_x]) : (hw_d[acc->pdata->axis_map_x]));
    k3dh_xyz[1] = xyz[1] = ((acc->pdata->negate_y) ? (-hw_d[acc->pdata->axis_map_y]) : (hw_d[acc->pdata->axis_map_y]));
    k3dh_xyz[2] = xyz[2] = ((acc->pdata->negate_z) ? (-hw_d[acc->pdata->axis_map_z]) : (hw_d[acc->pdata->axis_map_z]));

    if(DEBUG_DEV_DEBOUNCE & debug_mask)
		printk(KERN_INFO "%s read x=%d, y=%d, z=%d\n",K3DH_ACC_DEV_NAME, xyz[0], xyz[1], xyz[2]);

    return err;
}

#ifndef CONFIG_LGE_SENSOR_FUSION
static int k3dh_guesture_click_src(struct k3dh_acc_data *acc,int *data)
{
    int err = -1;
    u8 buf[2];
    u8 val0[3];
    u8 val1[3];
    u8 sign;

    err = k3dh_acc_register_read(acc, buf, TT_SRC);
    if (err < 0)
	return err;

    if(buf[0])
    {
	val0[0] = (buf[0] & (1 << 0)) >> 0;
	val0[1] = (buf[0] & (1 << 1)) >> 1;
	val0[2] = (buf[0] & (1 << 2)) >> 2;
	sign    = (buf[0] & (1 << 3)) >> 3;

	val1[0] = val0[acc->pdata->axis_map_x];
	val1[1] = val0[acc->pdata->axis_map_y];
	val1[2] = val0[acc->pdata->axis_map_z];

	if(val1[0])
	{
	    if(acc->pdata->negate_x) 
	    {
		sign = sign ? 0 : 1;
	    }
	}
	else if(val1[1])
	{
	    if(acc->pdata->negate_y)
	    {
		sign = sign ? 0 : 1;
	    }	
	}
	else if(val1[2])
	{
	    if(acc->pdata->negate_z)
	    {
		sign = sign ? 0 : 1;
	    }
	}
    }

    *data = (buf[0] & 0xF0) | (val1[0] << 0) | (val1[1] << 1) | (val1[2] << 2) | (sign << 3);
  
    return err;
}


static int k3dh_guesture_intr_src(struct k3dh_acc_data *acc,int *data)
{
    int err = -1;
    u8 buf[2];

    err = k3dh_acc_register_read(acc, buf, INT_SRC1);
    if (err < 0)
	return err;

    *data = buf[0];
    return err;
}
#endif

static void k3dh_acc_report_values(struct k3dh_acc_data *acc, int *xyz)
{
    if(DEBUG_FUNC_TRACE & debug_mask)
	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);
	report_cnt ++;

    input_report_abs(acc->input_dev, ABS_X, xyz[0]);
    input_report_abs(acc->input_dev, ABS_Y, xyz[1]);
    input_report_abs(acc->input_dev, ABS_Z, xyz[2]);
    input_sync(acc->input_dev);
}

#ifndef CONFIG_LGE_SENSOR_FUSION

static void k3dh_tap_report_values(struct k3dh_acc_data *acc, int data)
{
    if(DEBUG_FUNC_TRACE & debug_mask)
    {
		printk(KERN_INFO "%s: line: %d,data=%x\n", __func__, __LINE__,data);
    }
  
    input_report_abs(acc->input_dev_tap, ABS_MISC, data);
    input_sync(acc->input_dev_tap);
}

static void k3dh_flip_report_values(struct k3dh_acc_data *acc, int *xyz, int data)
{
    if(DEBUG_FUNC_TRACE & debug_mask)
    {
		printk(KERN_INFO "%s: line: %d,data=%x\n", __func__, __LINE__,data);
    }
  
    if((data & (0x40|0x20)) == (0x40|0x20))
    {
		input_report_abs(acc->input_dev_flip, ABS_MISC, xyz[2]);
		input_sync(acc->input_dev_flip);
    }
}
#endif

static int k3dh_acc_enable(struct k3dh_acc_data *acc, int dev_id)
{
    int err;
    
    if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d\n",__func__, __LINE__);

    if(dev_id == ID_RESUME)
    {
		acc->resume = 1;
   		//if (!atomic_cmpxchg(&acc->enabled, 0, acc->on_before_suspend)) 
    	if(acc->on_before_suspend||acc->on_before_early_suspend)
		{
			if(acc->on_before_suspend)
	    	atomic_set(&acc->enabled, acc->on_before_suspend);
			else if (acc->on_before_early_suspend)
				atomic_set(&acc->enabled, acc->on_before_early_suspend);
		    if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_INFO "%s: line: %d, call power on!\n",__func__, __LINE__);
		    err = k3dh_acc_device_power_on(acc);
		    if(err < 0)
		    {
				atomic_set(&acc->enabled, 0);
				return err;
		    }

		    if(acc->pdata->poll_interval == 0)
		    {
				pr_err("%s: poll_interval = %d\n",__func__, acc->pdata->poll_interval);
		    }
#ifdef USE_HR_TIMER
			acc->polling_ktime = ns_to_ktime(MS_TO_NS(acc->pdata->poll_interval));
			hrtimer_start(&acc->htimer,
					acc->polling_ktime, HRTIMER_MODE_REL);
#else
		    schedule_delayed_work(&acc->input_work, 
	                            msecs_to_jiffies(acc->pdata->poll_interval));
#endif
		}
    }
    else
    {
		if(!acc->enable)
		{
		    if (!atomic_cmpxchg(&acc->enabled, 0, 1)) 
			{      
#ifdef CONFIG_LGE_SENSOR_FUSION
				acc->enable |= (ena_mask[ID_ACC]);
#else
				acc->enable |= (ena_mask[dev_id]);
#endif
				if(DEBUG_DEV_STATUS & debug_mask)
					printk(KERN_INFO "%s: line: %d, call power on!\n",__func__, __LINE__);

				err = k3dh_acc_device_power_on(acc);
				if(err < 0)
				{
					atomic_set(&acc->enabled, 0);
#ifdef CONFIG_LGE_SENSOR_FUSION		
					acc->enable &= ~( ena_mask[ID_ACC]);
#else
					acc->enable &= ~( ena_mask[dev_id]);
#endif
					return err;
				}

				if(acc->pdata->poll_interval == 0)
				{
					pr_err("%s: poll_interval = %d\n",__func__, acc->pdata->poll_interval);
				}
#ifdef USE_HR_TIMER
				acc->polling_ktime = ns_to_ktime(MS_TO_NS(acc->pdata->poll_interval));
				hrtimer_start(&acc->htimer,
						acc->polling_ktime, HRTIMER_MODE_REL);
#else
				schedule_delayed_work(&acc->input_work, 
					    msecs_to_jiffies(acc->pdata->poll_interval));
#endif
			}
		}
		else
		{
#ifdef CONFIG_LGE_SENSOR_FUSION	
			acc->enable |= (ena_mask[ID_ACC]);
#else
			acc->enable |= (ena_mask[dev_id]);
#endif
		}
	}

	return 0;
}

static int k3dh_acc_disable(struct k3dh_acc_data *acc, int dev_id)
{
	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line:%d, id(%d)",__func__, __LINE__, dev_id);

	if(dev_id == ID_RESUME)
	{
		acc->resume = 0;
		if(acc->on_before_suspend||acc->on_before_early_suspend)
		{
			atomic_set(&acc->enabled, 0);
#ifdef USE_HR_TIMER
			hrtimer_cancel(&acc->htimer);
			cancel_work_sync(&acc->hr_work);
			flush_workqueue(acc->hr_work_q);
#else
			cancel_delayed_work_sync(&acc->input_work);
#endif
		    if(DEBUG_DEV_STATUS & debug_mask)
				printk(KERN_INFO "%s: line: %d, call power off!\n",__func__, __LINE__);

			k3dh_acc_device_power_off(acc);
		}
	}
	else
	{
#ifdef CONFIG_LGE_SENSOR_FUSION    
		acc->enable &= ~(ena_mask[ID_ACC]);
#else
		acc->enable &= ~(ena_mask[dev_id]);
#endif
		if(acc->enable == 0)
		{
			atomic_set(&acc->enabled, 0);
#ifdef USE_HR_TIMER
			hrtimer_cancel(&acc->htimer);
			cancel_work_sync(&acc->hr_work);
			flush_workqueue(acc->hr_work_q);
#else
			cancel_delayed_work_sync(&acc->input_work);
#endif
			k3dh_acc_device_power_off(acc);
		}
	}

	return 0;
}

static int k3dh_acc_misc_open(struct inode *inode, struct file *file)
{
    int err;
	
    err = nonseekable_open(inode, file);
    if (err < 0)
	return err;

    if(DEBUG_FUNC_TRACE & debug_mask)
	printk(KERN_INFO "%s: line:%d",__func__, __LINE__);
	
    file->private_data = k3dh_acc_misc_data;

    return 0;
}

static int k3dh_acc_misc_ioctl(struct inode *inode, struct file *file,
		unsigned int cmd, unsigned long arg)
{
    void __user *argp = (void __user *)arg;
    u8 buf[4];
    u8 mask;
    u8 reg_address;
    u8 bit_values;
    int err = 0;
    int interval;
	int buff[4];
    struct k3dh_acc_data *acc = file->private_data;

    if(acc->enable == 0) 
    {
	if(DEBUG_FUNC_TRACE & debug_mask)
	    printk(KERN_INFO "k3dh_acc_misc is not enabled..\n");
	    return 0;
    }
    if(DEBUG_FUNC_TRACE & debug_mask)
	printk(KERN_INFO "%s: %s call with cmd 0x%x and arg 0x%x\n",
		K3DH_ACC_DEV_NAME, __func__, cmd, (unsigned int)arg);

    switch (cmd) {
	case K3DH_ACC_IOCTL_GET_DELAY:
	    interval = acc->pdata->poll_interval;
	    if (copy_to_user(argp, &interval, sizeof(interval)))
		return -EFAULT;
	    break;

	case K3DH_ACC_IOCTL_SET_DELAY:
	    if (copy_from_user(&interval, argp, sizeof(interval)))
		return -EFAULT;
	    if (interval < 0 || interval > 1000)
		return -EINVAL;

	    acc->pdata->poll_interval = max(interval,
			acc->pdata->min_interval);
	    err = k3dh_acc_update_odr(acc, acc->pdata->poll_interval);
		/* TODO: if update fails poll is still set */
	    if (err < 0)
		return err;
	    break;

	case K3DH_ACC_IOCTL_SET_ENABLE:
	    if (copy_from_user(&interval, argp, sizeof(interval)))
		return -EFAULT;
	    if (interval > 1)
		return -EINVAL;

#if !defined(NEW_DRIVER)
	    if (interval)
		err = k3dh_acc_enable(acc);
	    else
		err = k3dh_acc_disable(acc);
#endif

#if 0
		if (interval)
			err = k3dh_acc_enable(k3dh_acc_misc_data, ID_ACC);
		else
			err = k3dh_acc_disable(k3dh_acc_misc_data, ID_ACC);
#endif
	    return err;
	    break;

	case K3DH_ACC_IOCTL_GET_ENABLE:
	    interval = atomic_read(&acc->enabled);
	    if (copy_to_user(argp, &interval, sizeof(interval)))
		return -EINVAL;
	    break;

	case K3DH_ACC_IOCTL_SET_G_RANGE:
	    if (copy_from_user(buf, argp, 1))
		return -EFAULT;
	    bit_values = buf[0];
	    err = k3dh_acc_update_g_range(acc, bit_values);
	    if (err < 0)
		return err;
	    break;

#ifdef INTERRUPT_MANAGEMENT
	case K3DH_ACC_IOCTL_SET_CTRL_REG3:
	    if (copy_from_user(buf, argp, 2))
		return -EFAULT;
	    reg_address = CTRL_REG3;
	    mask = buf[1];
	    bit_values = buf[0];
	    err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
		mask, bit_values);
	    if (err < 0)
		return err;
	    acc->resume_state[RES_CTRL_REG3] = ((mask & bit_values) |
			( ~mask & acc->resume_state[RES_CTRL_REG3]));
	    break;

	case K3DH_ACC_IOCTL_SET_CTRL_REG6:
		if (copy_from_user(buf, argp, 2))
			return -EFAULT;
		reg_address = CTRL_REG6;
		mask = buf[1];
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_CTRL_REG6] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_CTRL_REG6]));
		break;

	case K3DH_ACC_IOCTL_SET_DURATION1:
		if (copy_from_user(buf, argp, 1))
			return -EFAULT;
		reg_address = INT_DUR1;
		mask = 0x7F;
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_INT_DUR1] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_INT_DUR1]));
		break;

	case K3DH_ACC_IOCTL_SET_THRESHOLD1:
		if (copy_from_user(buf, argp, 1))
			return -EFAULT;
		reg_address = INT_THS1;
		mask = 0x7F;
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_INT_THS1] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_INT_THS1]));
		break;

	case K3DH_ACC_IOCTL_SET_CONFIG1:
		if (copy_from_user(buf, argp, 2))
			return -EFAULT;
		reg_address = INT_CFG1;
		mask = buf[1];
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_INT_CFG1] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_INT_CFG1]));
		break;

	case K3DH_ACC_IOCTL_GET_SOURCE1:
		err = k3dh_acc_register_read(acc, buf, INT_SRC1);
		if (err < 0)
			return err;
		if(DEBUG_FUNC_TRACE & debug_mask)
			printk(KERN_ALERT "INT1_SRC content: %d , 0x%x\n", buf[0], buf[0]);
	
		if (copy_to_user(argp, buf, 1))
			return -EINVAL;
		break;

	case K3DH_ACC_IOCTL_SET_DURATION2:
		if (copy_from_user(buf, argp, 1))
			return -EFAULT;
		reg_address = INT_DUR2;
		mask = 0x7F;
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_INT_DUR2] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_INT_DUR2]));
		break;

	case K3DH_ACC_IOCTL_SET_THRESHOLD2:
		if (copy_from_user(buf, argp, 1))
			return -EFAULT;
		reg_address = INT_THS2;
		mask = 0x7F;
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_INT_THS2] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_INT_THS2]));
		break;

	case K3DH_ACC_IOCTL_SET_CONFIG2:
		if (copy_from_user(buf, argp, 2))
			return -EFAULT;
		reg_address = INT_CFG2;
		mask = buf[1];
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_INT_CFG2] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_INT_CFG2]));
		break;

	case K3DH_ACC_IOCTL_GET_SOURCE2:
		err = k3dh_acc_register_read(acc, buf, INT_SRC2);
		if (err < 0)
			return err;
		
		if(DEBUG_FUNC_TRACE & debug_mask)
			printk(KERN_ALERT "INT2_SRC content: %d , 0x%x\n", buf[0], buf[0]);

		if (copy_to_user(argp, buf, 1))
			return -EINVAL;
		break;

	case K3DH_ACC_IOCTL_GET_TAP_SOURCE:
		err = k3dh_acc_register_read(acc, buf, TT_SRC);
		if (err < 0)
			return err;
		if(DEBUG_FUNC_TRACE & debug_mask)
			printk(KERN_ALERT "TT_SRC content: %d , 0x%x\n", buf[0], buf[0]);
		
		if (copy_to_user(argp, buf, 1)) {
			printk(KERN_ERR "%s: %s error in copy_to_user \n",
					K3DH_ACC_DEV_NAME, __func__);
			return -EINVAL;
		}
		break;

	case K3DH_ACC_IOCTL_SET_TAP_CFG:
		if (copy_from_user(buf, argp, 2))
			return -EFAULT;
		reg_address = TT_CFG;
		mask = buf[1];
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_TT_CFG] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_TT_CFG]));
		break;

	case K3DH_ACC_IOCTL_SET_TAP_TLIM:
		if (copy_from_user(buf, argp, 2))
			return -EFAULT;
		reg_address = TT_LIM;
		mask = buf[1];
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_TT_LIM] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_TT_LIM]));
		break;

	case K3DH_ACC_IOCTL_SET_TAP_THS:
		if (copy_from_user(buf, argp, 2))
			return -EFAULT;
		reg_address = TT_THS;
		mask = buf[1];
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_TT_THS] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_TT_THS]));
		break;

	case K3DH_ACC_IOCTL_SET_TAP_TLAT:
		if (copy_from_user(buf, argp, 2))
			return -EFAULT;
		reg_address = TT_TLAT;
		mask = buf[1];
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_TT_TLAT] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_TT_TLAT]));
		break;

	case K3DH_ACC_IOCTL_SET_TAP_TW:
		if (copy_from_user(buf, argp, 2))
			return -EFAULT;
		reg_address = TT_TW;
		mask = buf[1];
		bit_values = buf[0];
		err = k3dh_acc_register_update(acc, (u8 *) arg, reg_address,
				mask, bit_values);
		if (err < 0)
			return err;
		acc->resume_state[RES_TT_TW] = ((mask & bit_values) |
				( ~mask & acc->resume_state[RES_TT_TW]));
		break;

#endif /* INTERRUPT_MANAGEMENT */

	case K3DH_ACC_IOCTL_READ_ACCEL_XYZ:
		err = k3dh_acc_get_acceleration_data(acc, (int *)buff);
		if (err < 0)
				return err;

		if (copy_to_user(argp, buff, sizeof(int)*3)){
			printk(KERN_ERR "%s: %s error in copy_to_user \n",
					K3DH_ACC_DEV_NAME, __func__);
			return -EINVAL;
		}


		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static const struct file_operations k3dh_acc_misc_fops = {
		.owner = THIS_MODULE,
		.open = k3dh_acc_misc_open,
		.ioctl = k3dh_acc_misc_ioctl,
};

static struct miscdevice k3dh_acc_misc_device = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = K3DH_ACC_DEV_NAME,
		.fops = &k3dh_acc_misc_fops,
};

static void k3dh_acc_input_work_func(struct work_struct *work)
{
	struct k3dh_acc_data *acc;

	int xyz[3] = { 0 };
#ifndef CONFIG_LGE_SENSOR_FUSION
	int  click    = 0;
	int  intr_src = 0;
#endif
	int err;

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

#ifdef USE_HR_TIMER	
	acc = container_of((struct work_struct *)work,
			struct k3dh_acc_data,	hr_work);
#else
	acc = container_of((struct delayed_work *)work,
			struct k3dh_acc_data,	input_work);
	mutex_lock(&acc->lock);
#endif


	err = k3dh_acc_get_acceleration_data(acc, xyz);
	if (err < 0)
	{
		dev_err(&acc->client->dev, "get_acceleration_data failed\n");
	}
#ifndef CONFIG_LGE_SENSOR_FUSION  
	err = k3dh_guesture_click_src(acc, &click);
	if (err < 0)
	{
 		dev_err(&acc->client->dev, "k3dh_guesture_click_src failed\n");
  }
  
	err = k3dh_guesture_intr_src(acc, &intr_src);
	if (err < 0)
	{
 		dev_err(&acc->client->dev, "k3dh_guesture_intr_src failed\n");
  }
#endif

  if(acc->enable & (ena_mask[ID_ACC]))
  {
    k3dh_acc_report_values(acc,xyz);
  }

#ifndef CONFIG_LGE_SENSOR_FUSION
  if(acc->enable & (ena_mask[ID_TAP]))
  {
    k3dh_tap_report_values(acc,click);
  }
  if(acc->enable & (ena_mask[ID_FLIP]))
  {
    k3dh_flip_report_values(acc,xyz,intr_src);
  }
#endif

#ifdef USE_HR_TIMER
	hrtimer_start(&acc->htimer,
		acc->polling_ktime, HRTIMER_MODE_REL);
#else
	schedule_delayed_work(&acc->input_work, msecs_to_jiffies(
			acc->pdata->poll_interval));
	mutex_unlock(&acc->lock);
#endif
}


#ifdef USE_HR_TIMER
static enum hrtimer_restart k3dh_acc_timer_work_func(struct hrtimer *timer)
{
	struct k3dh_acc_data *acc = container_of(timer, struct k3dh_acc_data, htimer);
	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line %d\n", __func__, __LINE__);

	queue_work(acc->hr_work_q, &acc->hr_work);

	return HRTIMER_NORESTART;
}
#endif

#ifdef K3DH_ACC_OPEN_ENABLE
int k3dh_acc_input_open(struct input_dev *input)
{
	struct k3dh_acc_data *acc = input_get_drvdata(input);
	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);
	
	return k3dh_acc_enable(acc);
}

void k3dh_acc_input_close(struct input_dev *dev)
{
	struct k3dh_acc_data *acc = input_get_drvdata(dev);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);
	
	k3dh_acc_disable(acc);
}
#endif

static int k3dh_acc_validate_pdata(struct k3dh_acc_data *acc)
{
  acc->pdata->poll_interval = max(acc->pdata->poll_interval,
  acc->pdata->min_interval);

  if(DEBUG_FUNC_TRACE & debug_mask)
    printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  if (acc->pdata->axis_map_x > 2 || acc->pdata->axis_map_y > 2 || acc->pdata->axis_map_z > 2) 
  {
    dev_err(&acc->client->dev, "invalid axis_map value x:%u y:%u z%u\n",
                                acc->pdata->axis_map_x, acc->pdata->axis_map_y, acc->pdata->axis_map_z);
    return -EINVAL;
  }

  /* Only allow 0 and 1 for negation boolean flag */
  if (acc->pdata->negate_x > 1 || acc->pdata->negate_y > 1 || acc->pdata->negate_z > 1) 
  {
    dev_err(&acc->client->dev, "invalid negate value x:%u y:%u z:%u\n", 
                                acc->pdata->negate_x, acc->pdata->negate_y, acc->pdata->negate_z);
    return -EINVAL;
  }

  /* Enforce minimum polling interval */
  if (acc->pdata->poll_interval < acc->pdata->min_interval) 
  {
    dev_err(&acc->client->dev, "minimum poll interval violated\n");
    return -EINVAL;
  }

  if(DEBUG_FUNC_TRACE & debug_mask)
  printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  return 0;
}

int k3dh_update_delay(void)
{
    int ms;
 
    if(k3dh_acc_misc_data->acc_poll_ms == 0)
		k3dh_acc_misc_data->acc_poll_ms = 1000;

    if(k3dh_acc_misc_data->gesture_poll_ms == 0)
		k3dh_acc_misc_data->gesture_poll_ms = 1000;
 
    ms = min(k3dh_acc_misc_data->acc_poll_ms,k3dh_acc_misc_data->gesture_poll_ms);
  
    if(DEBUG_INTR_INFO & debug_mask)
		printk(KERN_INFO "%s: line: %d, acc_poll(%d), gesture_poll(%d), ms(%d)\n",__func__, __LINE__, k3dh_acc_misc_data->acc_poll_ms,k3dh_acc_misc_data->gesture_poll_ms,ms);

    k3dh_acc_misc_data->pdata->poll_interval = ms;
    return k3dh_acc_update_odr(k3dh_acc_misc_data, k3dh_acc_misc_data->pdata->poll_interval);
}

// I-project Middleware Interface
static ssize_t k3dh_show_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
    if(DEBUG_SYSFS_INFO & debug_mask)
		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);
#ifdef CONFIG_LGE_SENSOR_FUSION
	if(k3dh_acc_misc_data->enable)
#else
    if(k3dh_acc_misc_data->enable & ena_mask[ID_ACC])
#endif
    {
		return sprintf(buf, "1\n");
    }
    else
    {
		return sprintf(buf, "0\n");
    }
}

static ssize_t k3dh_store_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    unsigned long val = simple_strtoul(buf, NULL, 10);

    if(DEBUG_SYSFS_INFO & debug_mask)
	printk(KERN_INFO "%s: line: %d, val = %d \n", __func__, __LINE__, (int)val);

    if(val == 0)
    {
		return k3dh_acc_disable(k3dh_acc_misc_data,ID_ACC);
    }
    else
    {
	    report_cnt = 0;
		return k3dh_acc_enable(k3dh_acc_misc_data,ID_ACC);
    }
}

static DEVICE_ATTR(enable, S_IRUGO|S_IWUSR, k3dh_show_enable, k3dh_store_enable);

static ssize_t k3dh_show_delay(struct device *dev, struct device_attribute *attr, char *buf)
{
    int val;

    // ms -> ns
    val = k3dh_acc_misc_data->pdata->poll_interval * 1000000;

    return sprintf(buf, "%d\n", val);
}

static ssize_t k3dh_store_delay(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    int val = (int)simple_strtoul(buf, NULL, 10);

    if(DEBUG_DEV_STATUS & debug_mask)
		printk(KERN_INFO "%s: line: %d = %d \n", __func__, __LINE__, (int)val);

    // ns -> ms
    if(val != 0) val = val / 1000000;
  
    if (val < 0 || val > 1000)
    {
		pr_err("%s, out of range(0~100) : %d\n",__func__,val);
		return -1;
    }

    k3dh_acc_misc_data->acc_poll_ms = (int)val;
  
    return k3dh_update_delay();
}

static DEVICE_ATTR(poll_delay, S_IRUGO|S_IWUSR, k3dh_show_delay, k3dh_store_delay);

static int k3dh_acc_input_init(struct k3dh_acc_data *acc)
{
  int err;

  if(DEBUG_FUNC_TRACE & debug_mask)
  	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

#ifndef USE_HR_TIMER
  INIT_DELAYED_WORK(&acc->input_work, k3dh_acc_input_work_func);
#endif

  acc->input_dev = input_allocate_device();

  if(!acc->input_dev)
  {
    err = -ENOMEM;
    dev_err(&acc->client->dev, "input device allocate failed\n");
    goto err0;
  }


#ifdef K3DH_ACC_OPEN_ENABLE
	acc->input_dev->open = k3dh_acc_input_open;
 	acc->input_dev->close = k3dh_acc_input_close;
#endif

 	input_set_drvdata(acc->input_dev, acc);

  	set_bit(EV_ABS, acc->input_dev->evbit);
  	/*	next is used for interruptA sources data if the case */
  	set_bit(ABS_MISC, acc->input_dev->absbit);
  	/*	next is used for interruptB sources data if the case */
  	set_bit(ABS_WHEEL, acc->input_dev->absbit);

  	input_set_abs_params(acc->input_dev, ABS_X, -G_MAX, G_MAX, FUZZ, FLAT);
  	input_set_abs_params(acc->input_dev, ABS_Y, -G_MAX, G_MAX, FUZZ, FLAT);
  	input_set_abs_params(acc->input_dev, ABS_Z, -G_MAX, G_MAX, FUZZ, FLAT);
  	/*	next is used for interruptA sources data if the case */
  	input_set_abs_params(acc->input_dev, ABS_MISC, INT_MIN, INT_MAX, 0, 0);
  	/*	next is used for interruptB sources data if the case */
  	input_set_abs_params(acc->input_dev, ABS_WHEEL, INT_MIN, INT_MAX, 0, 0);

  	acc->input_dev->name = "accelerometer";

  	err = input_register_device(acc->input_dev);
  	if(err)
  	{
    	dev_err(&acc->client->dev,
      		"unable to register input polled device %s\n",acc->input_dev->name);
    	goto err1;
  	}



  	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  	return 0;

err1:
	  input_free_device(acc->input_dev);
err0:
  	return err;
}

static void k3dh_acc_input_cleanup(struct k3dh_acc_data *acc)
{
	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  	input_unregister_device(acc->input_dev);
  	input_free_device(acc->input_dev);
}

#ifndef CONFIG_LGE_SENSOR_FUSION

static int k3dh_regs_update(struct k3dh_acc_data *acc, u8 reg_addr, int res_addr, u8 value)
{
  	int err;
  	u8 buf[2];
  
  	err = k3dh_acc_register_write(acc,buf,reg_addr,value);

  	if(err < 0)
  	{
    	return err;
  	}
  
  	acc->resume_state[res_addr] = value;
  	return 0;
}
static ssize_t k3dh_show_tap_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
    if(k3dh_acc_misc_data->enable & ena_mask[ID_TAP])
    {
	return sprintf(buf, "1\n");
    }
    else
    {
	return sprintf(buf, "0\n");
    }
}
static ssize_t k3dh_store_tap_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
 	unsigned long val = simple_strtoul(buf, NULL, 10);
  
  	if(DEBUG_INTR_INFO & debug_mask)
  		printk(KERN_INFO "%s: line: %d = %d \n", __func__, __LINE__, (int)val);

  	if(val == 0)
  	{
    	k3dh_regs_update(k3dh_acc_misc_data,TT_CFG,RES_TT_CFG,0x00);
    	k3dh_regs_update(k3dh_acc_misc_data,CTRL_REG3,RES_CTRL_REG3,0x00);
 		k3dh_acc_misc_data->gesture_poll_ms = 1000;
		k3dh_update_delay();
    	k3dh_acc_disable(k3dh_acc_misc_data,ID_TAP);
    	return 0;
  	}
  	else
  	{
    	k3dh_acc_enable(k3dh_acc_misc_data,ID_TAP);
    	/* enable single click-click */
    	k3dh_regs_update(k3dh_acc_misc_data,TT_CFG,RES_TT_CFG,((1<<4)|(1<<2)|(1<<0)));
    	/* set click-click threshold */
    	k3dh_regs_update(k3dh_acc_misc_data,TT_THS,RES_TT_THS,(0x50|0x80));//(0x67|0x80)
    	/* set click-click time limit */
    	k3dh_regs_update(k3dh_acc_misc_data,TT_LIM,RES_TT_LIM,0x03);
    	/* set click-click time latency */
    	k3dh_regs_update(k3dh_acc_misc_data,TT_TLAT,RES_TT_TLAT,0x60);
    	/* set click-click time window */
    	k3dh_regs_update(k3dh_acc_misc_data,TT_TW,RES_TT_TW,0x00);
 		/*set ODR 1250*/
 		k3dh_acc_misc_data->gesture_poll_ms = 1;
		k3dh_update_delay();
		k3dh_acc_update_g_range(k3dh_acc_misc_data,K3DH_ACC_G_4G);
		/* interrupt 1 duration */
    	k3dh_regs_update(k3dh_acc_misc_data,INT_DUR1,RES_INT_DUR1,1);
    	/* interrupt 1 threshold */
    	k3dh_regs_update(k3dh_acc_misc_data,INT_THS1,RES_INT_THS1,29);
    	/* interrupt 1 config : enable z-high */
    	k3dh_regs_update(k3dh_acc_misc_data,INT_CFG1,RES_INT_CFG1,20);
    	k3dh_regs_update(k3dh_acc_misc_data,CTRL_REG6,RES_CTRL_REG6,00);
    	k3dh_regs_update(k3dh_acc_misc_data,CTRL_REG3,RES_CTRL_REG3,(0x80|0x40)); 

    	return 0;
  	}
}

static DEVICE_ATTR(tap_enable, S_IWUSR|S_IRUGO, k3dh_show_tap_enable, k3dh_store_tap_enable);

static ssize_t k3dh_show_tap_delay(struct device *dev, struct device_attribute *attr, char *buf)
{
  	int val;

  	// ms -> ns
  	val = k3dh_acc_misc_data->pdata->poll_interval * 1000000;

  	return sprintf(buf, "%d\n", val);
}

static ssize_t k3dh_store_tap_delay(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    int val = (int)simple_strtoul(buf, NULL, 10);

    if(DEBUG_INTR_INFO & debug_mask)
		printk(KERN_INFO "%s: line: %d = %d \n", __func__, __LINE__, (int)val);

  	// ns -> ms
  	if(val != 0) val = val / 1000000;
  
  	if (val < 0 || val > 1000)
  	{
    	pr_err("%s, out of range(0~100) : %d\n",__func__,val);
    	return -1;
  	}

  	k3dh_acc_misc_data->gesture_poll_ms = (int)val;
  	return k3dh_update_delay();
}

static DEVICE_ATTR(tap_delay, S_IRUGO|S_IWUSR, k3dh_show_tap_delay, k3dh_store_tap_delay);

static int k3dh_tap_input_init(struct k3dh_acc_data *acc)
{
  	int err;

  	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  	acc->input_dev_tap = input_allocate_device();
  	if (!acc->input_dev_tap)
  	{
    	err = -ENOMEM;
    	dev_err(&acc->client->dev, "input(tap) device allocate failed\n");
    	goto err0;
  	}
  
  	input_set_drvdata(acc->input_dev_tap, acc);

  	input_set_capability(acc->input_dev_tap, EV_ABS, ABS_MISC);
  	input_set_abs_params(acc->input_dev_tap, ABS_MISC, INT_MIN, INT_MAX, 0, 0);
	//  input_set_abs_params(acc->input_dev_tap, ABS_WHEEL, INT_MIN, INT_MAX, 0, 0);

  	acc->input_dev_tap->name = "gesture_tap";
  	err = input_register_device(acc->input_dev_tap);

  	if(err) 
  	{
    	dev_err(&acc->client->dev,"unable to register input device %s\n",acc->input_dev_tap->name);
    	goto err1;
  	}

  	err = device_create_file(&acc->input_dev_tap->dev, &dev_attr_tap_enable);
  	err = device_create_file(&acc->input_dev_tap->dev, &dev_attr_tap_delay);

  	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  	return 0;

err1:
  	input_free_device(acc->input_dev_tap);
err0:
  	return err;
}


static void k3dh_tap_input_cleanup(struct k3dh_acc_data *acc)
{
  	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  	input_unregister_device(acc->input_dev_tap);
  	input_free_device(acc->input_dev_tap);
}


static ssize_t k3dh_show_flip_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
  	if(k3dh_acc_misc_data->enable & ena_mask[ID_FLIP])
  	{
    	return sprintf(buf, "1\n");
 	}
  	else
  	{
    	return sprintf(buf, "0\n");
  	}
}

static ssize_t k3dh_store_flip_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
  	unsigned long val = simple_strtoul(buf, NULL, 10);
  
  	if(DEBUG_INTR_INFO & debug_mask)
  		printk(KERN_INFO "%s: line: %d = %d \n", __func__, __LINE__, (int)val);

  	if(val == 0)
  	{
    	k3dh_regs_update(k3dh_acc_misc_data,TT_CFG,RES_TT_CFG,0x00);
    	k3dh_regs_update(k3dh_acc_misc_data,CTRL_REG3,RES_CTRL_REG3,0x00);
 		k3dh_acc_misc_data->gesture_poll_ms = 1000;
		k3dh_update_delay();
    	k3dh_acc_disable(k3dh_acc_misc_data,ID_FLIP);
    	return 0;
  	}
  	else
  	{
    	k3dh_acc_enable(k3dh_acc_misc_data,ID_FLIP);
    	k3dh_regs_update(k3dh_acc_misc_data,TT_CFG,RES_TT_CFG,0x15);
    	k3dh_regs_update(k3dh_acc_misc_data,TT_THS,RES_TT_THS,(0x67|0x80));
    	k3dh_regs_update(k3dh_acc_misc_data,TT_LIM,RES_TT_LIM,0x03);
    	k3dh_regs_update(k3dh_acc_misc_data,TT_TLAT,RES_TT_TLAT,0x60);
    	k3dh_regs_update(k3dh_acc_misc_data,TT_TW,RES_TT_TW,0x00);
 		/*set ODR 1250*/
 		k3dh_acc_misc_data->gesture_poll_ms = 1;
		k3dh_update_delay();
		k3dh_acc_update_g_range(k3dh_acc_misc_data,K3DH_ACC_G_4G);
    	k3dh_regs_update(k3dh_acc_misc_data,INT_DUR1,RES_INT_DUR1,1);
    	k3dh_regs_update(k3dh_acc_misc_data,INT_THS1,RES_INT_THS1,29);
    	k3dh_regs_update(k3dh_acc_misc_data,INT_CFG1,RES_INT_CFG1,20); /* enable z-high */
    	k3dh_regs_update(k3dh_acc_misc_data,CTRL_REG6,RES_CTRL_REG6,00);
    	k3dh_regs_update(k3dh_acc_misc_data,CTRL_REG3,RES_CTRL_REG3,(0x80|0x40)); 

    	return 0;
  	}
}
static DEVICE_ATTR(flip_enable, S_IWUSR|S_IRUGO, k3dh_show_flip_enable, k3dh_store_flip_enable);

static ssize_t k3dh_show_flip_delay(struct device *dev, struct device_attribute *attr, char *buf)
{
  	int val;

  	// ms -> ns
  	val = k3dh_acc_misc_data->pdata->poll_interval * 1000000;

  	return sprintf(buf, "%d\n", val);
}

static ssize_t k3dh_store_flip_delay(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
  	int val = (int)simple_strtoul(buf, NULL, 10);

  	if(DEBUG_INTR_INFO & debug_mask)
  		printk(KERN_INFO "%s: line: %d = %d \n", __func__, __LINE__, (int)val);

  	// ns -> ms
  	if(val != 0) val = val / 1000000;
  
  	if (val < 0 || val > 1000)
  	{
    	pr_err("%s, out of range(0~100) : %d\n",__func__,val);
    	return -1;
  	}
  	k3dh_acc_misc_data->gesture_poll_ms = (int)val;
  	return k3dh_update_delay();
}

static DEVICE_ATTR(flip_delay, S_IRUGO|S_IWUSR, k3dh_show_flip_delay, k3dh_store_flip_delay);

static int k3dh_flip_input_init(struct k3dh_acc_data *acc)
{
  	int err;

  	if(DEBUG_FUNC_TRACE & debug_mask)
  		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  	acc->input_dev_flip = input_allocate_device();
  	if (!acc->input_dev_flip)
  	{
    	err = -ENOMEM;
    	dev_err(&acc->client->dev, "input(tap) device allocate failed\n");
    	goto err0;
  	}
  
  	input_set_drvdata(acc->input_dev_flip, acc);
  	input_set_capability(acc->input_dev_flip, EV_ABS, ABS_MISC);
  	input_set_abs_params(acc->input_dev_flip, ABS_MISC, INT_MIN, INT_MAX, 0, 0);

  	acc->input_dev_flip->name = "gesture_flip";
  	err = input_register_device(acc->input_dev_flip);

  	if(err) 
  	{
    	dev_err(&acc->client->dev,"unable to register input device %s\n",acc->input_dev_flip->name);
    	goto err1;
  	}

  	err = device_create_file(&acc->input_dev_flip->dev, &dev_attr_flip_enable);
  	err = device_create_file(&acc->input_dev_flip->dev, &dev_attr_flip_delay);

  	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  	return 0;

err1:
  	input_free_device(acc->input_dev_flip);
err0:
  	return err;
}



static void k3dh_flip_input_cleanup(struct k3dh_acc_data *acc)
{
  	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  	input_unregister_device(acc->input_dev_flip);
  	input_free_device(acc->input_dev_flip);
}
#endif //CONFIG_LGE_SENSOR_FUSION

static ssize_t k3dh_show_report_cnt(struct device *dev, struct device_attribute *attr, char *buf)
{
	printk(KERN_INFO "%s: report_cnt: %d\n", __func__, report_cnt);

	if(k3dh_acc_misc_data->enable & ena_mask[ID_ACC])
		return sprintf(buf, "%d\n", report_cnt);
	else
		return sprintf(buf, "%d\n", -1);
}

static ssize_t k3dh_show_x(struct device *dev, struct device_attribute *attr, char *buf)
{
	printk(KERN_INFO "%s: x: %d\n", __func__, k3dh_xyz[0]);

	if(k3dh_acc_misc_data->enable & ena_mask[ID_ACC])
		return sprintf(buf, "%d\n", k3dh_xyz[0]);
	else
		return sprintf(buf, "%d\n", -1);
}

static ssize_t k3dh_show_y(struct device *dev, struct device_attribute *attr, char *buf)
{
	printk(KERN_INFO "%s: y: %d\n", __func__, k3dh_xyz[1]);

	if(k3dh_acc_misc_data->enable & ena_mask[ID_ACC])
		return sprintf(buf, "%d\n", k3dh_xyz[1]);
	else
		return sprintf(buf, "%d\n", -1);
}

static ssize_t k3dh_show_z(struct device *dev, struct device_attribute *attr, char *buf)
{
	printk(KERN_INFO "%s: z: %d\n", __func__, k3dh_xyz[2]);

	if(k3dh_acc_misc_data->enable & ena_mask[ID_ACC])
		return sprintf(buf, "%d\n", k3dh_xyz[2]);
	else
		return sprintf(buf, "%d\n", -1);
}

#ifdef K3DH_USER_CALIBRATION
int calibration_status = 0;
int calibration_result = 0;

static ssize_t k3dh_show_calibration(struct device *dev, struct device_attribute *attr, char *buf)
{
	// read offset file and print
	//if(DEBUG_SYSFS_INFO & debug_mask)
	//	printk(KERN_INFO "%s ### calibration_status = %d\n", K3DH_ACC_DEV_NAME, calibration_status);
	// print no file
	return sprintf(buf, "%d\n", calibration_status);
}

static ssize_t k3dh_store_calibration(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{  
	if(DEBUG_SYSFS_INFO & debug_mask)
		printk(KERN_INFO "%s write to calibration %s\n", K3DH_ACC_DEV_NAME, buf);
	
	if (sysfs_streq(buf, "1"))
	{
		calibration_status = 1;
	}
	else if (sysfs_streq(buf, "0"))
	{
		calibration_status = 0;
	}
	else if(sysfs_streq(buf, "2"))
	{
		calibration_status = 2;
	}
	else if(sysfs_streq(buf, "3"))
	{
		calibration_status = 3;
	}
	else if(sysfs_streq(buf, "4"))
	{
		calibration_status = 4;
	}
	else if(sysfs_streq(buf, "5"))
	{
		calibration_status = 5;
	}
	else
	{
		calibration_status = 9;
	}
		
	
	return count;
}

static DEVICE_ATTR(calibration, S_IRUGO|S_IWUSR, k3dh_show_calibration, k3dh_store_calibration);
#endif

static DEVICE_ATTR(acc_cal, S_IRUGO|S_IWUSR, k3dh_show_calibration, k3dh_store_calibration);
static DEVICE_ATTR(cnt, S_IRUGO, k3dh_show_report_cnt, NULL);
static DEVICE_ATTR(x, S_IRUGO, k3dh_show_x, NULL);
static DEVICE_ATTR(y, S_IRUGO, k3dh_show_y, NULL);
static DEVICE_ATTR(z, S_IRUGO, k3dh_show_z, NULL);
static struct attribute *k3dh_attributes[] = 
{
  	&dev_attr_enable.attr,
  	&dev_attr_poll_delay.attr,
	&dev_attr_acc_cal.attr,
	&dev_attr_cnt.attr,
  	&dev_attr_x.attr,
  	&dev_attr_y.attr,
  	&dev_attr_z.attr,
	NULL,
};
static const struct attribute_group k3dh_attr_group = 
{
  	.attrs = k3dh_attributes,
};

static int k3dh_acc_probe(struct i2c_client *client,const struct i2c_device_id *id)
{
  	struct k3dh_acc_data *acc;

  	int err = -1;
  	int tempvalue;

  	if(DEBUG_FUNC_TRACE & debug_mask)
  		pr_info("%s: probe start.\n", K3DH_ACC_DEV_NAME);

  	if (client->dev.platform_data == NULL) 
  	{
    	dev_err(&client->dev, "platform data is NULL. exiting.\n");
    	err = -ENODEV;
    	goto exit_check_functionality_failed;
  	}

  	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) 
  	{
    	dev_err(&client->dev, "client not i2c capable\n");
    	err = -ENODEV;
    	goto exit_check_functionality_failed;
  	}

  	if (!i2c_check_functionality(client->adapter, I2C_FUNC_SMBUS_BYTE      |
                                                I2C_FUNC_SMBUS_BYTE_DATA |
                                                I2C_FUNC_SMBUS_WORD_DATA)) 
  	{
    	dev_err(&client->dev, "client not smb-i2c capable:2\n");
    	err = -EIO;
    	goto exit_check_functionality_failed;
  	}

  	if (!i2c_check_functionality(client->adapter, I2C_FUNC_SMBUS_I2C_BLOCK))
 	{
    	dev_err(&client->dev, "client not smb-i2c capable:3\n");
    	err = -EIO;
    	goto exit_check_functionality_failed;
  	}
  /*
  * OK. From now, we presume we have a valid client. We now create the
  * client structure, even though we cannot fill it completely yet.
  */

  	acc = kzalloc(sizeof(struct k3dh_acc_data), GFP_KERNEL);

  	if (acc == NULL) 
  	{
    	err = -ENOMEM;
    	dev_err(&client->dev,
    	"failed to allocate memory for module data: "
    	"%d\n", err);
    	goto exit_alloc_data_failed;
  	}

  	mutex_init(&acc->lock);
  	mutex_lock(&acc->lock);

  	acc->pdata = kmalloc(sizeof(*acc->pdata), GFP_KERNEL);

  	if (acc->pdata == NULL) 
  	{
    	err = -ENOMEM;
    	dev_err(&client->dev,
	   "failed to allocate memory for pdata: %d\n",	err);
	   goto err_mutexunlockfreedata;
  	}

  	memcpy(acc->pdata, client->dev.platform_data, sizeof(*acc->pdata));

  	err = k3dh_acc_validate_pdata(acc);
  	if (err < 0) 
  	{
    	dev_err(&client->dev, "failed to validate platform data\n");
    	goto exit_kfree_pdata;
  	}

  	i2c_set_clientdata(client, acc);
  	acc->client = client;

	if(acc->pdata->gpio_int1 > 0)
 	{
  		INIT_WORK(&acc->irq1_work, k3dh_acc_irq1_work_func);
  		acc->irq1_work_queue = create_singlethread_workqueue("k3dh_acc_wq1");

  		if (!acc->irq1_work_queue) 
  		{
    		err = -ENOMEM;
    		dev_err(&client->dev, "cannot create work queue1: %d\n", err);
		   goto err_destoyworkqueue1;
  		}
	}

	if(acc->pdata->gpio_int2 > 0)
	{
  		INIT_WORK(&acc->irq2_work, k3dh_acc_irq2_work_func);
  		acc->irq2_work_queue = create_singlethread_workqueue("k3dh_acc_wq2");

  		if (!acc->irq2_work_queue) 
  		{
    		err = -ENOMEM;
    		dev_err(&client->dev, "cannot create work queue2: %d\n", err);
		   goto err_destoyworkqueue2;
  		}
	}
  	err = k3dh_acc_device_power_on(acc);
  	if (err < 0)
  	{
	   dev_err(&client->dev, "power on failed: %d\n", err);
	   goto err2;
  	}
#ifdef USE_HR_TIMER
	/* hrtimer settings.  we poll for gyro values using a timer. */
	hrtimer_init(&acc->htimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	acc->polling_ktime = ns_to_ktime(MS_TO_NS(acc->pdata->poll_interval));
	//delay_ns = ktime_to_ns(acc->polling_ktime);
	//do_div(delay_ns, data->time_to_read);
	acc->htimer.function = k3dh_acc_timer_work_func;

	/* the timer just fires off a work queue request.
	   We need a thread to read i2c (can be slow and blocking). */
	acc->hr_work_q = create_singlethread_workqueue("k3dh_hr_wq");
	if (!acc->hr_work_q) {
		err = -ENOMEM;
		dev_err(&client->dev, "hr_wq failed: %d\n", err);
		goto err2;
	}
	INIT_WORK(&acc->hr_work, k3dh_acc_input_work_func);
#endif

  	err = sysfs_create_group(&client->dev.kobj, &k3dh_attr_group);
  	if (err) 
  	{
    	printk(KERN_ERR "Unable to do sysfs_create_group");
    	goto exit;
  	}

  	if (i2c_smbus_read_byte(client) < 0) 
  	{
    	printk(KERN_ERR "i2c_smbus_read_byte error!!\n");
    	goto err_destoyworkqueue2;
  	} 
  	else 
  	{
   	 	printk(KERN_INFO "%s Device detected!\n", K3DH_ACC_DEV_NAME);
  	}

  	/* read chip id */
  	tempvalue = i2c_smbus_read_word_data(client, WHO_AM_I);
  	if ((tempvalue & 0x00FF) == WHOAMI_K3DH_ACC)
  	{
   	 	printk(KERN_INFO "%s I2C driver registered!\n", K3DH_ACC_DEV_NAME);
  	}
  	else
  	{
    	acc->client = NULL;
    	printk(KERN_INFO "I2C driver not registered!"
    	" Device unknown\n");
	    goto err_destoyworkqueue2;
  	}

  	if (acc->pdata->init) 
  	{
    	err = acc->pdata->init();
    	if (err < 0) 
    	{
      		dev_err(&client->dev, "init failed: %d\n", err);
      		goto err2;
    	}
  	}

  	if(DEBUG_FUNC_TRACE & debug_mask)
  		printk(KERN_INFO " %s: line: %d\n", __func__, __LINE__);

  	memset(acc->resume_state, 0, ARRAY_SIZE(acc->resume_state));

#ifndef NO_ISR
  	if(acc->pdata->gpio_int1 > 0)
  	{
    	acc->irq1 = gpio_to_irq(acc->pdata->gpio_int1);
    
    	if(DEBUG_FUNC_TRACE & debug_mask)
      		printk(KERN_INFO "%s: %s has set irq1 to irq: %d mapped on gpio:%d\n", K3DH_ACC_DEV_NAME, __func__, acc->irq1,acc->pdata->gpio_int1);
  	}
  
  	if(acc->pdata->gpio_int2 > 0)
  	{
    	acc->irq2 = gpio_to_irq(acc->pdata->gpio_int2);

    	if(DEBUG_FUNC_TRACE & debug_mask)
      		printk(KERN_INFO "%s: %s has set irq2 to irq: %d mapped on gpio:%d\n", K3DH_ACC_DEV_NAME, __func__, acc->irq2, acc->pdata->gpio_int2);
  	}
#endif
  	acc->resume_state[RES_CTRL_REG1] = K3DH_ACC_ENABLE_ALL_AXES;
  	acc->resume_state[RES_CTRL_REG2] = 0x00;
  	acc->resume_state[RES_CTRL_REG3] = 0x00;
  	acc->resume_state[RES_CTRL_REG4] = 0x00;
  	acc->resume_state[RES_CTRL_REG5] = 0x00;
  	acc->resume_state[RES_CTRL_REG6] = 0x00;

  	acc->resume_state[RES_TEMP_CFG_REG] = 0x00;
  	acc->resume_state[RES_FIFO_CTRL_REG] = 0x00;
  	acc->resume_state[RES_INT_CFG1] = 0x00;
  	acc->resume_state[RES_INT_THS1] = 0x00;
  	acc->resume_state[RES_INT_DUR1] = 0x00;
  	acc->resume_state[RES_INT_CFG2] = 0x00;
  	acc->resume_state[RES_INT_THS2] = 0x00;
  	acc->resume_state[RES_INT_DUR2] = 0x00;

  	acc->resume_state[RES_TT_CFG] = 0x00;
  	acc->resume_state[RES_TT_THS] = 0x00;
  	acc->resume_state[RES_TT_LIM] = 0x00;
  	acc->resume_state[RES_TT_TLAT] = 0x00;
  	acc->resume_state[RES_TT_TW] = 0x00;

  	atomic_set(&acc->enabled, 1);

  	err = k3dh_acc_update_g_range(acc, acc->pdata->g_range);
  	if (err < 0) 
  	{
   	 	dev_err(&client->dev, "update_g_range failed\n");
    	goto  err_power_off;
  	}

  	err = k3dh_acc_update_odr(acc, acc->pdata->poll_interval);
  	if (err < 0) 
  	{
    	dev_err(&client->dev, "update_odr failed\n");
    	goto  err_power_off;
  	}

  	if(DEBUG_FUNC_TRACE & debug_mask)
  		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);
	
  	err = k3dh_acc_input_init(acc);
  	if (err < 0) 
  	{
    	dev_err(&client->dev, "input init failed\n");
    	goto err_power_off;
  	}

#ifndef CONFIG_LGE_SENSOR_FUSION
  	err = k3dh_tap_input_init(acc);
  	if (err < 0) 
  	{
    	dev_err(&client->dev, "input(tap) init failed\n");
	   goto err_input_cleanup1;
  	}

  	err = k3dh_flip_input_init(acc);
  	if (err < 0) 
  	{
    	dev_err(&client->dev, "input(flip) init failed\n");
	   goto err_input_cleanup2;
  	}
#endif  
  	k3dh_acc_misc_data = acc;

  	err = misc_register(&k3dh_acc_misc_device);
  	if (err < 0)
  	{
   	   dev_err(&client->dev,"misc K3DH_ACC_DEV_NAME register failed\n");
	   goto err_input_cleanup;
  	}

  	k3dh_acc_device_power_off(acc);

  	/* As default, do not report information */
  	atomic_set(&acc->enabled, 0);

  	if (acc->irq1 > 0) {
		if(DEBUG_FUNC_TRACE & debug_mask)
			printk(KERN_INFO "%s: call request_irq for irq1..\n", __func__);

  		err = request_threaded_irq(acc->irq1, NULL,
  			k3dh_acc_isr1, IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
  			"k3dh_irq1", acc);
  		if (err < 0)
  		{
  			pr_err("%s: can't allocate irq.\n", __func__);
  			goto err_misc_dereg;
  		}
  		disable_irq_nosync(acc->irq1);
  	}
  	if (acc->irq2 > 0) {
		if(DEBUG_FUNC_TRACE & debug_mask)
			printk(KERN_INFO "%s: call request_irq for irq2..\n", __func__);
		
  		err = request_irq(acc->irq2, k3dh_acc_isr2, IRQF_TRIGGER_RISING,
  			"k3dh_irq2", acc);
  		if (err < 0) 
		{
  			dev_err(&client->dev, "request irq2 failed: %d\n", err);
  			goto err_free_irq1;
  		}
  		disable_irq_nosync(acc->irq2);
  	}

#if defined(CONFIG_HAS_EARLYSUSPEND)
	k3dh_sensor_early_suspend.suspend = k3dh_acc_early_suspend;
	k3dh_sensor_early_suspend.resume = k3dh_acc_late_resume;
	k3dh_sensor_early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN - 45;
	register_early_suspend(&k3dh_sensor_early_suspend);
#endif
  	mutex_unlock(&acc->lock);

  	if(DEBUG_FUNC_TRACE & debug_mask)
	  	dev_info(&client->dev, "%s: probed\n", K3DH_ACC_DEV_NAME);

#if !defined(NEW_DRIVER)
  	err = device_create_file(&acc->input_dev->dev, &dev_attr_enable);
  	err = device_create_file(&acc->input_dev->dev, &dev_attr_delay);
#endif
#ifdef K3DH_USER_CALIBRATION
		err = device_create_file(k3dh_acc_misc_device.this_device, &dev_attr_calibration);
#endif
  	err = device_create_file(&acc->input_dev->dev, &dev_attr_enable);
  	err = device_create_file(&acc->input_dev->dev, &dev_attr_poll_delay);
	err = device_create_file(&acc->input_dev->dev, &dev_attr_acc_cal);
  	err = device_create_file(&acc->input_dev->dev, &dev_attr_cnt);	
  	err = device_create_file(&acc->input_dev->dev, &dev_attr_x);
  	err = device_create_file(&acc->input_dev->dev, &dev_attr_y);
	err = device_create_file(&acc->input_dev->dev, &dev_attr_z);

  	return 0;

err_free_irq1:
  	free_irq(acc->irq1, acc);
err_misc_dereg:
  	misc_deregister(&k3dh_acc_misc_device);
err_input_cleanup:
  	k3dh_acc_input_cleanup(acc);
#ifndef CONFIG_LGE_SENSOR_FUSION	
err_input_cleanup1:
  	k3dh_tap_input_cleanup(acc);
err_input_cleanup2:
  	k3dh_flip_input_cleanup(acc);
#endif
err_power_off:
  	k3dh_acc_device_power_off(acc);
err2:
  	if (acc->pdata->exit)
    	acc->pdata->exit();
exit_kfree_pdata:
  	kfree(acc->pdata);
err_destoyworkqueue2:
	if(acc->pdata->gpio_int2 > 0)	
  		destroy_workqueue(acc->irq2_work_queue);
err_destoyworkqueue1:
	if(acc->pdata->gpio_int1 > 0)
  		destroy_workqueue(acc->irq1_work_queue);
err_mutexunlockfreedata:
  	mutex_unlock(&acc->lock);
  	kfree(acc);
exit_alloc_data_failed:
exit_check_functionality_failed:
  	printk(KERN_ERR "%s: Driver Init failed\n", K3DH_ACC_DEV_NAME);
  	return err;
exit:
  	return err;
}

static int __devexit k3dh_acc_remove(struct i2c_client *client)
{
  /* TODO: revisit ordering here once _probe order is finalized */
  struct k3dh_acc_data *acc = i2c_get_clientdata(client);

  //device_remove_file(&client->dev, &dev_attr_x);
  //device_remove_file(&client->dev, &dev_attr_y);
  //device_remove_file(&client->dev, &dev_attr_z);
  //device_remove_file(&client->dev, &dev_attr_enable);

  device_remove_file(&k3dh_acc_misc_data->input_dev->dev, &dev_attr_acc_cal);
  device_remove_file(&k3dh_acc_misc_data->input_dev->dev, &dev_attr_cnt);  
  device_remove_file(&k3dh_acc_misc_data->input_dev->dev, &dev_attr_x);
  device_remove_file(&k3dh_acc_misc_data->input_dev->dev, &dev_attr_y);
  device_remove_file(&k3dh_acc_misc_data->input_dev->dev, &dev_attr_z);
  device_remove_file(&k3dh_acc_misc_data->input_dev->dev, &dev_attr_enable);
  device_remove_file(&k3dh_acc_misc_data->input_dev->dev, &dev_attr_poll_delay);

  if(DEBUG_FUNC_TRACE & debug_mask)
    printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  if(acc->irq1)
    free_irq(acc->irq1, acc);
  if(acc->irq2)
    free_irq(acc->irq2, acc);

  if(acc->pdata->gpio_int1 > 0){
    gpio_free(acc->pdata->gpio_int1);
    destroy_workqueue(acc->irq1_work_queue);
  }
  if(acc->pdata->gpio_int2 > 0){
    gpio_free(acc->pdata->gpio_int2);
	destroy_workqueue(acc->irq2_work_queue);
  }

#ifdef USE_HR_TIMER
	hrtimer_cancel(&acc->htimer);
	cancel_work_sync(&acc->hr_work);
	destroy_workqueue(acc->hr_work_q);
#endif
  misc_deregister(&k3dh_acc_misc_device);
  k3dh_acc_input_cleanup(acc);
  k3dh_acc_device_power_off(acc);

  if (acc->pdata->exit)
    acc->pdata->exit();

  kfree(acc->pdata);
  kfree(acc);

#if defined(CONFIG_HAS_EARLYSUSPEND)
	unregister_early_suspend(&k3dh_sensor_early_suspend);
#endif
  return 0;
}
#if defined(CONFIG_HAS_EARLYSUSPEND)
static void k3dh_acc_early_suspend(struct early_suspend *h)
{
	if(DEBUG_FUNC_TRACE & debug_mask)
	  printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

	k3dh_acc_misc_data->on_before_early_suspend = atomic_read(&k3dh_acc_misc_data->enabled);
	k3dh_acc_disable(k3dh_acc_misc_data, ID_RESUME);
}

static void k3dh_acc_late_resume(struct early_suspend *h)
{
	if(DEBUG_FUNC_TRACE & debug_mask)
	  printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

	k3dh_acc_enable(k3dh_acc_misc_data, ID_RESUME);
}
#else

#if defined(NEW_DRIVER)
static int k3dh_acc_resume(struct i2c_client *client)
{
  struct k3dh_acc_data *acc = i2c_get_clientdata(client);

  if(DEBUG_FUNC_TRACE & debug_mask)
  	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);


  return k3dh_acc_enable(acc,ID_RESUME);
}

static int k3dh_acc_suspend(struct i2c_client *client, pm_message_t mesg)
{
  struct k3dh_acc_data *acc = i2c_get_clientdata(client);

  if(DEBUG_FUNC_TRACE & debug_mask)
  	printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);

  acc->on_before_suspend = atomic_read(&acc->enabled);
  return k3dh_acc_disable(acc,ID_RESUME);
}
#else /* NEW_DRIVER */
static int k3dh_acc_resume(struct i2c_client *client)
{
	struct k3dh_acc_data *acc = i2c_get_clientdata(client);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);
	
	//if (acc->on_before_suspend)
		return k3dh_acc_enable(acc);
	return 0;
}

static int k3dh_acc_suspend(struct i2c_client *client, pm_message_t mesg)
{
	struct k3dh_acc_data *acc = i2c_get_clientdata(client);

	if(DEBUG_FUNC_TRACE & debug_mask)
		printk(KERN_INFO "%s: line: %d\n", __func__, __LINE__);
	
	//acc->on_before_suspend = atomic_read(&acc->enabled);
	return k3dh_acc_disable(acc);
}
#endif /* NEW_DRIVER */
#endif

static const struct i2c_device_id k3dh_acc_id[]
  = { { K3DH_ACC_DEV_NAME, 0 }, { }, };

MODULE_DEVICE_TABLE(i2c, k3dh_acc_id);

static struct i2c_driver k3dh_acc_driver = {
  .driver = {
    .name = K3DH_ACC_DEV_NAME,
  },
  .probe = k3dh_acc_probe,
  .remove = __devexit_p(k3dh_acc_remove),
#ifndef CONFIG_HAS_EARLYSUSPEND
  .resume = k3dh_acc_resume,
  .suspend = k3dh_acc_suspend,
#endif
  .id_table = k3dh_acc_id,
};

static int __init k3dh_acc_init(void)
{
  	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s accelerometer driver: init\n", K3DH_ACC_DEV_NAME);
  	return i2c_add_driver(&k3dh_acc_driver);
}

static void __exit k3dh_acc_exit(void)
{
  	if(DEBUG_FUNC_TRACE & debug_mask)
    	printk(KERN_INFO "%s accelerometer driver exit\n", K3DH_ACC_DEV_NAME);
  	i2c_del_driver(&k3dh_acc_driver);
  	return;
}

module_init(k3dh_acc_init);
module_exit(k3dh_acc_exit);

MODULE_DESCRIPTION("k3dh accelerometer misc driver");
MODULE_AUTHOR("STMicroelectronics");
MODULE_LICENSE("GPL");

