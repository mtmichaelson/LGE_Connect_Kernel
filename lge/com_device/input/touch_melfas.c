/* Touch_melfas.c
 *
 * Copyright (C) 2011 LGE.
 *
 * Author: yehan.ahn@lge.com, hyesung.shin@lge.com
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/err.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/slab.h>

#include <mach/gpio.h>

#include <linux/input/lge_touch_core.h>
#include <linux/input/touch_melfas.h>

#include <linux/regulator/machine.h>

#define MODE_CONTROL                    0x01
#define TS_READ_START_ADDR              0x10

#define TS_READ_START_ADDR				0x10
#define TS_READ_VERSION_ADDR			0xF0
#define TS_HW_REVISION_ADDR             0xF1
#define TS_CORE_VERSION_ADDR            0xF3
#define TS_PRIVATE_CUSTOM_VERSION_ADDR  0xF4
#define TS_PUBLIC_CUSTOM_VERSION_ADDR   0xF5

#define TS_READ_REGS_LEN				100
#define TS_READ_VERSION_INFO_LEN		6

#define MIP_INPUT_EVENT_PACKET_SIZE		0x0F
#define MIP_INPUT_EVENT_INFORMATION		0x10

/* Get user-finger-data from register.
 */
#define TS_MFS_GET_TYPE(_type_data) \
		((_type_data & 0x60) >> 5)
#define TS_MFS_GET_STATE(_state_data) \
		((_state_data & 0x80) == 0x80)
#define TS_MFS_GET_REPORT_ID(_id_data) \
		(_id_data & 0x0F)
#define TS_MFS_GET_X_POSITION(_high_reg, _low_reg) \
		((_high_reg & 0x0F) << 8 | _low_reg)
#define TS_MFS_GET_Y_POSITION(_high_reg, _low_reg) \
		((_high_reg & 0xF0) << 4 | _low_reg)
#define TS_MFS_GET_PRESSURE(_pressure) \
		_pressure

int melfas_ts_get_data(struct i2c_client *client, struct t_data* data, struct b_data* button, u8* total_num)
{
	struct melfas_ts_data* ts =
			(struct melfas_ts_data*)get_touch_handle(client);

	int i;
	u16 touchType = 0, touchState = 0, touchID = 0;
	u16 posX = 0, posY = 0, width = 0;
	int keyID = 0, reportID = 0;
	u8 packet_size;
	u8 event_data[TS_READ_REGS_LEN];
	u8 index = 0;

	if (unlikely(touch_debug_mask & DEBUG_TRACE))
		TOUCH_DEBUG_MSG("\n");	

	/* Read packet size */
	if (unlikely(touch_i2c_read(client, MIP_INPUT_EVENT_PACKET_SIZE, 1, &packet_size) < 0)) {
		TOUCH_ERR_MSG("MIP_INPUT_EVENT_PACKET_SIZE read fail\n");
		goto err_melfas_getdata;
	}

	if (packet_size == 0) {
		TOUCH_ERR_MSG("read number 0 error!!!!\n");
		// TODO: Need Error handling?
		goto out;
	}

	/* Read event information */
	if (unlikely(touch_i2c_read(client, MIP_INPUT_EVENT_INFORMATION, packet_size, event_data) < 0)) {
		TOUCH_ERR_MSG("MIP_INPUT_EVENT_PACKET_SIZE read fail\n");
		goto err_melfas_getdata;
	}

	/* decode low data */
	for (i = 0; i < packet_size; i = i + 6) {
		touchType = TS_MFS_GET_TYPE(event_data[i]);		/* Touch Screen, Touch Key */
		touchState = TS_MFS_GET_STATE(event_data[i]); 	/* touchAction = (buf[0]>>7)&&0x01;*/
		/* Touch Screen -> n.th finger input
		 * Touch Key -> n.th touch key area. 
		 */
		reportID = TS_MFS_GET_REPORT_ID(event_data[i]);		
		posX = (u16) TS_MFS_GET_X_POSITION(event_data[i + 1], event_data[i + 2]);	/* X position (0 ~ 4096, 12 bit) */
		posY = (u16) TS_MFS_GET_Y_POSITION(event_data[i + 1], event_data[i + 3]);	/* Y position (0 ~ 4096, 12 bit) */
		width = event_data[i + 4];

		if (touchType == TOUCH_KEY)
			keyID = reportID;
		else if (touchType == TOUCH_SCREEN)
			touchID = reportID-1;

		if (touchID > MAX_FINGER-1) {
			// TODO: Dose it needs?
			TOUCH_ERR_MSG("invaliad data\n");
			goto err_melfas_getdata;
		}

		/* finger data */
		if (touchType == TOUCH_SCREEN && touchState) {
			data[index].id = touchID;
			data[index].x_position = posX;
			data[index].y_position = posY;
			data[index].width_major = width;
			//data[index].width_minor = 0;
			//data[index].width_orientation = 0;
			// TODO: check it...
			data[index].pressure = 10;	// dummy value - need to improve

			index++;
		} 

		/* button data */
		// TODO: button priority for defencing multi press
		if (touchType == TOUCH_KEY) {
			if (keyID > ts->pdata->caps->number_of_button || keyID == 0) {
				TOUCH_ERR_MSG("Touchkey ID error: id = %d\n", keyID);
			} else {
				button->key_code = ts->pdata->caps->button_name[keyID-1];
				button->state = touchState;
			}

			// TODO: why?? key is final data??
			break;
		}
	}

	if (touchType == TOUCH_SCREEN) {
		*total_num = index;
		if (unlikely(touch_debug_mask & DEBUG_GET_DATA))
			TOUCH_INFO_MSG("Total_num: %d\n", *total_num);
	}

out:
	return 0;

//err_melfas_device_damage:
err_melfas_getdata:
	return -EIO;
}

int get_ic_info(struct melfas_ts_data* ts, struct touch_fw_info* fw_info)
{
	u8 buf[TS_READ_VERSION_INFO_LEN];
	
	memset(fw_info, 0, sizeof(fw_info));

	// TODO: why connection check here??
#if 0
	for (i = 0; i < I2C_RETRY_CNT; i++) {
		ret = i2c_master_send(ts->client, &buf[0], 1);
		if (ret >= 0) {
			printk(KERN_ERR "melfas_ts_probe: i2c_master_send() ok [%d]\n", ret);
			break;
		} else {
			printk(KERN_ERR "melfas_ts_probe: i2c_master_send() failed[%d]\n", ret);
			if (i == I2C_RETRY_CNT-1) {
				printk(KERN_ERR "melfas_ts_probe : no touch panel \n");
				ret = mms100_download(1);
				if (ret == 0)
					printk(KERN_ERR "melfas_ts_probe : Touch FW update Success \n");
				else
					return ret ;
			}
		}
	}
#endif	

	if (unlikely(touch_i2c_read(ts->client, TS_READ_VERSION_ADDR,
			TS_READ_VERSION_INFO_LEN, buf) < 0)) {
		TOUCH_ERR_MSG("TS_READ_VERSION_ADDR read fail\n");
		return -EIO;
	}

	TOUCH_INFO_MSG("= Melfas Version Info =\n");
	TOUCH_INFO_MSG("Panel Version :: %d, HW Revision :: %d, HW Compatibility GR :: %d\n", buf[0], buf[1], buf[2]);
	TOUCH_INFO_MSG("Core Version :: %d, Private Custom Version :: %d, Public Custom Version :: %d\n", buf[3], buf[4], buf[5]);

	fw_info->fw_rev = buf[3];

	ts->fw_info = fw_info;

	return 0;
}

int melfas_ts_init(struct i2c_client* client, struct touch_fw_info* fw_info)
{
	struct melfas_ts_data* ts =
			(struct melfas_ts_data*)get_touch_handle(client);

	if (touch_debug_mask & DEBUG_TRACE)
		TOUCH_DEBUG_MSG("\n");

	if (!ts->is_probed)
		if (unlikely(get_ic_info(ts, fw_info) < 0))
			return -EIO;

	ts->is_probed = 1;

	return 0;
}

int melfas_ts_power(struct i2c_client* client, int power_ctrl)
{
	struct melfas_ts_data* ts =
			(struct melfas_ts_data*)get_touch_handle(client);

	if (touch_debug_mask & DEBUG_TRACE)
		TOUCH_DEBUG_MSG("\n");

	switch (power_ctrl) {
	case POWER_OFF:
		if (ts->pdata->pwr->use_regulator) {
			regulator_disable(ts->regulator_vio);
			regulator_disable(ts->regulator_vdd);
		}
		else
			ts->pdata->pwr->power(0);

		break;
	case POWER_ON:
		if (ts->pdata->pwr->use_regulator) {
			regulator_enable(ts->regulator_vdd);
			regulator_enable(ts->regulator_vio);
		}
		else
			ts->pdata->pwr->power(1);

		/* P2 H/W bug fix */
		if (ts->pdata->reset_pin > 0) {
			msleep(10);
			gpio_set_value(ts->pdata->reset_pin, 0);
			msleep(ts->pdata->role->reset_delay);
			gpio_set_value(ts->pdata->reset_pin, 1);
		}
		break;
	case POWER_SLEEP:
	case POWER_WAKE:
		break;
	default:
		return -EIO;
		break;
	}

	return 0;
}

int melfas_ts_probe(struct i2c_client* client)
{
	struct melfas_ts_data* ts;
	int ret = 0;

	if (touch_debug_mask & DEBUG_TRACE)
		TOUCH_DEBUG_MSG("\n");

	ts = kzalloc(sizeof(struct melfas_ts_data), GFP_KERNEL);
	if (!ts) {
		TOUCH_ERR_MSG("Can not allocate memory\n");
		ret = -ENOMEM;
		goto err_alloc_data_failed;
	}

	set_touch_handle(client, ts);

	ts->client = client;
	ts->pdata = client->dev.platform_data;

	if (ts->pdata->pwr->use_regulator) {
		ts->regulator_vdd = regulator_get_exclusive(NULL, ts->pdata->pwr->vdd);
		if (IS_ERR(ts->regulator_vdd)) {
			TOUCH_ERR_MSG("FAIL: regulator_get_vdd - %s\n", ts->pdata->pwr->vdd);
			ret = -EPERM;
			goto err_get_vdd_failed;
		}

		ts->regulator_vio = regulator_get_exclusive(NULL, ts->pdata->pwr->vio);
		if (IS_ERR(ts->regulator_vio)) {
			TOUCH_ERR_MSG("FAIL: regulator_get_vio - %s\n", ts->pdata->pwr->vio);
			ret = -EPERM;
			goto err_get_vio_failed;
		}

		if (ts->pdata->pwr->vdd_voltage > 0) {
			ret = regulator_set_voltage(ts->regulator_vdd, ts->pdata->pwr->vdd_voltage, ts->pdata->pwr->vdd_voltage);
			if (ret < 0)
				TOUCH_ERR_MSG("FAIL: VDD voltage setting - (%duV)\n", ts->pdata->pwr->vdd_voltage);
		}

		if (ts->pdata->pwr->vio_voltage > 0) {
			ret = regulator_set_voltage(ts->regulator_vio, ts->pdata->pwr->vio_voltage, ts->pdata->pwr->vio_voltage);
			if (ret < 0)
				TOUCH_ERR_MSG("FAIL: VIO voltage setting - (%duV)\n",ts->pdata->pwr->vio_voltage);
		}
	}

	return ret;

err_get_vio_failed:
	if (ts->pdata->pwr->use_regulator) {
		regulator_put(ts->regulator_vdd);
	}
err_get_vdd_failed:
err_alloc_data_failed:
	kfree(ts);
	return ret;
}

void melfas_ts_remove(struct i2c_client* client)
{
	struct melfas_ts_data* ts =
			(struct melfas_ts_data*)get_touch_handle(client);

	if (touch_debug_mask & DEBUG_TRACE)
		TOUCH_DEBUG_MSG("\n");

	if (ts->pdata->pwr->use_regulator) {
		regulator_put(ts->regulator_vio);
		regulator_put(ts->regulator_vdd);
	}

	kfree(ts);
}

int melfas_ts_fw_upgrade(struct i2c_client* client, const char* fw_path)
{
	struct melfas_ts_data* ts =
			(struct melfas_ts_data*)get_touch_handle(client);
	int ret = 0;

	ts->is_probed = 0;

	// TODO: Should be implement FW upgrade

	/* update IC info */
	get_ic_info(ts, ts->fw_info);

	return ret;
}

int melfas_ts_ic_ctrl(struct i2c_client *client, u8 code, u16 value)
{
//	struct melfas_ts_data* ts =
//			(struct melfas_ts_data*)get_touch_handle(client);
	u8 buf = 0;

	switch (code)
	{
	case IC_CTRL_BASELINE:
		switch (value)
		{
		case BASELINE_OPEN:
			break;
		case BASELINE_FIX:
			break;
		case BASELINE_REBASE:
			break;
		default:
			break;
		}
		break;
	case IC_CTRL_READ:
		if (touch_i2c_read(client, value, 1, &buf) < 0) {
			TOUCH_ERR_MSG("IC_CTRL_READ fail\n");
			return -EIO;
		}
		break;
	case IC_CTRL_WRITE:
		if (touch_i2c_write_byte(client, ((value & 0xFF00) >> 8), (value & 0xFF)) < 0) {
			TOUCH_ERR_MSG("IC_CTRL_WRITE fail\n");
			return -EIO;
		}
		break;
	case IC_CTRL_RESET_CMD:
		break;
	default:
		break;
	}

	return buf;
}

struct touch_device_driver melfas_ts_driver = {
	.probe 	= melfas_ts_probe,		// ok - none
	.remove	= melfas_ts_remove,		// ok - none
	.init  	= melfas_ts_init,		// ok
	.data  	= melfas_ts_get_data,	// ok
	.power 	= melfas_ts_power,		// ok
	.fw_upgrade = NULL, // melfas_ts_fw_upgrade,
	.ic_ctrl	= melfas_ts_ic_ctrl,// ok
};

static int __devinit touch_init(void)
{
	if (touch_debug_mask & DEBUG_TRACE)
		TOUCH_DEBUG_MSG("\n");

	return touch_driver_register(&melfas_ts_driver);
}

static void __exit touch_exit(void)
{
	if (touch_debug_mask & DEBUG_TRACE)
		TOUCH_DEBUG_MSG("\n");

	touch_driver_unregister();
}

module_init(touch_init);
module_exit(touch_exit);

MODULE_AUTHOR("yehan.ahn@lge.com, hyesung.shin@lge.com");
MODULE_DESCRIPTION("LGE Touch Driver");
MODULE_LICENSE("GPL");

