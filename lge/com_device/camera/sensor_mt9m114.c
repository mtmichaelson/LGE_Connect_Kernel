/* Copyright (c) 2009, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <media/msm_camera.h>
#include <mach/gpio.h>
#include "sensor_mt9m114.h"
#ifdef CONFIG_VTCAM_SD_IMAGE_TUNNING
#include "register_common_init.h"
#endif


/* Micron MT9M114 Registers and their values */

#define SENSOR_DEBUG 0

struct mt9m114_work {
	struct work_struct work;
};

static struct  mt9m114_work *mt9m114_sensorw;
static struct  i2c_client *mt9m114_client;
static int32_t config_csi;

struct mt9m114_ctrl_t {
	const struct msm_camera_sensor_info *sensordata;
};

static struct mt9m114_ctrl_t *mt9m114_ctrl;

static DECLARE_WAIT_QUEUE_HEAD(mt9m114_wait_queue);
DEFINE_MUTEX(mt9m114_sem);

static int prev_effect_mode;
static int prev_balance_mode;
static int prev_iso_mode;
static int prev_antibanding_mode;
static int prev_brightness_mode;
//LGE_CAMERA_S : AE_metering - jonghwan.ko@lge.com
static int prev_ae_metering_mode; 
//LGE_CAMERA_E : AE_metering - jonghwan.ko@lge.com
//LGE_CAMERA_S : FPS - jonghwan.ko@lge.com
static int prev_fps_mode;
//LGE_CAMERA_E : FPS - jonghwan.ko@lge.com

/*=============================================================
	EXTERNAL DECLARATIONS
==============================================================*/
extern struct mt9m114_reg mt9m114_regs;


/*=============================================================*/

static int mt9m114_probe_init_done(const struct msm_camera_sensor_info *data)
{
	CDBG("%s : mt9m114 sensor_reset 0\n", __func__);
	gpio_direction_output(data->sensor_reset, 0);
    gpio_direction_output(data->vt_mclk_enable, 0);
	gpio_free(data->sensor_reset);
    gpio_free(data->vt_mclk_enable);
	return 0;
}

static int mt9m114_reset(const struct msm_camera_sensor_info *dev)
{
	int rc = 0;
    rc = gpio_request(dev->vt_mclk_enable, "mt9m114_clk_en");
    if (!rc) {
        rc = gpio_direction_output(dev->vt_mclk_enable, 1);
        CDBG("%s: vt_mclk_enable 0 = %d, rc = %d\n",__func__, dev->vt_mclk_enable, rc);
    }
    else{
        gpio_free(dev->vt_mclk_enable);
        return -EFAULT;
    }
    mdelay(5);

	rc = gpio_request(dev->sensor_reset, "mt9m114_reset");
    
	if (!rc) {
		rc = gpio_direction_output(dev->sensor_reset, 0);
		CDBG("%s: reset 0 = %d, rc = %d\n",__func__, dev->sensor_reset, rc);
		mdelay(10);
		rc = gpio_direction_output(dev->sensor_reset, 1);
		CDBG("%s: reset 1 = %d, rc = %d\n",__func__, dev->sensor_reset, rc);
	}
	else{
		CDBG(" mt9m114_probe_init_sensor fails\n");
		mt9m114_probe_init_done(dev);

		return -EFAULT;
	}

//	gpio_free(dev->sensor_reset);

	CDBG(" mt9m114_probe_init_sensor finishes\n");	
	return rc;
}

static int mt9m114_i2c_rxdata(unsigned short saddr,
	unsigned char *rxdata, int length)
{
	struct i2c_msg msgs[] = {
	{
		.addr   = saddr << 1,
		.flags = 0,
		.len   = 2,
		.buf   = rxdata,
	},
	{
		.addr   = saddr << 1,
		.flags = I2C_M_RD,
		.len   = length,
		.buf   = rxdata,
	},
	};

#if SENSOR_DEBUG
	if (length == 2)
		CDBG("msm_io_i2c_r: 0x%04x 0x%04x\n",
			*(u16 *) rxdata, *(u16 *) (rxdata + 2));
	else if (length == 4)
		CDBG("msm_io_i2c_r: 0x%04x\n", *(u16 *) rxdata);
	else
		CDBG("msm_io_i2c_r: length = %d\n", length);
#endif

	if (i2c_transfer(mt9m114_client->adapter, msgs, 2) < 0) {
		CDBG("mt9m114_i2c_rxdata failed!\n");
		return -EIO;
	}

	return 0;
}

static int32_t mt9m114_i2c_read(unsigned short   saddr,
	unsigned short raddr, unsigned short *rdata, enum mt9m114_width width)
{
	int32_t rc = 0;
	unsigned char buf[4];

	if (!rdata)
		return -EIO;

	memset(buf, 0, sizeof(buf));

	switch (width) 
	{
		case BYTE_LEN:
			buf[0] = (raddr & 0xFF00) >> 8;
			buf[1] = (raddr & 0x00FF);
			rc = mt9m114_i2c_rxdata(saddr, buf, 2);
			if (rc < 0)
				return rc;
			*rdata = buf[0];
			break;

		case WORD_LEN: 
			buf[0] = (raddr & 0xFF00)>>8;
			buf[1] = (raddr & 0x00FF);

			rc = mt9m114_i2c_rxdata(saddr, buf, 2);
			if (rc < 0)
				return rc;

			*rdata = buf[0] << 8 | buf[1];
			break;

		default:
			break;
	}

	if (rc < 0)
		CDBG("mt9m114_i2c_read failed!\n");

	return rc;
}

static int32_t mt9m114_i2c_txdata(unsigned short saddr,
	unsigned char *txdata, int length)
{
	struct i2c_msg msg[] = {
		{
			.addr = saddr << 1,
			.flags = 0,
			.len = length,
			.buf = txdata,
		},
	};

#if SENSOR_DEBUG
	if (length == 2)
		CDBG("msm_io_i2c_w: 0x%04x 0x%04x\n",
			*(u16 *) txdata, *(u16 *) (txdata + 2));
	else if (length == 4)
		CDBG("msm_io_i2c_w: 0x%04x\n", *(u16 *) txdata);
	else
		CDBG("msm_io_i2c_w: length = %d\n", length);
#endif
	if (i2c_transfer(mt9m114_client->adapter, msg, 1) < 0) {
		CDBG("mt9m114_i2c_txdata failed\n");
		return -EIO;
	}

	return 0;
}

/*  // for compile
static int32_t mt9m114_i2c_write(unsigned short saddr,
	unsigned short waddr, unsigned short wdata, enum mt9m114_width width)
{
	int32_t rc = -EIO;
	unsigned char buf[4];

	memset(buf, 0, sizeof(buf));
	switch (width) {
	case WORD_LEN: {
		buf[0] = (waddr & 0xFF00)>>8;
		buf[1] = (waddr & 0x00FF);
		buf[2] = (wdata & 0xFF00)>>8;
		buf[3] = (wdata & 0x00FF);

		rc = mt9m114_i2c_txdata(saddr, buf, 4);
	}
		break;

	case BYTE_LEN: {
		buf[0] = waddr;
		buf[1] = wdata;
		rc = mt9m114_i2c_txdata(saddr, buf, 2);
	}
		break;

	default:
		break;
	}

	if (rc < 0)
		CDBG(
		"i2c_write failed, addr = 0x%x, val = 0x%x!\n",
		waddr, wdata);

	return rc;
}
*/

static int32_t mt9m114_i2c_write_w_sensor(unsigned short waddr, unsigned short wdata)
{
	int32_t rc = -EIO;
	unsigned char buf[4];
	memset(buf, 0, sizeof(buf));

	buf[0] = (waddr & 0xFF00) >> 8;
	buf[1] = (waddr & 0x00FF);
	buf[2] = (wdata & 0xFF00) >> 8;
	buf[3] = (wdata & 0x00FF);
	rc = mt9m114_i2c_txdata(mt9m114_client->addr, buf, 4);
//       printk(KERN_ERR "[### WORD_LEN check] i2c_write , addr = 0x%04x, val = 0x%04x!\n", waddr, wdata);

	if (rc < 0)
		CDBG("i2c_write_w failed, addr = 0x%x, val = 0x%x!\n", waddr, wdata);

	return rc;
}

static int32_t mt9m114_i2c_write_table(struct mt9m114_i2c_reg_conf const *reg_conf_tbl, int num_of_items_in_table)
{
	int i;
	int32_t rc = -EIO;

	for (i = 0; i < num_of_items_in_table; i++) {
		if(reg_conf_tbl->waddr == 0xFFFF)
		{
			msleep(reg_conf_tbl->wdata);
			rc = 0;
		}
		else if(reg_conf_tbl->waddr == 0xFFFE)
		{
			unsigned short test_data = 0;
			for(i=0; i<50; i++){ // max delay ==> 500 ms 
				rc  = mt9m114_i2c_read(mt9m114_client->addr, 0x0080, &test_data, WORD_LEN);
				if (rc < 0)
					return rc;


				if((test_data & reg_conf_tbl->wdata)==0)
					break;
				else
					mdelay(10);

				printk(KERN_ERR "### %s :  Polling set, 0x0080 Reg : 0x%x\n", __func__, test_data);	
			}			
		}
		else if(reg_conf_tbl->waddr == 0x301A)
		{
			unsigned short test_data = 0;		
			rc  = mt9m114_i2c_read(mt9m114_client->addr, 0x301A, &test_data, WORD_LEN);
			if (rc < 0)
				return rc;

			rc = mt9m114_i2c_write_w_sensor(0x301A, test_data|0x0200);
			if (rc < 0)
				return rc;

			printk(KERN_ERR "### %s : Reset reg check, 0x301A Reg : 0x%x\n", __func__, test_data|0x0200);
		}
		else if((reg_conf_tbl->waddr == 0x0080)&&((reg_conf_tbl->wdata == 0x8000)||(reg_conf_tbl->wdata == 0x0001)))
		{
			unsigned short test_data = 0;
			rc  = mt9m114_i2c_read(mt9m114_client->addr, 0x0080, &test_data, WORD_LEN);
			if (rc < 0)
				return rc;

			test_data = test_data|reg_conf_tbl->wdata;
			rc = mt9m114_i2c_write_w_sensor(0x0080, test_data);
			if (rc < 0)
				return rc;

			printk(KERN_ERR "### %s : Patch check, 0x0080 Reg : 0x%x\n", __func__, test_data);
		}		
		else
			rc = mt9m114_i2c_write_w_sensor(reg_conf_tbl->waddr, reg_conf_tbl->wdata);
//			rc = mt9m114_i2c_write(mt9m114_client->addr, reg_conf_tbl->waddr, reg_conf_tbl->wdata, reg_conf_tbl->width);

		if (rc < 0)
			break;

		reg_conf_tbl++;
	}

	return rc;
}

static long mt9m114_reg_init(void)
{
	int32_t rc = 0;
#ifdef CONFIG_VTCAM_SD_IMAGE_TUNNING
	common_reg_list_type* pstRegisterList = NULL, *ptr_list;
	int loop;

	printk(KERN_ERR "### %s: Register init\n", __func__);
	common_register_init(COMMON_REG_MEM, &pstRegisterList);
	if (!pstRegisterList)
	{
		rc = mt9m114_i2c_write_table(mt9m114_regs.init_tbl, mt9m114_regs.inittbl_size);
	}
	else
	{
		ptr_list = pstRegisterList;

		for (loop = 0; loop < ptr_list->num_regs; loop++)
		{
			if (ptr_list->list_regs[loop].mem.addr == 0xFFFF)
			{
				msleep(ptr_list->list_regs[loop].mem.val);
				CDBG("[icebox]%s:msleep addr = %d, val = %d\n", __func__, ptr_list->list_regs[loop].mem.addr, ptr_list->list_regs[loop].mem.val);
				rc = 0;
			}
			else
			//isx006_i2c_write(isx006_client->addr, ptr_list->list_regs[loop].mem_var4.addr, ptr_list->list_regs[loop].mem_var4.vals.val32, ptr_list->list_regs[loop].mem_var4.len);
			rc = mt9m114_i2c_write_w_sensor(ptr_list->list_regs[loop].mem.addr, ptr_list->list_regs[loop].mem.val);
			CDBG("[icebox]%s: addr = %d, val = %d\n", __func__, ptr_list->list_regs[loop].mem.addr, ptr_list->list_regs[loop].mem.val);

			if (rc < 0)
			break;
		}
	}

	if (pstRegisterList)
		kfree(pstRegisterList);
#else
	/* PLL Setup Start and initial setting */
	rc = mt9m114_i2c_write_table(mt9m114_regs.init_tbl, mt9m114_regs.inittbl_size);
#endif
	if (rc < 0)
		return rc;

	return 0;
}

static int mt9m114_set_effect(int effect)
{
	int rc = 0;

	if(prev_effect_mode == effect)
	{
		CDBG("### ; [CHECK]%s: skip this function, effect_mode -> %d\n", __func__, effect);
		return rc;
	}

       CDBG("###  ; [CHECK]%s: effect -> %d\n", __func__, effect);

	switch (effect) {
	case CAMERA_EFFECT_OFF:
	 	rc = mt9m114_i2c_write_table(mt9m114_regs.effect_default_tbl, mt9m114_regs.effect_default_tbl_size);
		if (rc < 0)
			return rc;
		break;
	case CAMERA_EFFECT_MONO:
	 	rc = mt9m114_i2c_write_table(mt9m114_regs.effect_mono_tbl, mt9m114_regs.effect_mono_tbl_size);
		if (rc < 0)
			return rc;
		break;
	case CAMERA_EFFECT_NEGATIVE:
	 	rc = mt9m114_i2c_write_table(mt9m114_regs.effect_negative_tbl, mt9m114_regs.effect_negative_tbl_size);
		if (rc < 0)
			return rc;
		break;
	case CAMERA_EFFECT_SOLARIZE:
	 	rc = mt9m114_i2c_write_table(mt9m114_regs.effect_solarization_tbl, mt9m114_regs.effect_solarization_tbl_size);
		if (rc < 0)
			return rc;
		break;
	case CAMERA_EFFECT_SEPIA:
	 	rc = mt9m114_i2c_write_table(mt9m114_regs.effect_sepia_tbl, mt9m114_regs.effect_sepia_tbl_size);
		if (rc < 0)
			return rc;
		break;
	case CAMERA_EFFECT_AQUA:
	 	rc = mt9m114_i2c_write_table(mt9m114_regs.effect_aqua_tbl, mt9m114_regs.effect_aqua_tbl_size);
		if (rc < 0)
			return rc;
		break;
	case CAMERA_EFFECT_POSTERIZE : // effect off code
	 	rc = mt9m114_i2c_write_table(mt9m114_regs.effect_default_tbl, mt9m114_regs.effect_default_tbl_size);
		if (rc < 0)
			return rc;
		break;
	default:
		return -EINVAL;
	}

	rc = mt9m114_i2c_write_w_sensor(0x0080, 0x8004);
	if (rc < 0)
		return rc;
	{
		unsigned short test_data = 0, i;
		for(i=0; i<50; i++){ // max delay ==> 500 ms 
			rc  = mt9m114_i2c_read(mt9m114_client->addr, 0x0080, &test_data, WORD_LEN);
			if (rc < 0)
				return rc;

			if((test_data & 0x0004)==0)
				break;
			else
				mdelay(10);	
			
			printk(KERN_ERR "### %s :  Refresh Polling set, 0x0080 Reg : 0x%x\n", __func__, test_data);	
		}
	}
	
	prev_effect_mode = effect;
	return rc;
}

static int mt9m114_set_wb(int mode)
{
	int32_t rc = 0;

	if(prev_balance_mode == mode)
	{
		printk(KERN_ERR "###  [CHECK]%s: skip this function, wb_mode -> %d\n", __func__, mode);
		return rc;
	}
       printk(KERN_ERR "###  [CHECK]%s: mode -> %d\n", __func__, mode);

	switch (mode) {
		case CAMERA_WB_AUTO:
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.wb_default_tbl, mt9m114_regs.wb_default_tbl_size);
			if (rc < 0)
				return rc;			
			break;
		case CAMERA_WB_DAYLIGHT:	// sunny
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.wb_sunny_tbl, mt9m114_regs.wb_sunny_tbl_size);
			if (rc < 0)
				return rc;		
			break;
		case CAMERA_WB_CLOUDY_DAYLIGHT:  // cloudy
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.wb_cloudy_tbl, mt9m114_regs.wb_cloudy_tbl_size);
			if (rc < 0)
				return rc;
			break;
		case CAMERA_WB_FLUORESCENT:
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.wb_fluorescent_tbl, mt9m114_regs.wb_fluorescent_tbl_size);
			if (rc < 0)
				return rc;
			break;			
		case CAMERA_WB_INCANDESCENT:
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.wb_incandescent_tbl, mt9m114_regs.wb_incandescent_tbl_size);
			if (rc < 0)
				return rc;
			break;
		default:
			return -EINVAL;
	}
	
	prev_balance_mode = mode;
	return rc;
}

static int mt9m114_set_iso(int mode)
{
	int32_t rc = 0;

	if(prev_iso_mode == mode)
	{
		printk(KERN_ERR "###  [CHECK]%s: skip this function, iso_mode -> %d\n", __func__, mode);
		return rc;
	}
       printk(KERN_ERR "###  [CHECK]%s: mode -> %d\n", __func__, mode);

	switch (mode) {
		case CAMERA_ISO_AUTO:
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.iso_default_tbl, mt9m114_regs.iso_default_tbl_size);
			if (rc < 0)
				return rc;
			break;
		case CAMERA_ISO_100:
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.iso_100_tbl, mt9m114_regs.iso_100_tbl_size);
			if (rc < 0)
				return rc;		
			break;
		case CAMERA_ISO_200:  
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.iso_200_tbl, mt9m114_regs.iso_200_tbl_size);
			if (rc < 0)
				return rc;
			break;
		case CAMERA_ISO_400:
		 	rc = mt9m114_i2c_write_table(mt9m114_regs.iso_400_tbl, mt9m114_regs.iso_400_tbl_size);
			if (rc < 0)
				return rc;
			break;			
		default:
			return 0; //return -EINVAL;
	}
 	rc = mt9m114_i2c_write_table(mt9m114_regs.change_config_tbl, mt9m114_regs.change_config_tbl_size);
	if (rc < 0)
		return rc;	
	
	prev_iso_mode = mode;
	return rc;
}

static int mt9m114_set_antibanding(int mode)
{
	int32_t rc = 0;

	if(prev_antibanding_mode == mode)
	{
		printk(KERN_ERR "###  [CHECK]%s: skip this function, antibanding_mode -> %d\n", __func__, mode);
		return rc;
	}
       printk(KERN_ERR "###  [CHECK]%s: mode -> %d\n", __func__, mode);

	prev_antibanding_mode = mode;

	switch (mode) {
		case CAMERA_ANTIBANDING_60HZ:
			rc = mt9m114_i2c_write_w_sensor(0x098E, 0xCC03);
			if (rc < 0)
				return rc;	
			rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0200);
			if (rc < 0)
				return rc;
			break;
		case CAMERA_ANTIBANDING_50HZ:
			rc = mt9m114_i2c_write_w_sensor(0x098E, 0xCC03);
			if (rc < 0)
				return rc;
			rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0100);
			if (rc < 0)
				return rc;
			break;
		default:
			return 0;   // return -EINVAL;
	}
	return rc;	
}

static int brightness_table[] = {0xDC00, 0xE200, 0xE800, 0xEE00, 0xF400, 0xFA00, 0x0000, 0x0800, 0x1000, 0x1800, 0x2800, 0x3000, 0x3800}; // 13 step
																		// value < 0x80 --> value should be increased , max value => 0x7F00
							// value > 0x80 --> value should be decreased	, max value => 0x8100													
static int gamma_table_sub[] = {0x00DC, 0x00DC, 0x00DC, 0x00DC, 0x00DC, 0x00DC, 0x00DC, 0x00DC, 0x00DC, 0x00DC, 0x00C8, 0x00C8, 0x00C8}; // 13 step							
							// 2.2 gamma 															// 0.5 gamma
static int mt9m114_set_brightness(int mode)
{
	int32_t rc = 0;

	if(prev_brightness_mode == mode)
	{
		printk(KERN_ERR "###  [CHECK]%s: skip this function, brightness_mode -> %d\n", __func__, mode);
		return rc;
	}
	mode = mode%13;
        printk(KERN_ERR "###  [CHECK]%s: mode -> %d\n", __func__, mode);

	if(mode < 0 || mode > 12){
		CDBG("###[ERROR]%s: Invalid Mode value\n", __func__);
		return -EINVAL;	
	}
	rc = mt9m114_i2c_write_w_sensor(0x098E, 0xC870);
	if (rc < 0)
		return rc;	
	rc = mt9m114_i2c_write_w_sensor(0x0990, brightness_table[mode]);
	if (rc < 0)
		return rc;
	rc = mt9m114_i2c_write_w_sensor(0xC940, gamma_table_sub[mode]);
	if (rc < 0)
		return rc;


 	rc = mt9m114_i2c_write_table(mt9m114_regs.change_config_tbl, mt9m114_regs.change_config_tbl_size);
	if (rc < 0)
		return rc;	

	prev_brightness_mode = mode;
	
	return rc;
}

static int mt9m114_reg_preview(void)
{
	int rc = 0;

	printk(KERN_ERR "%s in :%d\n",__func__, __LINE__); 

 	rc = mt9m114_i2c_write_table(mt9m114_regs.prev_tbl, mt9m114_regs.prevtbl_size);
	if (rc < 0)
		return rc;

//	msleep(50);

	return rc;
}

static int mt9m114_reg_snapshot(void)
{
	int rc = 0;

	printk(KERN_ERR "%s in :%d\n",__func__, __LINE__); 

 	rc = mt9m114_i2c_write_table(mt9m114_regs.snap_tbl, mt9m114_regs.snaptbl_size);
	if (rc < 0)
		return rc;

//	msleep(50);
	
	return rc;
}

static long mt9m114_set_sensor_mode(int mode)
{
	int32_t rc = 0;
	int32_t temp_rc = 0;
	unsigned short test_data = 0;
	int retry = 0;
	struct msm_camera_csi_params mt9m114_csi_params;
	/* config mipi csi controller */
	printk(KERN_ERR "### %s: config mipi csi controller\n", __func__);
	if (config_csi == 0) {
		mt9m114_csi_params.lane_cnt = 1;
		mt9m114_csi_params.data_format = CSI_8BIT;
		mt9m114_csi_params.lane_assign = 0xe4;
		mt9m114_csi_params.dpcm_scheme = 0;
		mt9m114_csi_params.settle_cnt = 0x14;

	       printk(KERN_ERR "%s: config mipi enter \n", __func__);
		rc = msm_camio_csi_config(&mt9m114_csi_params);
		if (rc < 0)
			printk(KERN_ERR "config csi controller failed \n");

		msleep(50);
		config_csi = 1;
	}
	temp_rc = mt9m114_i2c_read(mt9m114_client->addr, 0xDC01, &test_data, WORD_LEN);
		if (temp_rc < 0)
			printk(KERN_ERR "0xDC01 Reg - I2C Read failed!\n");
		else
			printk(KERN_ERR "0xDC01 Reg -> 0x%x\n",test_data);
	switch (mode) {
	case SENSOR_PREVIEW_MODE:
// Start LGE_BSP_CAMERA::john.park@lge.com 2011-05-07  For flashing during re-init
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xDC01);
		if (rc < 0)
			return rc;

		mdelay(5);
		rc  = mt9m114_i2c_read(mt9m114_client->addr, 0x0990, &test_data, WORD_LEN);
		if (rc < 0)
			return rc;		
		
		if (test_data == 0x3100){
			printk(KERN_ERR "### %s: Skip preview mode , 0xDC01 Reg == 0x3100 \n", __func__);
			 return 0;
		}
		else{
			printk(KERN_ERR "### %s: Going preview mode ,0xDC01 Reg -> 0x%x\n",__func__, test_data);		
		}
// End LGE_BSP_CAMERA::john.park@lge.com 2011-05-07  For flashing during re-init		

		for (retry = 0; retry < 3; ++retry) {
			printk(KERN_ERR "[ERROR]%s:Sensor Preview Mode In\n", __func__);
			rc = mt9m114_reg_preview();
			if (rc < 0)
				printk(KERN_ERR "[ERROR]%s:Sensor Preview Mode Fail\n", __func__);
			else
				break;
		}
		break;
	case SENSOR_SNAPSHOT_MODE:
	case SENSOR_RAW_SNAPSHOT_MODE:
		for (retry = 0; retry < 3; ++retry) {
			printk(KERN_ERR "[ERROR]%s:Sensor Snapshot Mode In\n", __func__);
			rc = mt9m114_reg_snapshot();
			if (rc < 0)
				printk(KERN_ERR "[ERROR]%s:Sensor Snapshot Mode Fail\n", __func__);
			else
				break;
		}
		break;		
	default:
		rc = -EINVAL;
		break;
	}
	temp_rc = mt9m114_i2c_read(mt9m114_client->addr, 0xDC01, &test_data, WORD_LEN);
		if (temp_rc < 0)
			printk(KERN_ERR "0xDC01 Reg - I2C Read failed!\n");
		else
			printk(KERN_ERR "0xDC01 Reg -> 0x%x\n",test_data);
		
	return rc;
}

#if 1 // jonghwan.ko@lge.com
// LGE_CAMERA_S : Adjust VT Cam frame rate - jonghwan.ko@lge.com
static int mt9m114_set_Fps(int mode)
{
	int32_t rc = 0;
	
	printk(KERN_ERR "mt9m114_set_Fps mode = %d \n ",mode);
	
	if(prev_fps_mode == mode)
	{
		printk(KERN_ERR "###  [CHECK]%s: skip this function, prev_fps_mode -> %d\n", __func__, mode);
		return rc;
	}
	
	switch (mode) {			
		case SENSOR_FIXED_FPS_15://CAMERA_FPS_15:
			 // 15 fps fixed 
			rc = mt9m114_i2c_write_w_sensor(0x098E, 0x4812);
			if (rc < 0)
				return rc;	
			rc = mt9m114_i2c_write_w_sensor(0xC812, 0x07E0);
			if (rc < 0)
				return rc;			
			rc = mt9m114_i2c_write_w_sensor(0xC88E, 0x1E02);
			if (rc < 0)
				return rc;
			break;		
			
		case SENSOR_FIXED_FPS_30: //CAMERA_FPS_30:	// sunny
			// 30 fps fixed 
			rc = mt9m114_i2c_write_w_sensor(0x098E, 0x4812);
			if (rc < 0)
				return rc;	
			rc = mt9m114_i2c_write_w_sensor(0xC812, 0x03EE);
			if (rc < 0)
				return rc;			
			rc = mt9m114_i2c_write_w_sensor(0xC88E, 0x1E02);
			if (rc < 0)
				return rc;
		
			break;			
			
		case SENSOR_AUTO_FPS_1030: //CAMERA_FPS_10to30:
			// 10 fps ~ 30 fps variable 
			rc = mt9m114_i2c_write_w_sensor(0x098E, 0x4812);
			if (rc < 0)
				return rc;	
			rc = mt9m114_i2c_write_w_sensor(0xC812, 0x03EE);
			if (rc < 0)
				return rc;			
			rc = mt9m114_i2c_write_w_sensor(0xC88E, 0x0A00);
			if (rc < 0)
				return rc;
		
			break;			
			
		case SENSOR_AUTO_FPS_0730://CAMERA_FPS_7to30:  // cloudy
			 // 7.5 fps ~ 30 fps variable
			rc = mt9m114_i2c_write_w_sensor(0x098E, 0x4812);
			if (rc < 0)
				return rc;	
			rc = mt9m114_i2c_write_w_sensor(0xC812, 0x03EE);
			if (rc < 0)
				return rc;			
			rc = mt9m114_i2c_write_w_sensor(0xC88E, 0x0780);
			if (rc < 0)
				return rc;		
			break;
			
		default:
			// 30 fps fixed
			rc = mt9m114_i2c_write_w_sensor(0x098E, 0x4812);
			if (rc < 0)
				return rc;	
			rc = mt9m114_i2c_write_w_sensor(0xC812, 0x03EE);
			if (rc < 0)
				return rc;			
			rc = mt9m114_i2c_write_w_sensor(0xC88E, 0x1E02);
			if (rc < 0)
				return rc;		
		       printk(KERN_ERR "mt9m114_set_Fps wrong value : %d \n ",mode);
			break;
	}
	
 	rc = mt9m114_i2c_write_table(mt9m114_regs.change_config_tbl, mt9m114_regs.change_config_tbl_size);
	if (rc < 0)
		return rc;	

	prev_fps_mode = mode;
	printk(KERN_ERR "mt9m114_set_Fps Change Frame rate \n ");
	return rc;
}
// LGE_CAMERA_E : Adjust VT Cam frame rate - jonghwan.ko@lge.com
//LGE_CAMERA_S : AE_metering - jonghwan.ko@lge.com

static int mt9m114_set_AE_metering(int mode)
{
	int32_t rc = 0;

	if(prev_ae_metering_mode == mode)
	{
		printk(KERN_ERR "###  [CHECK]%s: skip this function, prev_ae_metering_mode -> %d\n", __func__, mode);
		return rc;
	}
	
	printk(KERN_ERR "###  [CHECK]%s: mode -> %d\n", __func__, mode);

	switch (mode) {
	case AE_METERING_DEFAULT: // AE DEFAULT metering:
		//[AE DEFAULT metering]
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA407);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA408);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA409);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40A);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40B);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40C);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40D);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x4B00);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40E);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x4B00);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40F);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x4B00);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA410);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA411);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA412);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x4B00);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA413);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x6400);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA414);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x4B00);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA415);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA416);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA417);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x4B00);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA418);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x4B00);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA419);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x4B00);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41A);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41B);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41C);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41D);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41E);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41F);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x1900);
	break;

	case AE_METERING_CENTER: //AE CENTER metering:  
		//[AE CENTER metering]
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA407);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA408);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA409);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40A);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40B);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40C);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40D);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40E);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA40F);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA410);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA411);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA412);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA413);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x6400);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA414);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA415);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA416);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA417);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA418);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA419);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41A);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41B);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41C);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41D);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41E);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
		rc = mt9m114_i2c_write_w_sensor(0x098E, 0xA41F);
		rc = mt9m114_i2c_write_w_sensor(0x0990, 0x0000);
	break;

	default:
	return -EINVAL;
	}

	prev_ae_metering_mode = mode;
	
	return rc;	
}

//LGE_CAMERA_E : AE_metering - jonghwan.ko@lge.com

#endif

int mt9m114_sensor_config(void __user *argp)
{
	struct sensor_cfg_data cfg_data;
	long   rc = 0;

	if (copy_from_user(&cfg_data,
			(void *)argp,
			sizeof(struct sensor_cfg_data)))
		return -EFAULT;

	mutex_lock(&mt9m114_sem);

	CDBG("mt9m114_ioctl, cfgtype = %d, mode = %d\n",
		cfg_data.cfgtype, cfg_data.mode);

		switch (cfg_data.cfgtype) {
		case CFG_SET_MODE:
			rc = mt9m114_set_sensor_mode(cfg_data.mode);
			break;

		case CFG_SET_EFFECT:
			rc = mt9m114_set_effect(cfg_data.mode);
			break;

		case CFG_SET_WB:
			rc = mt9m114_set_wb(cfg_data.mode);
			break;

		case CFG_SET_ISO:
			rc = mt9m114_set_iso(cfg_data.mode);
			break;

		case CFG_SET_ANTIBANDING:
			rc = mt9m114_set_antibanding(cfg_data.mode);
			break;
			
		case CFG_SET_BRIGHTNESS:
			rc = mt9m114_set_brightness(cfg_data.mode);
			break;			
//LGE_CAMERA_S : AE_metering - jonghwan.ko@lge.com
		case SENSOR_AE_METERING:
			rc = mt9m114_set_AE_metering(cfg_data.mode);
			break;
//LGE_CAMERA_E : AE_metering - jonghwan.ko@lge.com
// LGE_CAMERA_S : Adjust VT Cam frame rate - jonghwan.ko@lge.com		
		case CFG_FIXED_FPS:
			rc = mt9m114_set_Fps(cfg_data.mode);
			break;
// LGE_CAMERA_E : Adjust VT Cam frame rate - jonghwan.ko@lge.com			
		default:
			rc = -EINVAL;
			break;
		}

	mutex_unlock(&mt9m114_sem);

	return rc;
}

static int mt9m114_sensor_init_probe(const struct msm_camera_sensor_info *data)
{
	int rc = 0;

	CDBG("%s in :%d\n",__func__, __LINE__);

	rc = mt9m114_reset(data);
	if (rc < 0) {
		CDBG("reset failed!\n");
		goto init_probe_fail;
	}
//	mdelay(5);

	/* Micron suggested Power up block Start:
	* Put MCU into Reset - Stop MCU */
#if 0	
	rc = mt9m114_i2c_write(mt9m114_client->addr,
		REG_MT9M114_MCU_BOOT, 0x0501, WORD_LEN);
	if (rc < 0)
		goto init_probe_fail;

	/* Micron suggested Power up block End */
	/* Read the Model ID of the sensor */
	rc = mt9m114_i2c_read(mt9m114_client->addr,
		REG_MT9M114_MODEL_ID, &model_id, WORD_LEN);
	if (rc < 0)
		goto init_probe_fail;

	/* Check if it matches it with the value in Datasheet */
	if (model_id != MT9M114_MODEL_ID) {
		rc = -EINVAL;
		goto init_probe_fail;
	}
#endif

	rc = mt9m114_reg_init();
	if (rc < 0)
		goto init_probe_fail;

	CDBG("mt9m114_sensor_init_probe done\n");
	return rc;

init_probe_fail:
	mt9m114_probe_init_done(data);
	return rc;
}

int mt9m114_sensor_init(const struct msm_camera_sensor_info *data)
{
	int rc = 0;

	mt9m114_ctrl = kzalloc(sizeof(struct mt9m114_ctrl_t), GFP_KERNEL);
	if (!mt9m114_ctrl) {
		CDBG("mt9m114_init failed!\n");
		rc = -ENOMEM;
		goto init_done;
	}

	config_csi = 0;
	
	if (data)
		mt9m114_ctrl->sensordata = data;

#ifdef CONFIG_LGE_SENSOR_MT9M114
//	msm_camio_camif_pad_reg_reset();
#endif

	mutex_lock(&mt9m114_sem);

	rc = mt9m114_sensor_init_probe(data);

	mutex_unlock(&mt9m114_sem);

	if (rc < 0) {
		CDBG("mt9m114_sensor_init failed!\n");
		goto init_fail;
	}

	prev_effect_mode = -1;	
	prev_balance_mode = -1;
	prev_iso_mode = -1;	
	prev_antibanding_mode = -1;
	prev_brightness_mode = -1;	
//LGE_CAMERA_S : FPS - jonghwan.ko@lge.com
	prev_fps_mode = -1;
//LGE_CAMERA_E : FPS - jonghwan.ko@lge.com	

init_done:
	return rc;

init_fail:
	mt9m114_probe_init_done(data);	
	kfree(mt9m114_ctrl);
	return rc;
}

static int mt9m114_init_client(struct i2c_client *client)
{
	/* Initialize the MSM_CAMI2C Chip */
	init_waitqueue_head(&mt9m114_wait_queue);
	return 0;
}

int mt9m114_sensor_release(void)
{
	int rc = 0;

	mutex_lock(&mt9m114_sem);
	
	//gpio_direction_output(mt9m114_ctrl->sensordata->sensor_reset, 0);
	gpio_direction_output(mt9m114_ctrl->sensordata->vt_mclk_enable, 0);
	printk(KERN_ERR "%s = %d\n",__func__, mt9m114_ctrl->sensordata->vt_mclk_enable);
	gpio_free(mt9m114_ctrl->sensordata->sensor_reset);
    gpio_free(mt9m114_ctrl->sensordata->vt_mclk_enable);

	kfree(mt9m114_ctrl);

	mutex_unlock(&mt9m114_sem);

	return rc;
}

static int mt9m114_i2c_probe(struct i2c_client *client,
	const struct i2c_device_id *id)
{
	int rc = 0;
	CDBG("mt9m114_i2c_probe called!\n");
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		rc = -ENOTSUPP;
		CDBG("i2c_check_functionality failed\n");
		goto probe_failure;
	}

	mt9m114_sensorw =
		kzalloc(sizeof(struct mt9m114_work), GFP_KERNEL);

	if (!mt9m114_sensorw) {
		rc = -ENOMEM;
		CDBG("kzalloc failed.\n");
		goto probe_failure;
	}

	i2c_set_clientdata(client, mt9m114_sensorw);
	mt9m114_init_client(client);
	mt9m114_client = client;

	CDBG("mt9m114_probe succeeded!\n");

	return 0;

probe_failure:
	kfree(mt9m114_sensorw);
	mt9m114_sensorw = NULL;
	CDBG("mt9m114_probe failed!\n");
	return rc;
}

static const struct i2c_device_id mt9m114_i2c_id[] = {
	{ "mt9m114", 0},
	{ },
};

static struct i2c_driver mt9m114_i2c_driver = {
	.id_table = mt9m114_i2c_id,
	.probe  = mt9m114_i2c_probe,
	.remove = __exit_p(mt9m114_i2c_remove),
	.driver = {
		.name = "mt9m114",
	},
};

static int mt9m114_sensor_probe(const struct msm_camera_sensor_info *info,
				struct msm_sensor_ctrl *s)
{
	int rc = i2c_add_driver(&mt9m114_i2c_driver);
	if (rc < 0 || mt9m114_client == NULL) {
		CDBG("%s: ret =%d\n",__func__,rc);
		rc = -ENOTSUPP;
		goto probe_done;
	}
	s->s_init = mt9m114_sensor_init;
	s->s_release = mt9m114_sensor_release;
	s->s_config  = mt9m114_sensor_config;
	s->s_camera_type = FRONT_CAMERA_2D;
	s->s_mount_angle  = 270;

probe_done:
	CDBG("%s %s:%d\n", __FILE__, __func__, __LINE__);
	return rc;
}

static int __mt9m114_probe(struct platform_device *pdev)
{
	return msm_camera_drv_start(pdev, mt9m114_sensor_probe);
}

static struct platform_driver msm_camera_driver = {
	.probe = __mt9m114_probe,
	.driver = {
		.name = "msm_camera_mt9m114",
		.owner = THIS_MODULE,
	},
};

static int __init mt9m114_init(void)
{
	return platform_driver_register(&msm_camera_driver);
}

module_init(mt9m114_init);
