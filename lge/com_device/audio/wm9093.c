/* lge/audio/wm9093.c
 *
 * Copyright (C) 2010 LGE, Inc.
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

#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/device.h>
#include <asm/gpio.h>
#include <asm/system.h>
#include <linux/jiffies.h>
#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include "wm9093.h"

#define	DEBUG_AMP_CTL	1

#define MODULE_NAME	"wm9093"

static uint32_t msm_snd_debug = 1;
module_param_named(debug_mask, msm_snd_debug, uint, 0664);

#if DEBUG_AMP_CTL
#define D(fmt, args...) printk(fmt, ##args)
#else
#define D(fmt, args...) do {} while(0)
#endif

/* This struct is used to save the context */
struct amp_data {
	struct i2c_client *client;
	struct wm9093_platform_data *pdata;
};

static struct amp_data *_data = NULL;

static int amp_read_register(u8 reg, int* ret)
{
	//ret = swab16(i2c_smbus_read_word_data(_data->client, reg));
	struct i2c_msg	xfer[2];
	u16				data = 0xffff;
	u16				retval;

	xfer[0].addr = _data->client->addr;
	xfer[0].flags = 0;
	xfer[0].len  = 1;
	xfer[0].buf = &reg;

	xfer[1].addr = _data->client->addr;
	xfer[1].flags = I2C_M_RD;
	xfer[1].len = 2;
	xfer[1].buf = (u8*)&data;

	retval = i2c_transfer(_data->client->adapter, xfer, 2);

	*ret =  (data>>8) | ((data & 0xff) << 8);

	return retval;
}

static int amp_write_register(u8 reg, int value)
{
	int				 err;
	unsigned char    buf[3];
	struct i2c_msg	msg = { _data->client->addr, 0, 3, &buf[0] }; 
	
	buf[0] = reg;
	buf[1] = (value & 0xFF00) >> 8;
	buf[2] = value & 0x00FF;

	if ((err = i2c_transfer(_data->client->adapter, &msg, 1)) < 0){
		return -EIO;
	} 
	else {
		return 0;
	}
}

void check_audio_i2c_data(int RtnVal, wmCodecCmd wmReg)
{
#if 0//def DEBUG_AMP_CTL
	int rtnRD = 0;
	int wmrData = 0;
	
	if (RtnVal < 0)
		D(KERN_ERR "WM9093 I2C Write FAIL : reg = 0x%X, data = 0x%X\n",wmReg.wmaddress,wmReg.wmdata);
	else
		D(KERN_INFO "WM9093 I2C Write OK : reg = 0x%X, data = 0x%X\n",wmReg.wmaddress,wmReg.wmdata);


							
	rtnRD = amp_read_register(wmReg.wmaddress, &wmrData);

							
	if (rtnRD > 0)
		D(KERN_INFO "WM9093 I2C Read OK : reg = 0x%X, data = 0x%X\n",wmReg.wmaddress,wmrData&0xFFFF);
	else
		D(KERN_ERR "WM9093 I2C Read FAIL : reg = 0x%X, data = 0x%X\n",wmReg.wmaddress,wmrData&0xFFFF);
#endif	

}

static void wm9093_cmd_register_sequence(struct wm9093_CodecCmd_data *seq) {
	int idx = 0;
    int rtnWD = 0;
	D(KERN_INFO "voc_codec b Tuning Flag %d \n", _data->pdata->bTuningOnOff); 
	
	for(idx = 0; idx < seq->amp_function_size; idx++)
	{	
		if(_data->pdata->bTuningOnOff)
		{
			D(KERN_INFO "WM9093 Tuning Parameter SET \n");
			rtnWD = amp_write_register(seq->amp_tuning_function[idx].wmaddress, seq->amp_tuning_function[idx].wmdata);
			check_audio_i2c_data(rtnWD , seq->amp_tuning_function[idx]);
		}
		else
		{
			rtnWD = amp_write_register(seq->amp_function[idx].wmaddress, seq->amp_function[idx].wmdata);
			check_audio_i2c_data(rtnWD , seq->amp_function[idx]);

		}
	}
}

void wm9093_cmd_register(wmCodecCmd wmCmd) {

    int rtnWD = 0;
	rtnWD = amp_write_register(wmCmd.wmaddress, wmCmd.wmdata);
	check_audio_i2c_data(rtnWD , wmCmd);

}

void wm9093_reg_dump(int icodec_num)
{

 //   int rtnWD = 0;
	int i=0;
	int read_result;
	int reg_val;
	D(KERN_INFO "************** wm regs *************\n");
	
	if (NULL == _data) {
		printk(KERN_ERR "wm9093 is not initialized yet\n");
		return;
	}

	switch(icodec_num) {
		case ICODEC_HANDSET_RX:
        case  ICODEC_AMP_OFF:
			break;
				
		case  ICODEC_HEADSET_ST_RX:
		D(KERN_INFO "************** wm HDSET regs *************\n");		
		for (i = 0; i < _data->pdata->hph_on.amp_function_size ; i++) {
			read_result = amp_read_register((u8)_data->pdata->hph_on.amp_function[i].wmaddress, &reg_val);
			if (read_result < 0) {
				D(KERN_INFO "failed to read codec register\n");
				break;
			} else
			D(KERN_INFO "WM9093[0x%02X] Oval: 0x%04X Tval: 0x%04X Readval: 0x%04X\n", _data->pdata->hph_on.amp_function[i].wmaddress,_data->pdata->hph_on.amp_function[i].wmdata ,_data->pdata->hph_on.amp_tuning_function[i].wmdata,reg_val);
			
		}
		break;

		case  ICODEC_SPEAKER_RX:
		D(KERN_INFO "************** wm SPK regs *************\n");			
			for (i = 0; i < _data->pdata->speaker_on.amp_function_size ; i++) {
				read_result = amp_read_register((u8)_data->pdata->speaker_on.amp_function[i].wmaddress, &reg_val);
				if (read_result < 0) {
					D(KERN_INFO "failed to read codec register\n");
					break;
				} else
				D(KERN_INFO "WM9093[0x%02X] Oval: 0x%04X Tval: 0x%04X Readval: 0x%04X\n", _data->pdata->speaker_on.amp_function[i].wmaddress,_data->pdata->speaker_on.amp_function[i].wmdata ,_data->pdata->speaker_on.amp_tuning_function[i].wmdata,reg_val);
				
			}
		break;	

		case ICODEC_HEADSET_ST_RX_SPEAKER_RX:   // simultaneously Ringing Headset and SPK
			D(KERN_INFO "************** wm HDSET and SPK regs *************\n");			
			for (i = 0; i < _data->pdata->hph_spk_on.amp_function_size ; i++) {
				read_result = amp_read_register((u8)_data->pdata->hph_spk_on.amp_function[i].wmaddress, &reg_val);
				if (read_result < 0) {
					D(KERN_INFO "failed to read codec register\n");
					break;
				} else
				D(KERN_INFO "WM9093[0x%02X] Oval: 0x%04X Tval: 0x%04X Readval: 0x%04X\n", _data->pdata->hph_spk_on.amp_function[i].wmaddress,_data->pdata->hph_spk_on.amp_function[i].wmdata ,_data->pdata->hph_spk_on.amp_tuning_function[i].wmdata,reg_val);
				
			}
        break;
		case  ICODEC_HEADSET_ST_PLAYBACK_RX:
		D(KERN_INFO "************** wm MUSIC HDSET regs *************\n");		
		for (i = 0; i < _data->pdata->hph_playback_on.amp_function_size ; i++) {
			read_result = amp_read_register((u8)_data->pdata->hph_playback_on.amp_function[i].wmaddress, &reg_val);
			if (read_result < 0) {
				D(KERN_INFO "failed to read codec register\n");
				break;
			} else
			D(KERN_INFO "WM9093[0x%02X] Oval: 0x%04X Tval: 0x%04X Readval: 0x%04X\n", _data->pdata->hph_playback_on.amp_function[i].wmaddress,_data->pdata->hph_playback_on.amp_function[i].wmdata ,_data->pdata->hph_playback_on.amp_tuning_function[i].wmdata,reg_val);
			
		}
		break;

		case  ICODEC_SPEAKER_PLAYBACK_RX:
		D(KERN_INFO "************** wm MUSIC SPK regs *************\n");			
			for (i = 0; i < _data->pdata->speaker_playback_on.amp_function_size ; i++) {
				read_result = amp_read_register((u8)_data->pdata->speaker_playback_on.amp_function[i].wmaddress, &reg_val);
				if (read_result < 0) {
					D(KERN_INFO "failed to read codec register\n");
					break;
				} else
				D(KERN_INFO "WM9093[0x%02X] Oval: 0x%04X Tval: 0x%04X Readval: 0x%04X\n", _data->pdata->speaker_playback_on.amp_function[i].wmaddress,_data->pdata->speaker_playback_on.amp_function[i].wmdata ,_data->pdata->speaker_playback_on.amp_tuning_function[i].wmdata,reg_val);
				
			}
		break;	
		
		default:
			for (i = 0; i < 0x50 ; i++) {
			read_result = amp_read_register((u8)i, &reg_val);
			if (read_result < 0) {
				D(KERN_INFO "failed to read codec register\n");
				break;
			} else
				D(KERN_INFO "WM9093 reg 0x%02X val 0x%04X\n", i, reg_val);
		}	
		break;	
			
	}
	D(KERN_INFO "*****************************************\n");
}
void wm9093_set_amp_path(int icodec_num)
{

	if (NULL == _data) {
		D(KERN_ERR "wm9093 is not initialized yet\n");
		return;
	}
	
	switch(icodec_num) {
		case ICODEC_HANDSET_RX:
			D(KERN_INFO "voc_codec %d does not use the amp\n", icodec_num);
			break;

        case  ICODEC_AMP_OFF:
			D(KERN_INFO "voc_codec %d  amp off\n", icodec_num);
			wm9093_cmd_register_sequence(&(_data->pdata->power_down));
			break;
				
		case  ICODEC_HEADSET_ST_RX:
			D(KERN_INFO "voc_codec %d  for HEADSET_ST_RX amp\n", icodec_num);
			wm9093_cmd_register_sequence(&(_data->pdata->hph_on));
			break;

		case  ICODEC_SPEAKER_RX:
			D(KERN_INFO "voc_codec %d for SPEAKER_RX amp\n", icodec_num);
			wm9093_cmd_register_sequence(&(_data->pdata->speaker_on));
			break;

        case ICODEC_HEADSET_ST_RX_SPEAKER_RX:   // simultaneously Ringing Headset and SPK
            D(KERN_INFO "voc_codec %d for HEADSET_ST_RX_SPEAKER_RX amp\n", icodec_num);
            wm9093_cmd_register_sequence(&(_data->pdata->hph_spk_on));
            break;

        case ICODEC_TTY_RX: // TTY
            D(KERN_INFO "voc_codec %d for TTY_RX amp\n", icodec_num);
            wm9093_cmd_register_sequence(&(_data->pdata->tty_on));
            break;

        case ICODEC_SPEAKER_PLAYBACK_RX:   // Playback not call
            D(KERN_INFO "voc_codec %d for ICODEC_SPEAKER_PLAYBACK_RX amp\n", icodec_num);
            wm9093_cmd_register_sequence(&(_data->pdata->speaker_playback_on));
            break;

        case ICODEC_SPEAKER_PLAYBACK_VZWNAVI:   // Playback not call
            D(KERN_INFO "voc_codec %d for ICODEC_SPEAKER_VZW_NAVI amp\n", icodec_num);
            wm9093_cmd_register_sequence(&(_data->pdata->speaker_vzwnavi_on));
            break;

        case ICODEC_HEADSET_ST_PLAYBACK_RX:   // Playback not call
            D(KERN_INFO "voc_codec %d for ICODEC_HEADSET_ST_PLAYBACK_RX amp\n", icodec_num);
            wm9093_cmd_register_sequence(&(_data->pdata->hph_playback_on));
            break;

		default :
			D(KERN_INFO "voc_icodec %d does not support AMP\n", icodec_num);
			break;
    }
}

static int wm9093_amp_ctl_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct amp_data *data;
	struct i2c_adapter* adapter = client->adapter;
	int err;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_WORD_DATA)){
		err = -EOPNOTSUPP;
		return err;
	}

	if (msm_snd_debug & 1)
		D(KERN_INFO "%s()\n", __FUNCTION__);

	data = kzalloc(sizeof(struct amp_data), GFP_KERNEL);
	if (NULL == data) {
		dev_err(&client->dev, "Can not allocate memory\n");
		return -ENOMEM;
	}

	if (client->dev.platform_data) {
		data->pdata = client->dev.platform_data;		
		data->pdata->set_amp_path = wm9093_set_amp_path;
		data->pdata->wm9093_cmd_register = wm9093_cmd_register;
		data->pdata->wm9093_reg_dump = wm9093_reg_dump;
		_data = data;
		data->client = client;
		i2c_set_clientdata(client, data);
	} else {
		dev_err(&client->dev, "No platform data to initialize\n");
		return -EINVAL;
	}

	
	if (msm_snd_debug & 1)
		D(KERN_INFO "%s chip found\n", client->name);
	err = amp_write_register(0x00, 0x9093);
	if (err == 0)
		D(KERN_INFO "AMP INIT OK\n");
	else
		D(KERN_ERR "AMP INIT ERR\n");
	msleep(100);
	return 0;
}

static int wm9093_amp_ctl_remove(struct i2c_client *client)
{
	struct amp_data *data = i2c_get_clientdata(client);
	wm9093_set_amp_path(ICODEC_AMP_OFF);
	data->pdata->set_amp_path = NULL;
	msleep(100);
	_data = NULL;
	kfree (data);
	
	D(KERN_INFO "%s()\n", __FUNCTION__);
	i2c_set_clientdata(client, NULL);
	return 0;
}


static struct i2c_device_id wm9093_amp_idtable[] = {
	{ "wm9093", 1 },
};

static struct i2c_driver wm9093_amp_ctl_driver = {
	.probe = wm9093_amp_ctl_probe,
	.remove = wm9093_amp_ctl_remove,
	.id_table = wm9093_amp_idtable,
	.driver = {
		.name = MODULE_NAME,
	},
};

static int __init wm9093_amp_ctl_init(void)
{
	return i2c_add_driver(&wm9093_amp_ctl_driver);	
}

static void __exit wm9093_amp_ctl_exit(void)
{
	return i2c_del_driver(&wm9093_amp_ctl_driver);
}

module_init(wm9093_amp_ctl_init);
module_exit(wm9093_amp_ctl_exit);

MODULE_DESCRIPTION("WM9093 Audio Subsystem Control");
MODULE_AUTHOR("DongSung SHIN <dongsung.shin@lge.com");
MODULE_LICENSE("GPL");
