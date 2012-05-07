/*
 *  Copyright (c) 2010 LGE.
 *
 *  All source code in this file is licensed under the following license
 *  except where indicated.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  version 2 as published by the Free Software Foundation.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, you can find it at http://www.fsf.org
 */

#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/input.h>
#include <linux/slab.h>

#include "eta_event_log.h"

#ifdef ETA_EVENT_LOG_DEBUG
#define PDEBUG(fmt, args...) printk("eta_event_log: " fmt, ## args)
#else
#define PDEBUG(fmt, args...)
#endif

#define JIFFIES_TO_MS(t) ((t) * 1000 / HZ)
#define ETA_CMD_STR "/system/bin/eta"

static struct input_handler input_handler;
static struct work_struct eta_event_log_work;
static struct eta_event_log_type eta_event_log_data;

static unsigned int eta_event_log_mask = 0x00000000;
static int touch_status = 0; 
static char touch_prev_action = ETA_TOUCH_DEFAULT;

static int eta_key_event[] = {
	/* keypad key */
	KEY_VOLUMEUP,
	KEY_VOLUMEDOWN,
	KEY_MENU,
	KEY_HOME,
	KEY_BACK,
	/* 7k_handset key */
	KEY_MEDIA,
	KEY_END,
};

static int eta_abs_event[] = {
	ABS_MT_TOUCH_MAJOR,
	ABS_MT_WIDTH_MAJOR,
	ABS_MT_POSITION_X,
	ABS_MT_POSITION_Y,
};

static const struct input_device_id eta_event_log_ids[] = {
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT,
		.evbit = { BIT_MASK(EV_KEY) },
	},
	{ },
};

/*------ Base64 Encoding Table ------*/
const char MimeBase64[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};

int base64_encode(char *text, int numBytes, char *encodedText)
{
	unsigned char input[3] = {0,0,0}; 
	unsigned char output[4] = {0,0,0,0}; 
	int  index, i, j; 
	char *p, *plen; 

	plen = text + numBytes - 1; 

	j = 0;

	for (i = 0, p = text;p <= plen; i++, p++) { 
	    index = i % 3; 
	    input[index] = *p;

		if (index == 2 || p == plen) { 
	    	output[0] = ((input[0] & 0xFC) >> 2); 
			output[1] = ((input[0] & 0x3) << 4) | ((input[1] & 0xF0) >> 4); 
			output[2] = ((input[1] & 0xF) << 2) | ((input[2] & 0xC0) >> 6); 
			output[3] = (input[2] & 0x3F);

			encodedText[j++] = MimeBase64[output[0]]; 
			encodedText[j++] = MimeBase64[output[1]]; 
			encodedText[j++] = index == 0? '=' : MimeBase64[output[2]]; 
			encodedText[j++] = index < 2? '=' : MimeBase64[output[3]];

			input[0] = input[1] = input[2] = 0; 
		} 
	}
	encodedText[j] = '\0';

	return strlen(encodedText); 	
}

int eta_execute_n(char *string, size_t size)
{
	int ret;
	char *cmdstr;

	char *envp[] = {
		"HOME=/",
		"TERM=linux",
		NULL,
	};

	char *argv[] = {
		ETA_CMD_STR,
		NULL,
		NULL,
	};

	size += 1;

	if (!(cmdstr = kmalloc(size, GFP_KERNEL)))
	{
		return ENOMEM;
	}

	argv[1] = cmdstr;
	memset(cmdstr, 0, size);

	snprintf(cmdstr, size, "AT+MTC=%s", string);
	PDEBUG("execute eta : data - %s\n", string);

	if ((ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC)) != 0) {
		PDEBUG("eta failed to run \": %i\n", ret);
	}

	kfree(cmdstr);
	return ret;
}

int eta_event_log_connect(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id)
{
	int i;
	int ret;
	struct input_handle *handle;

	if (dev->name == NULL)
		return 0;

	for (i = 0 ; i < ARRAY_SIZE(eta_key_event) - 1 ; i++) {
		if (test_bit(eta_key_event[i], dev->keybit))
			break;
	}

	for (i = 0 ; i < ARRAY_SIZE(eta_abs_event) - 1 ; i++) {
		if (test_bit(eta_abs_event[i], dev->absbit))
			break;
	}

	PDEBUG("connect () %s\n",dev->name);

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if(!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "eta_event_log";
	handle->private = NULL;

	ret = input_register_handle(handle);
	if (ret)
		goto err_input_register_handle;

	ret = input_open_device(handle);
	if (ret)
		goto err_input_open_device;

	return 0;

err_input_open_device:
	input_unregister_handle(handle);
err_input_register_handle:
	kfree(handle);
	return ret;
}

void eta_event_log_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

void eta_event_log_event(struct input_handle *handle, unsigned int type, unsigned int code, int value)
{
	PDEBUG("[%d] type: %u, code: 0x%x, value: %d\n", touch_status, type, code, value);

	if ( (type == EV_KEY) && (ETA_EVENT_LOG_ID_KEY & eta_event_log_mask)) {
		eta_event_log_data.log_id = ETA_EVENT_LOG_ID_KEY; /* LOG_ID, 1 key, 2 touch */
		eta_event_log_data.log_len = 18; /* LOG_LEN */
		eta_event_log_data.x_hold = value; /* hold */
		eta_event_log_data.y_code = code;
		schedule_work(&eta_event_log_work);
		PDEBUG("handler: key hold %d\n", eta_event_log_data.x_hold);
		PDEBUG("handler: key code 0x%x\n", eta_event_log_data.y_code);
	}
	else if ( (type == EV_ABS || type == EV_SYN) && (ETA_EVENT_LOG_ID_TOUCH& eta_event_log_mask) ){
		switch(code){
			case ABS_MT_TOUCH_MAJOR:
				{
					touch_status++;
					if(value > 0){ /* value = 1 is touch pressed case */
						if (touch_prev_action == ETA_TOUCH_DOWN)
							eta_event_log_data.action = (unsigned char)ETA_TOUCH_MOVETO;
						else
							eta_event_log_data.action = (unsigned char)ETA_TOUCH_DOWN;

						touch_prev_action = ETA_TOUCH_DOWN;
					}
					else {
						eta_event_log_data.action = (unsigned char)ETA_TOUCH_UP;
						touch_prev_action = ETA_TOUCH_UP;
					}
					break;
				}
			case ABS_MT_POSITION_X :
				{
					eta_event_log_data.x_hold = value * 1000 / 1541; // 1.541 = 1110(max X)/720(width)
					touch_status++;
					break;
				}
			case ABS_MT_POSITION_Y:
				{
					eta_event_log_data.y_code = value * 1000 / 1541; // 1.541 = 1973(max Y)/1280(height)
					touch_status++;
					break;
				}
		}
		
		if(touch_status == 3){
			eta_event_log_data.log_id = ETA_EVENT_LOG_ID_TOUCH; /* LOG_ID, 1 key, 2 touch */
			eta_event_log_data.log_len = 22; /*LOG_LEN */
			touch_status = 0;
			schedule_work(&eta_event_log_work);
			PDEBUG("handler: touch action 0x%x\n", eta_event_log_data.action);
			PDEBUG("handler: touch x %u\n", eta_event_log_data.x_hold);
			PDEBUG("handler: touch y %u\n", eta_event_log_data.y_code);
		}
	}
}

void eta_event_log_work_func(struct work_struct *work)
{
	unsigned char *eta_cmd_buf;
	unsigned char *eta_cmd_buf_encoded;
	int index =0;
	int lenb64 = 0;
	int exec_result = 0;
	unsigned long long eta_time_val = 0;
	
	eta_cmd_buf = kmalloc(sizeof(unsigned char)*50, GFP_KERNEL);
	if(!eta_cmd_buf) {
		printk(KERN_ERR "%s: Error in alloc memory!!\n", __func__);
		return;
	}

	eta_cmd_buf_encoded = kmalloc(sizeof(unsigned char)*50, GFP_KERNEL);

	if(!eta_cmd_buf_encoded) {
		printk(KERN_ERR "%s: Error in alloc memory!!\n", __func__);
		kfree(eta_cmd_buf);
		return;
	}

	memset(eta_cmd_buf,0x00, 50);
	memset(eta_cmd_buf_encoded,0x00, 50);
				
	index = 0;
	eta_cmd_buf[index++] = (unsigned char)0xF0; //MTC_CMD_CODE
	eta_cmd_buf[index++] = (unsigned char)0x08; //MTC_LOG_REQ_CMD

	eta_cmd_buf[index++] = (unsigned char)eta_event_log_data.log_id; //LOG_ID, 1 key, 2 touch
	eta_cmd_buf[index++] = (unsigned char)eta_event_log_data.log_len; //LOG_LEN
	eta_cmd_buf[index++] = (unsigned char)0; //LOG_LEN

	eta_time_val = (unsigned long long)JIFFIES_TO_MS(jiffies);
	eta_cmd_buf[index++] = (unsigned char)(eta_time_val & 0xff); //LSB
	eta_cmd_buf[index++] = (unsigned char)( (eta_time_val >> 8) & 0xff );
	eta_cmd_buf[index++] = (unsigned char)( (eta_time_val >> 16) & 0xff );
	eta_cmd_buf[index++] = (unsigned char)( (eta_time_val >> 24) & 0xff );
	eta_cmd_buf[index++] = (unsigned char)( (eta_time_val >> 32) & 0xff );
	eta_cmd_buf[index++] = (unsigned char)( (eta_time_val >> 40) & 0xff );
	eta_cmd_buf[index++] = (unsigned char)( (eta_time_val >> 48) & 0xff );
	eta_cmd_buf[index++] = (unsigned char)( (eta_time_val >> 56) & 0xff ); // MSB

	index = 13;
	if(eta_event_log_data.log_id == ETA_EVENT_LOG_ID_KEY)
	{
		eta_cmd_buf[index++] = (unsigned char)((eta_event_log_data.x_hold)&0xFF);// hold
		eta_cmd_buf[index++] = (unsigned char)((eta_event_log_data.y_code)&0xFF);//key code

		for(index = 15; index<23; index++) // ACTIVE_UIID 8
		{
			eta_cmd_buf[index] = 0;
		}
	}
	else if(eta_event_log_data.log_id == ETA_EVENT_LOG_ID_TOUCH)
	{
		eta_cmd_buf[index++] = (unsigned char)1; // MAIN LCD
		eta_cmd_buf[index++] = (unsigned char)eta_event_log_data.action;
		eta_cmd_buf[index++] = (unsigned char)((eta_event_log_data.x_hold)&0xFF);// index = 15
		eta_cmd_buf[index++] = (unsigned char)(((eta_event_log_data.x_hold)>>8)&0xFF);// index = 16
		eta_cmd_buf[index++] = (unsigned char)((eta_event_log_data.y_code)&0xFF);// index = 17
		eta_cmd_buf[index++] = (unsigned char)(((eta_event_log_data.y_code)>>8)&0xFF);// index = 18

		for(index = 19; index<27; index++) // ACTIVE_UIID 8
		{
			eta_cmd_buf[index] = 0;
		}
	}

	lenb64 = base64_encode((char *)eta_cmd_buf, index, (char *)eta_cmd_buf_encoded);
			
	exec_result = eta_execute_n(eta_cmd_buf_encoded, strlen(eta_cmd_buf_encoded));
	PDEBUG("AT+MTC exec_result %d\n",exec_result);

	kfree(eta_cmd_buf);
	kfree(eta_cmd_buf_encoded);
}

int eta_event_log_start(void)
{
	int ret = 0;

	PDEBUG("start eta event logging\n");

	input_handler.name = "eta_event_logger";
	input_handler.connect = eta_event_log_connect;
	input_handler.disconnect = eta_event_log_disconnect;
	input_handler.event = eta_event_log_event;
	input_handler.id_table = eta_event_log_ids;

	ret = input_register_handler(&input_handler);

	if (ret != 0)
		printk("%s:fail to registers input handler\n", __func__);
	    
	INIT_WORK(&eta_event_log_work, eta_event_log_work_func);

	return ret;
}

void eta_event_log_stop(void)
{
    PDEBUG("stop eta event logging\n");
	input_unregister_handler(&input_handler);
}

long eta_event_log_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int rc = 0;
	unsigned int log_mask = 0;

	switch (cmd) {
		case ETA_EVENT_LOG_IOC_CHANGE_LOG_MASK:
			if (copy_from_user((void *)&log_mask, argp, sizeof(unsigned int)))
				rc = -EFAULT;

			switch(log_mask)
			{
				case 0x00000000://ETA_LOGMASK_DISABLE_ALL:
				case 0xFFFFFFFF://ETA_LOGMASK_ENABLE_ALL:
				case 0x00000001://ETA_LOGITEM_KEY:
				case 0x00000002://ETA_LOGITEM_TOUCHPAD:
				case 0x00000003://ETA_LOGITME_KEYTOUCH:
					eta_event_log_mask = log_mask;
					break;
				default:
					eta_event_log_mask = 0x00000000;//ETA_LOGMASK_DISABLE_ALL;
					break;
			}

			if(log_mask & 0xFFFFFFFF)
				eta_event_log_start();
			else
				eta_event_log_stop();

			break;

		default:
			printk("[ETA EVENT LOG] wrong ioctl cmd\n");
			rc = -EINVAL;
	}

	return rc;
}

struct file_operations eta_event_log_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = eta_event_log_ioctl,
};

struct miscdevice eta_event_log_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "eta_event_log",
	.fops = &eta_event_log_fops,
};

int __devinit eta_event_logger_probe(struct platform_device *pdev)
{
	return misc_register(&eta_event_log_dev);
}

int __devexit eta_event_logger_remove(struct platform_device *pdev)
{
	return 0;
}

struct platform_driver eta_event_logger_driver = {
	.driver = {
		.name = "eta_event_logger",
		.owner = THIS_MODULE,
	},
	.probe = eta_event_logger_probe,
	.remove = eta_event_logger_remove,
};

int __init eta_event_logger_init(void)
{
	return platform_driver_register(&eta_event_logger_driver);
}


void __exit eta_event_logger_exit(void)
{
	platform_driver_unregister(&eta_event_logger_driver);
}

module_init(eta_event_logger_init);
module_exit(eta_event_logger_exit);

MODULE_AUTHOR("LG Electronics Inc.");
MODULE_DESCRIPTION("ETA event logging driver");
MODULE_LICENSE("GPL v2");
