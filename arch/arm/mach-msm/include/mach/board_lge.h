/* arch/arm/mach-msm/include/mach/board_lge.h
 *
 * Copyright (C) 2011 LGE Corporation.
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

#ifndef __ASM_ARCH_MSM_BOARD_LGE_H
#define __ASM_ARCH_MSM_BOARD_LGE_H


#include <linux/types.h>
#include <linux/list.h>
#include <linux/i2c.h>
#include <linux/i2c-gpio.h>
#include <linux/rfkill.h>
#include <linux/platform_device.h>
#include <asm/setup.h>

//jinho.jang - add msm_rotator_control_status
#define MSM_ROTATOR_IOCTL_CHECK

#if 1 /* CONFIG_LGE_BOARD_SUPPORT */
enum {
  EVB1         = 0,
  EVB2,
  LGE_REV_A,
  LGE_REV_B,
  LGE_REV_C,
  LGE_REV_D,
  LGE_REV_E,
  LGE_REV_F,
  LGE_REV_G,
  // we don't use if this use, very big issue, LGE_REV_H,
  LGE_REV_10,
  LGE_REV_11,
  LGE_REV_12,
  // we don't use if this use, very big issue,LGE_REV_13,
  LGE_REV_TOT_NUM,
};

extern int lge_bd_rev;
#endif

#if 0 // remove
#ifdef CONFIG_LGE_PM_FACTORY_CURRENT_DOWN
enum {
 LGE_CABLE_56K,
 LGE_CABLE_130K,
 LGE_CABLE_910K,
 LGE_CABLE_NORMAL,
 LGE_CABLE_TOT_NUM,
};

extern int lge_cable_type;
#endif
#endif

#ifdef CONFIG_LGE_CHARGER_VOLTAGE_CURRENT_SCENARIO
enum {
	BATT_DS2704,
	BATT_ISL6296,
};

extern int lge_battery_info;
#endif

#ifdef CONFIG_LGE_SENSOR
#define SENSOR_POWER_OFF_K3DH	0x1
#define SENSOR_POWER_OFF_K3G	0x2
#define SENSOR_POWER_OFF_AMI306	0x4
#define SENSOR_POWER_OFF_VALID	0x7

enum {
	SENSOR_TYPE_ACCELEROMETER = 0, 	//K3DH
	SENSOR_TYPE_DCOMPASS,		//AMI306
	SENSOR_TYPE_GYROSCOPE,		//K3G
};
#endif

struct bluetooth_platform_data {
	int (*bluetooth_power)(int on);
	int (*bluetooth_toggle_radio)(void *data, bool blocked);
};

struct bluesleep_platform_data {
	int bluetooth_port_num;
};


struct gpio_i2c_pin {
	unsigned int sda_pin;
	unsigned int scl_pin;
	unsigned int reset_pin;
	unsigned int irq_pin;
};

struct synaptics_t1320_platform_data {
	int use_irq;
	unsigned long irqflags;
	int i2c_sda_gpio;
	int i2c_scl_gpio;
	int i2c_int_gpio;
	int (*power)(int on, bool log_on);
	int ic_booting_delay;		/* ms */
	int num_of_finger;
	int num_of_button;
	int button0;
	int button1;
	int button2;
	int button3;
	int x_max;
	int y_max;
	int fw_ver;
};

struct k3dh_acc_platform_data {
	int poll_interval;
	int min_interval;

	u8 g_range;

	u8 axis_map_x;
	u8 axis_map_y;
	u8 axis_map_z;

	u8 negate_x;
	u8 negate_y;
	u8 negate_z;

	int (*init)(void);
	void (*exit)(void);
	int (*power_on)(int);
	int (*power_off)(int);
	int gpio_int1;
	int gpio_int2;

};

struct k3g_platform_data 
{
	u8 fs_range;

	u8 axis_map_x;
	u8 axis_map_y;
	u8 axis_map_z;

	u8 negate_x;
	u8 negate_y;
	u8 negate_z;

	int (*init)(void);
	void (*exit)(void);
	int (*power_on)(int);
	int (*power_off)(int);
};

struct ami306_platform_data {
	int (*init)(void);
	void (*exit)(void);	
	int (*power_on)(int);
	int (*power_off)(int);

	int fdata_mDir;
	int fdata_sign_x;
	int fdata_sign_y;
	int fdata_sign_z;
	int fdata_order0;
	int fdata_order1;
	int fdata_order2;	
};

struct apds9900_platform_data {
	int irq_num;
	int (*power)(unsigned char onoff);
	unsigned int  prox_int_low_threshold;
	unsigned int  prox_int_high_threshold;
	unsigned int  als_threshold_hsyteresis;
	unsigned int  ppcount;
	unsigned int  B;
	unsigned int  C;
	unsigned int  D;
	unsigned int  alsit;
	unsigned int  ga_value;
	unsigned int  df_value;	
};
/* android vibrator platform data */
struct android_vibrator_platform_data {
	int enable_status;
	int (*power_set)(int enable);           /* LDO Power Set Function */
	int (*pwm_set)(int enable, int gain);           /* PWM Set Function */
	int (*ic_enable_set)(int enable);       /* Motor IC Set Function */
	int (*vibrator_init)(void);
};


int msm_snddev_enable_hdset_mic_power(void);
void msm_snddev_disable_hdset_mic_power(void);
int msm_snddev_enable_hdset_mic_bias(void);
void msm_snddev_disable_hdset_mic_bias(void);
void __init lge_add_misc_devices(void);

/* atcmd virtual keyboard platform data */
struct atcmd_virtual_platform_data {
	unsigned int keypad_row;
	unsigned int keypad_col;
	unsigned char *keycode;
};

/* implement in devices_lge.c */
void __init lge_add_atcmd_virtual_kbd_device(void);
void __init lge_add_eta_event_log_device(void);


#ifdef MSM_ROTATOR_IOCTL_CHECK
int  is_mt9p017_sensor_open(void);
void set_rotator_ctl_result(int result);
int get_rotator_ctl_result(void);
#endif
#endif
