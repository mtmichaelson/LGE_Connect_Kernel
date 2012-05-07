/* Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/*
 * Qualcomm PMIC 8058 Battery Alarm Device driver
 *
 */

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/pmic8058-batt-alarm.h>
#include <linux/mfd/pmic8058.h>

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
#include <linux/wakelock.h>
#include <linux/msm-charger.h>
#include <linux/max17040_battery.h>
#endif

/* PMIC 8058 Battery Alarm SSBI registers */
#define	REG_THRESHOLD			0x023
#define	REG_CTRL1			0x024
#define	REG_CTRL2			0x0AA
#define	REG_PWM_CTRL			0x0A3

/* Available voltage threshold values */
#define THRESHOLD_MIN_MV		2500
#define THRESHOLD_MAX_MV		5675
#define THRESHOLD_STEP_MV		25

/* Register bit definitions */

/* Threshold register */
#define THRESHOLD_UPPER_MASK		0xF0
#define THRESHOLD_LOWER_MASK		0x0F
#define THRESHOLD_UPPER_SHIFT		4
#define THRESHOLD_LOWER_SHIFT		0

/* CTRL 1 register */
#define CTRL1_BATT_ALARM_EN_MASK	0x80
#define CTRL1_HOLD_TIME_MASK		0x70
#define CTRL1_STATUS_UPPER_MASK		0x02
#define CTRL1_STATUS_LOWER_MASK		0x01
#define CTRL1_HOLD_TIME_SHIFT		4
#define CTRL1_HOLD_TIME_MIN		0
#define CTRL1_HOLD_TIME_MAX		7

/* CTRL 2 register */
#define CTRL2_COMP_UPPER_DISABLE_MASK	0x80
#define CTRL2_COMP_LOWER_DISABLE_MASK	0x40
#define CTRL2_FINE_STEP_UPPER_MASK	0x30
#define CTRL2_RANGE_EXT_UPPER_MASK	0x08
#define CTRL2_FINE_STEP_LOWER_MASK	0x06
#define CTRL2_RANGE_EXT_LOWER_MASK	0x01
#define CTRL2_FINE_STEP_UPPER_SHIFT	4
#define CTRL2_FINE_STEP_LOWER_SHIFT	1

/* PWM control register */
#define PWM_CTRL_ALARM_EN_MASK		0xC0
#define PWM_CTRL_ALARM_EN_NEVER		0x00
#define PWM_CTRL_ALARM_EN_TCXO		0x40
#define PWM_CTRL_ALARM_EN_PWM		0x80
#define PWM_CTRL_ALARM_EN_ALWAYS	0xC0
#define PWM_CTRL_PRE_MASK		0x38
#define PWM_CTRL_DIV_MASK		0x07
#define PWM_CTRL_PRE_SHIFT		3
#define PWM_CTRL_DIV_SHIFT		0
#define PWM_CTRL_PRE_MIN		0
#define PWM_CTRL_PRE_MAX		7
#define PWM_CTRL_DIV_MIN		1
#define PWM_CTRL_DIV_MAX		7

/* PWM control input range */
#define PWM_CTRL_PRE_INPUT_MIN		2
#define PWM_CTRL_PRE_INPUT_MAX		9
#define PWM_CTRL_DIV_INPUT_MIN		2
#define PWM_CTRL_DIV_INPUT_MAX		8

/* Available voltage threshold values */
#define THRESHOLD_BASIC_MIN_MV		2800
#define THRESHOLD_EXT_MIN_MV		4400

/*
 * Default values used during initialization:
 * Slowest PWM rate to ensure minimal status jittering when crossing thresholds.
 * Largest hold time also helps reduce status value jittering.  Comparators
 * are disabled by default and must be turned on by calling
 * pm8058_batt_alarm_state_set.
 */
#ifdef CONFIG_LGE_PM_BATTERY_ALARM
#define DEFAULT_THRESHOLD_LOWER		3500
#define DEFAULT_THRESHOLD_UPPER		4350
#else
#define DEFAULT_THRESHOLD_LOWER		3200
#define DEFAULT_THRESHOLD_UPPER		4300
#endif
#define DEFAULT_HOLD_TIME		PM8058_BATT_ALARM_HOLD_TIME_16_MS
#define DEFAULT_USE_PWM			1
#define DEFAULT_PWM_SCALER		9
#define DEFAULT_PWM_DIVIDER		8
#ifdef CONFIG_LGE_PM_BATTERY_ALARM
#define DEFAULT_LOWER_ENABLE		1
#define DEFAULT_UPPER_ENABLE		0 /* now, not used */
#else
#define DEFAULT_LOWER_ENABLE		0
#define DEFAULT_UPPER_ENABLE		0
#endif

#ifdef CONFIG_LGE_CHARGER_VOLTAGE_CURRENT_SCENARIO
extern int lge_battery_info;
#define DEFAULT_THRESHOLD_LOWER_CALC(x)		(3500 - (x*0))
#define DEFAULT_THRESHOLD_UPPER_CALC(x)		(4350 - (x*150))
#endif

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
/* kiwone.seo@lge.com 2011-08-14, bug fix of resume charging and low battery alarm */
#define AUTO_CHARGING_RESUME_MV_CALC(x) (4250-(x*150))
#endif

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
#undef LGE_DEBUG

#define P00_THRESHOLD_LOWER(x)		DEFAULT_THRESHOLD_LOWER_CALC(x)		/* 3500mV */
#define P01_THRESHOLD_LOWER(x)		P00_THRESHOLD_LOWER(x) + 50	/* 3550mV */
#define P03_THRESHOLD_LOWER(x)		P01_THRESHOLD_LOWER(x) + 50	/* 3600mV */
#define P15_THRESHOLD_LOWER(x)		P03_THRESHOLD_LOWER(x) + 50	/* 3650mV */

struct wake_lock batt_alarm_wake_lock;
extern int max17040_get_battery_capacity_percent(void);
extern int max17040_get_battery_mvolts(void);
extern int is_chg_plugged_in(void);
extern int batt_alarm_state;
int threshold_mv = DEFAULT_THRESHOLD_LOWER;
#endif

struct pm8058_batt_alarm_device {
	struct srcu_notifier_head		irq_notifier_list;
	struct pm8058_chip			*pm_chip;
	struct mutex				batt_mutex;
	unsigned int				irq;
	int					notifier_count;
	u8					reg_threshold;
	u8					reg_ctrl1;
	u8					reg_ctrl2;
	u8					reg_pwm_ctrl;
};
static struct pm8058_batt_alarm_device *the_battalarm;

static int pm8058_reg_write(struct pm8058_chip *chip, u16 addr, u8 val, u8 mask,
			    u8 *reg_save)
{
	int rc = 0;
	u8 reg;

	reg = (*reg_save & ~mask) | (val & mask);
	if (reg != *reg_save)
		rc = pm8058_write(chip, addr, &reg, 1);
	if (rc)
		pr_err("pm8058_write failed; addr=%03X, rc=%d\n", addr, rc);
	else
		*reg_save = reg;
	return rc;
}

/**
 * pm8058_batt_alarm_state_set - enable or disable the threshold comparators
 * @enable_lower_comparator: 1 = enable comparator, 0 = disable comparator
 * @enable_upper_comparator: 1 = enable comparator, 0 = disable comparator
 *
 * RETURNS: an appropriate -ERRNO error value on error, or zero for success.
 */
int pm8058_batt_alarm_state_set(int enable_lower_comparator,
				int enable_upper_comparator)
{
	struct pm8058_batt_alarm_device *battdev = the_battalarm;
	int rc;
	u8 reg_ctrl1 = 0, reg_ctrl2 = 0;

	if (!battdev) {
		pr_err("no battery alarm device found.\n");
		return -ENXIO;
	}

	if (!enable_lower_comparator)
		reg_ctrl2 |= CTRL2_COMP_LOWER_DISABLE_MASK;
	if (!enable_upper_comparator)
		reg_ctrl2 |= CTRL2_COMP_UPPER_DISABLE_MASK;

	if (enable_lower_comparator || enable_upper_comparator)
		reg_ctrl1 = CTRL1_BATT_ALARM_EN_MASK;

#ifdef LGE_DEBUG
	if (!enable_lower_comparator && !enable_upper_comparator)
		pr_info("BATTERY ALARM SET DISABLE\n");
	else if(enable_lower_comparator && enable_upper_comparator)
		pr_info("BATTERY ALARM SET ENABLE\n");
	else if(enable_lower_comparator && !enable_upper_comparator)
		pr_info("BATTERY ALARM LOWER SET ENABLE\n");
	else if(!enable_lower_comparator && enable_upper_comparator)
		pr_info("BATTERY ALARM UPPER SET ENABLE\n");
#endif

	mutex_lock(&battdev->batt_mutex);
	rc = pm8058_reg_write(battdev->pm_chip, REG_CTRL1, reg_ctrl1,
				CTRL1_BATT_ALARM_EN_MASK, &battdev->reg_ctrl1);
	if (rc)
		goto bail;

	rc = pm8058_reg_write(battdev->pm_chip, REG_CTRL2, reg_ctrl2,
		CTRL2_COMP_LOWER_DISABLE_MASK | CTRL2_COMP_UPPER_DISABLE_MASK,
		&battdev->reg_ctrl2);

bail:
	mutex_unlock(&battdev->batt_mutex);
	return rc;
}
EXPORT_SYMBOL_GPL(pm8058_batt_alarm_state_set);

/**
 * pm8058_batt_alarm_threshold_set - set the lower and upper alarm thresholds
 * @lower_threshold_mV: battery undervoltage threshold in millivolts
 * @upper_threshold_mV: battery overvoltage threshold in millivolts
 *
 * RETURNS: an appropriate -ERRNO error value on error, or zero for success.
 */
int pm8058_batt_alarm_threshold_set(int lower_threshold_mV,
				    int upper_threshold_mV)
{
	struct pm8058_batt_alarm_device *battdev = the_battalarm;
	int step, fine_step, rc;
	u8 reg_threshold = 0, reg_ctrl2 = 0;

	//pr_err("%s : lower_threshold_mV = %d, upper_threshold_mV = %d\n", __func__, lower_threshold_mV, upper_threshold_mV);
	if (!battdev) {
		pr_err("no battery alarm device found.\n");
		return -ENXIO;
	}

	if (lower_threshold_mV < THRESHOLD_MIN_MV
	    || lower_threshold_mV > THRESHOLD_MAX_MV) {
		pr_err("lower threshold value, %d mV, is outside of allowable "
			"range: [%d, %d] mV\n", lower_threshold_mV,
			THRESHOLD_MIN_MV, THRESHOLD_MAX_MV);
		return -EINVAL;
	}

	if (upper_threshold_mV < THRESHOLD_MIN_MV
	    || upper_threshold_mV > THRESHOLD_MAX_MV) {
		pr_err("upper threshold value, %d mV, is outside of allowable "
			"range: [%d, %d] mV\n", upper_threshold_mV,
			THRESHOLD_MIN_MV, THRESHOLD_MAX_MV);
		return -EINVAL;
	}

	if (upper_threshold_mV < lower_threshold_mV) {
		pr_err("lower threshold value, %d mV, must be <= upper "
			"threshold value, %d mV\n", lower_threshold_mV,
			upper_threshold_mV);
		return -EINVAL;
	}

	/* Determine register settings for lower threshold. */
	if (lower_threshold_mV < THRESHOLD_BASIC_MIN_MV) {
		/* Extended low range */
		reg_ctrl2 |= CTRL2_RANGE_EXT_LOWER_MASK;

		step = (lower_threshold_mV - THRESHOLD_MIN_MV)
			/ THRESHOLD_STEP_MV;

		fine_step = step & 0x3;
		/* Extended low range is for steps 0 to 2 */
		step >>= 2;

		reg_threshold |= (step << THRESHOLD_LOWER_SHIFT)
				 & THRESHOLD_LOWER_MASK;
		reg_ctrl2 |= (fine_step << CTRL2_FINE_STEP_LOWER_SHIFT)
			     & CTRL2_FINE_STEP_LOWER_MASK;
	} else if (lower_threshold_mV >= THRESHOLD_EXT_MIN_MV) {
		/* Extended high range */
		reg_ctrl2 |= CTRL2_RANGE_EXT_LOWER_MASK;

		step = (lower_threshold_mV - THRESHOLD_EXT_MIN_MV)
			/ THRESHOLD_STEP_MV;

		fine_step = step & 0x3;
		/* Extended high range is for steps 3 to 15 */
		step = (step >> 2) + 3;

		reg_threshold |= (step << THRESHOLD_LOWER_SHIFT)
				 & THRESHOLD_LOWER_MASK;
		reg_ctrl2 |= (fine_step << CTRL2_FINE_STEP_LOWER_SHIFT)
			     & CTRL2_FINE_STEP_LOWER_MASK;
	} else {
		/* Basic range */
		step = (lower_threshold_mV - THRESHOLD_BASIC_MIN_MV)
			/ THRESHOLD_STEP_MV;

		fine_step = step & 0x3;
		step >>= 2;

		reg_threshold |= (step << THRESHOLD_LOWER_SHIFT)
				 & THRESHOLD_LOWER_MASK;
		reg_ctrl2 |= (fine_step << CTRL2_FINE_STEP_LOWER_SHIFT)
			     & CTRL2_FINE_STEP_LOWER_MASK;
	}

	/* Determine register settings for upper threshold. */
	if (upper_threshold_mV < THRESHOLD_BASIC_MIN_MV) {
		/* Extended low range */
		reg_ctrl2 |= CTRL2_RANGE_EXT_UPPER_MASK;

		step = (upper_threshold_mV - THRESHOLD_MIN_MV)
			/ THRESHOLD_STEP_MV;

		fine_step = step & 0x3;
		/* Extended low range is for steps 0 to 2 */
		step >>= 2;

		reg_threshold |= (step << THRESHOLD_UPPER_SHIFT)
				 & THRESHOLD_UPPER_MASK;
		reg_ctrl2 |= (fine_step << CTRL2_FINE_STEP_UPPER_SHIFT)
			     & CTRL2_FINE_STEP_UPPER_MASK;
	} else if (upper_threshold_mV >= THRESHOLD_EXT_MIN_MV) {
		/* Extended high range */
		reg_ctrl2 |= CTRL2_RANGE_EXT_UPPER_MASK;

		step = (upper_threshold_mV - THRESHOLD_EXT_MIN_MV)
			/ THRESHOLD_STEP_MV;

		fine_step = step & 0x3;
		/* Extended high range is for steps 3 to 15 */
		step = (step >> 2) + 3;

		reg_threshold |= (step << THRESHOLD_UPPER_SHIFT)
				 & THRESHOLD_UPPER_MASK;
		reg_ctrl2 |= (fine_step << CTRL2_FINE_STEP_UPPER_SHIFT)
			     & CTRL2_FINE_STEP_UPPER_MASK;
	} else {
		/* Basic range */
		step = (upper_threshold_mV - THRESHOLD_BASIC_MIN_MV)
			/ THRESHOLD_STEP_MV;

		fine_step = step & 0x3;
		step >>= 2;

		reg_threshold |= (step << THRESHOLD_UPPER_SHIFT)
				 & THRESHOLD_UPPER_MASK;
		reg_ctrl2 |= (fine_step << CTRL2_FINE_STEP_UPPER_SHIFT)
			     & CTRL2_FINE_STEP_UPPER_MASK;
	}

	mutex_lock(&battdev->batt_mutex);
	rc = pm8058_reg_write(battdev->pm_chip, REG_THRESHOLD, reg_threshold,
				THRESHOLD_LOWER_MASK | THRESHOLD_UPPER_MASK,
				&battdev->reg_threshold);
	if (rc)
		goto bail;

	rc = pm8058_reg_write(battdev->pm_chip, REG_CTRL2, reg_ctrl2,
		CTRL2_FINE_STEP_LOWER_MASK | CTRL2_FINE_STEP_UPPER_MASK
		  | CTRL2_RANGE_EXT_LOWER_MASK | CTRL2_RANGE_EXT_UPPER_MASK,
		&battdev->reg_ctrl2);

bail:
	mutex_unlock(&battdev->batt_mutex);
	return rc;
}
EXPORT_SYMBOL_GPL(pm8058_batt_alarm_threshold_set);

/**
 * pm8058_batt_alarm_status_read - get status of both threshold comparators
 *
 * RETURNS:	< 0	   = error
 *		  0	   = battery voltage ok
 *		BIT(0) set = battery voltage below lower threshold
 *		BIT(1) set = battery voltage above upper threshold
 */
int pm8058_batt_alarm_status_read(void)
{
	struct pm8058_batt_alarm_device *battdev = the_battalarm;
	int status, rc;

	if (!battdev) {
		pr_err("no battery alarm device found.\n");
		return -ENXIO;
	}

	mutex_lock(&battdev->batt_mutex);
	rc = pm8058_read(battdev->pm_chip, REG_CTRL1, &battdev->reg_ctrl1, 1);

	status = ((battdev->reg_ctrl1 & CTRL1_STATUS_LOWER_MASK)
			? PM8058_BATT_ALARM_STATUS_BELOW_LOWER : 0)
		| ((battdev->reg_ctrl1 & CTRL1_STATUS_UPPER_MASK)
			? PM8058_BATT_ALARM_STATUS_ABOVE_UPPER : 0);
	mutex_unlock(&battdev->batt_mutex);

#ifdef LGE_DEBUG
	pr_info("LOW BATT ALARM = %d, UPPER BATT ALARM = %d\n", (battdev->reg_ctrl1 & CTRL1_STATUS_LOWER_MASK), (battdev->reg_ctrl1 & CTRL1_STATUS_UPPER_MASK));
#endif

	if (rc) {
		pr_err("pm8058_read failed, rc=%d\n", rc);
		return rc;
	}

	return status;
}
EXPORT_SYMBOL_GPL(pm8058_batt_alarm_status_read);

/**
 * pm8058_batt_alarm_hold_time_set - set hold time of interrupt output *
 * @hold_time:	amount of time that battery voltage must remain outside of the
 *		threshold range before the battery alarm interrupt triggers
 *
 * RETURNS: an appropriate -ERRNO error value on error, or zero for success.
 */
int pm8058_batt_alarm_hold_time_set(enum pm8058_batt_alarm_hold_time hold_time)
{
	struct pm8058_batt_alarm_device *battdev = the_battalarm;
	int rc;
	u8 reg_ctrl1 = 0;

	if (!battdev) {
		pr_err("no battery alarm device found.\n");
		return -ENXIO;
	}

	if (hold_time < CTRL1_HOLD_TIME_MIN
	    || hold_time > CTRL1_HOLD_TIME_MAX) {

		pr_err("hold time, %d, is outside of allowable range: "
			"[%d, %d]\n", hold_time, CTRL1_HOLD_TIME_MIN,
			CTRL1_HOLD_TIME_MAX);
		return -EINVAL;
	}

	reg_ctrl1 = hold_time << CTRL1_HOLD_TIME_SHIFT;

	mutex_lock(&battdev->batt_mutex);
	rc = pm8058_reg_write(battdev->pm_chip, REG_CTRL1, reg_ctrl1,
			      CTRL1_HOLD_TIME_MASK, &battdev->reg_ctrl1);
	mutex_unlock(&battdev->batt_mutex);

	return rc;
}
EXPORT_SYMBOL_GPL(pm8058_batt_alarm_hold_time_set);

/**
 * pm8058_batt_alarm_pwm_rate_set - set battery alarm update rate *
 * @use_pwm:		1 = use PWM update rate, 0 = comparators always active
 * @clock_scaler:	PWM clock scaler = 2 to 9
 * @clock_divider:	PWM clock divider = 2 to 8
 *
 * This function sets the rate at which the battery alarm module enables
 * the threshold comparators.  The rate is determined by the following equation:
 *
 * f_update = (1024 Hz) / (clock_divider * (2 ^ clock_scaler))
 *
 * Thus, the update rate can range from 0.25 Hz to 128 Hz.
 *
 * RETURNS: an appropriate -ERRNO error value on error, or zero for success.
 */
int pm8058_batt_alarm_pwm_rate_set(int use_pwm, int clock_scaler,
				   int clock_divider)
{
	struct pm8058_batt_alarm_device *battdev = the_battalarm;
	int rc;
	u8 reg_pwm_ctrl = 0, mask = 0;

	if (!battdev) {
		pr_err("no battery alarm device found.\n");
		return -ENXIO;
	}

	if (use_pwm && (clock_scaler < PWM_CTRL_PRE_INPUT_MIN
	    || clock_scaler > PWM_CTRL_PRE_INPUT_MAX)) {
		pr_err("PWM clock scaler, %d, is outside of allowable range: "
			"[%d, %d]\n", clock_scaler, PWM_CTRL_PRE_INPUT_MIN,
			PWM_CTRL_PRE_INPUT_MAX);
		return -EINVAL;
	}

	if (use_pwm && (clock_divider < PWM_CTRL_DIV_INPUT_MIN
	    || clock_divider > PWM_CTRL_DIV_INPUT_MAX)) {
		pr_err("PWM clock divider, %d, is outside of allowable range: "
			"[%d, %d]\n", clock_divider, PWM_CTRL_DIV_INPUT_MIN,
			PWM_CTRL_DIV_INPUT_MAX);
		return -EINVAL;
	}

	if (!use_pwm) {
		/* Turn off PWM control and always enable. */
		reg_pwm_ctrl = PWM_CTRL_ALARM_EN_ALWAYS;
		mask = PWM_CTRL_ALARM_EN_MASK;
	} else {
		/* Use PWM control. */
		reg_pwm_ctrl = PWM_CTRL_ALARM_EN_PWM;
		mask = PWM_CTRL_ALARM_EN_MASK | PWM_CTRL_PRE_MASK
			| PWM_CTRL_DIV_MASK;

		clock_scaler -= PWM_CTRL_PRE_INPUT_MIN - PWM_CTRL_PRE_MIN;
		clock_divider -= PWM_CTRL_DIV_INPUT_MIN - PWM_CTRL_DIV_MIN;

		reg_pwm_ctrl |= (clock_scaler << PWM_CTRL_PRE_SHIFT)
				& PWM_CTRL_PRE_MASK;
		reg_pwm_ctrl |= (clock_divider << PWM_CTRL_DIV_SHIFT)
				& PWM_CTRL_DIV_MASK;
	}

	mutex_lock(&battdev->batt_mutex);
	rc = pm8058_reg_write(battdev->pm_chip, REG_PWM_CTRL, reg_pwm_ctrl,
			      mask, &battdev->reg_pwm_ctrl);
	mutex_unlock(&battdev->batt_mutex);

	return rc;
}
EXPORT_SYMBOL_GPL(pm8058_batt_alarm_pwm_rate_set);

/*
 * Handle the BATT_ALARM interrupt:
 * Battery voltage is above or below threshold range.
 */
static irqreturn_t pm8058_batt_alarm_isr(int irq, void *data)
{
	struct pm8058_batt_alarm_device *battdev = data;
	int status;

	if (battdev) {
		status = pm8058_batt_alarm_status_read();

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
		batt_alarm_state = status;
#endif

		if (status < 0)
			pr_err("failed to read status, rc=%d\n", status);
		else
			srcu_notifier_call_chain(&battdev->irq_notifier_list,
						 status, NULL);
	}

	return IRQ_HANDLED;
}

/**
 * pm8058_batt_alarm_register_notifier - register a notifier to run when a
 *	battery voltage change interrupt fires
 * @nb:	notifier block containing callback function to register
 *
 * nb->notifier_call must point to a function of this form -
 * int (*notifier_call)(struct notifier_block *nb, unsigned long status,
 *			void *unused);
 * "status" will receive the battery alarm status; "unused" will be NULL.
 *
 * RETURNS: an appropriate -ERRNO error value on error, or zero for success.
 */
int pm8058_batt_alarm_register_notifier(struct notifier_block *nb)
{
	int rc;

	if (!the_battalarm) {
		pr_err("no battery alarm device found.\n");
		return -ENXIO;
	}

	rc = srcu_notifier_chain_register(&the_battalarm->irq_notifier_list,
					  nb);
	mutex_lock(&the_battalarm->batt_mutex);
	if (rc == 0) {
		if (the_battalarm->notifier_count == 0) {
			/* request the irq */
			rc = request_threaded_irq(the_battalarm->irq, NULL,
				pm8058_batt_alarm_isr,
				IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,
				"pm8058-batt_alarm-irq", the_battalarm);
			if (rc < 0) {
				pr_err("request_irq(%d) failed, rc=%d\n",
					the_battalarm->irq, rc);
				goto done;
			}

			rc = set_irq_wake(the_battalarm->irq, 1);
			if (rc < 0) {
				pr_err("set_irq_wake(%d,1) failed, rc=%d\n",
					the_battalarm->irq, rc);
				goto done;
			}
		}

		the_battalarm->notifier_count++;
	}
done:
	mutex_unlock(&the_battalarm->batt_mutex);
	return rc;
}
EXPORT_SYMBOL_GPL(pm8058_batt_alarm_register_notifier);

/**
 * pm8058_batt_alarm_unregister_notifier - unregister a notifier that is run
 *	when a battery voltage change interrupt fires
 * @nb:	notifier block containing callback function to unregister
 *
 * RETURNS: an appropriate -ERRNO error value on error, or zero for success.
 */
int pm8058_batt_alarm_unregister_notifier(struct notifier_block *nb)
{
	int rc;

	if (!the_battalarm) {
		pr_err("no battery alarm device found.\n");
		return -ENXIO;
	}

	rc = srcu_notifier_chain_unregister(&the_battalarm->irq_notifier_list,
					    nb);
	if (rc == 0) {
		mutex_lock(&the_battalarm->batt_mutex);

		the_battalarm->notifier_count--;

		if (the_battalarm->notifier_count == 0)
			free_irq(the_battalarm->irq, the_battalarm);

		WARN_ON(the_battalarm->notifier_count < 0);

		mutex_unlock(&the_battalarm->batt_mutex);
	}



	return rc;
}
EXPORT_SYMBOL_GPL(pm8058_batt_alarm_unregister_notifier);

static int pm8058_batt_alarm_reg_init(struct pm8058_batt_alarm_device *battdev)
{
	int rc = 0;

	/* save the current register states */
	rc = pm8058_read(battdev->pm_chip, REG_THRESHOLD,
			 &battdev->reg_threshold, 1);
	if (rc)
		goto bail;

	rc = pm8058_read(battdev->pm_chip, REG_CTRL1,
			 &battdev->reg_ctrl1, 1);
	if (rc)
		goto bail;

	rc = pm8058_read(battdev->pm_chip, REG_CTRL2,
			 &battdev->reg_ctrl2, 1);
	if (rc)
		goto bail;

	rc = pm8058_read(battdev->pm_chip, REG_PWM_CTRL,
			 &battdev->reg_pwm_ctrl, 1);
	if (rc)
		goto bail;

bail:
	if (rc)
		pr_err("pm8058_read failed; initial register states "
			"unknown, rc=%d\n", rc);
	return rc;
}

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
/* kiwone.seo@lge.com 2011-08-14, bug fix of resume charging and low battery alarm */
int pm8058_batt_alarm_config(void)
#else
static int pm8058_batt_alarm_config(void)
#endif
{
	int rc = 0;
#ifdef CONFIG_LGE_PM_BATTERY_ALARM
	int mv;

	if (!is_chg_plugged_in()) {
		mv = max17040_get_battery_mvolts();

		if (mv > P15_THRESHOLD_LOWER(lge_battery_info))
			threshold_mv = P15_THRESHOLD_LOWER(lge_battery_info);
		else if (mv > P03_THRESHOLD_LOWER(lge_battery_info) && mv <= P15_THRESHOLD_LOWER(lge_battery_info))
			threshold_mv = P03_THRESHOLD_LOWER(lge_battery_info);
		else if (mv > P01_THRESHOLD_LOWER(lge_battery_info) && mv <= P03_THRESHOLD_LOWER(lge_battery_info))
			threshold_mv = P01_THRESHOLD_LOWER(lge_battery_info);
		else
			threshold_mv = P00_THRESHOLD_LOWER(lge_battery_info);
		rc = pm8058_batt_alarm_threshold_set(threshold_mv,
			DEFAULT_THRESHOLD_UPPER);
	}
	else
#endif
	/* Use default values when no platform data is provided. */
#ifdef CONFIG_LGE_PM_BATTERY_ALARM
/* kiwone.seo@lge.com 2011-08-14, bug fix of resume charging and low battery alarm */
		rc = pm8058_batt_alarm_threshold_set(AUTO_CHARGING_RESUME_MV_CALC(lge_battery_info), 
			DEFAULT_THRESHOLD_UPPER_CALC(lge_battery_info));
#else
#ifdef CONFIG_LGE_CHARGER_VOLTAGE_CURRENT_SCENARIO
	rc = pm8058_batt_alarm_threshold_set(DEFAULT_THRESHOLD_LOWER_CALC(lge_battery_info), 
		DEFAULT_THRESHOLD_UPPER_CALC(lge_battery_info));
#else
	rc = pm8058_batt_alarm_threshold_set(DEFAULT_THRESHOLD_LOWER,
		DEFAULT_THRESHOLD_UPPER);
#endif
#endif
	if (rc) {
		pr_err("threshold_set failed, rc=%d\n", rc);
		goto done;
	}

	rc = pm8058_batt_alarm_hold_time_set(DEFAULT_HOLD_TIME);
	if (rc) {
		pr_err("hold_time_set failed, rc=%d\n", rc);
		goto done;
	}

	rc = pm8058_batt_alarm_pwm_rate_set(DEFAULT_USE_PWM,
			DEFAULT_PWM_SCALER, DEFAULT_PWM_DIVIDER);
	if (rc) {
		pr_err("pwm_rate_set failed, rc=%d\n", rc);
		goto done;
	}

	rc = pm8058_batt_alarm_state_set(DEFAULT_LOWER_ENABLE,
			DEFAULT_UPPER_ENABLE);
	if (rc) {
		pr_err("state_set failed, rc=%d\n", rc);
		goto done;
	}

done:
	return rc;
}

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
/* kiwone.seo@lge.com 2011-08-14, bug fix of resume charging and low battery alarm */
EXPORT_SYMBOL(pm8058_batt_alarm_config);
#endif

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
#if 0 /* not used */
static int pm8058_notifier_batt_alarm(struct notifier_block *this,
		unsigned long code,
		void *data)
{
	switch(code)
	{
		case CTRL1_STATUS_UPPER_MASK:
			pr_info("UPPER ALARM\n");
			break;

		case CTRL1_STATUS_LOWER_MASK:
			batt_alarm_state = 1;
			pr_info("LOWER ALARM\n");
			break;

		default:
			break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block nb = {
	.notifier_call = pm8058_notifier_batt_alarm,
};
#endif
#endif

static int __devinit pm8058_batt_alarm_probe(struct platform_device *pdev)
{
	struct pm8058_batt_alarm_device *battdev;
	struct pm8058_chip *pm_chip;
	unsigned int irq;
	int rc;

	pm_chip = platform_get_drvdata(pdev);
	if (pm_chip == NULL) {
		pr_err("no driver data passed in.\n");
		rc = -EFAULT;
		goto exit_input;
	}

	irq = platform_get_irq(pdev, 0);
	if (!irq) {
		pr_err("no IRQ passed in.\n");
		rc = -EFAULT;
		goto exit_input;
	}

	battdev = kzalloc(sizeof *battdev, GFP_KERNEL);
	if (battdev == NULL) {
		pr_err("kzalloc() failed.\n");
		rc = -ENOMEM;
		goto exit_input;
	}

	battdev->pm_chip = pm_chip;
	platform_set_drvdata(pdev, battdev);

	srcu_init_notifier_head(&battdev->irq_notifier_list);

	battdev->irq = irq;
	battdev->notifier_count = 0;
	mutex_init(&battdev->batt_mutex);

	rc = pm8058_batt_alarm_reg_init(battdev);
	if (rc)
		goto exit_free_dev;

	the_battalarm = battdev;

	rc = pm8058_batt_alarm_config();
	if (rc)
		goto exit_free_dev;

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
#if 0 /* not used */
	pm8058_batt_alarm_register_notifier(&nb);
#endif
#endif

	pr_notice("OK\n");
	return 0;

exit_free_dev:
	mutex_destroy(&battdev->batt_mutex);
	srcu_cleanup_notifier_head(&battdev->irq_notifier_list);
	platform_set_drvdata(pdev, battdev->pm_chip);
	kfree(battdev);
exit_input:
	return rc;
}

static int __devexit pm8058_batt_alarm_remove(struct platform_device *pdev)
{
	struct pm8058_batt_alarm_device *battdev = platform_get_drvdata(pdev);

	mutex_destroy(&battdev->batt_mutex);
	srcu_cleanup_notifier_head(&battdev->irq_notifier_list);
	platform_set_drvdata(pdev, battdev->pm_chip);
	free_irq(battdev->irq, battdev);
	kfree(battdev);

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
#if 0 /* not used */
	pm8058_batt_alarm_unregister_notifier(&nb);
#endif
#endif

	the_battalarm = NULL;

	return 0;
}

#ifdef CONFIG_LGE_PM_BATTERY_ALARM
static int pm8058_batt_alarm_suspend(struct device *dev)
{
	return 0;
}

static int pm8058_batt_alarm_resume(struct device *dev)
{
	int soc;

	msm_charger_notify_event(NULL, CHG_BATT_LOW_EVENT);

	soc = max17040_get_battery_capacity_percent();
	if (soc == 15 || soc == 3 || soc == 1 || soc == 0) {
		wake_lock(&batt_alarm_wake_lock);
		pr_info("wake lock..............\n");
		wake_unlock(&batt_alarm_wake_lock);
	}
	else if (!is_chg_plugged_in()) {
		pm8058_batt_alarm_config();
	}
	else
		pm8058_batt_alarm_state_set(1, 0);

	return 0;
}

static struct dev_pm_ops pm8058_batt_alarm_pm_ops = {
	.suspend	= pm8058_batt_alarm_suspend,
	.resume		= pm8058_batt_alarm_resume,
};
#endif

static struct platform_driver pm8058_batt_alarm_driver = {
	.probe	= pm8058_batt_alarm_probe,
	.remove	= __devexit_p(pm8058_batt_alarm_remove),
	.driver	= {
		.name = "pm8058-batt-alarm",
		.owner = THIS_MODULE,
#ifdef CONFIG_LGE_PM_BATTERY_ALARM
		.pm = &pm8058_batt_alarm_pm_ops,
#endif
	},
};

static int __init pm8058_batt_alarm_init(void)
{
#ifdef CONFIG_LGE_PM_BATTERY_ALARM
	wake_lock_init(&batt_alarm_wake_lock, WAKE_LOCK_SUSPEND, "pm8058_batt_alarm");
#endif
	return platform_driver_register(&pm8058_batt_alarm_driver);
}

static void __exit pm8058_batt_alarm_exit(void)
{
#ifdef CONFIG_LGE_PM_BATTERY_ALARM
	wake_lock_destroy(&batt_alarm_wake_lock);
#endif
	platform_driver_unregister(&pm8058_batt_alarm_driver);
}

module_init(pm8058_batt_alarm_init);
module_exit(pm8058_batt_alarm_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("PMIC8058 Battery Alarm Device driver");
MODULE_VERSION("1.0");
MODULE_ALIAS("platform:pm8058-batt-alarm");
