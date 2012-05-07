/* 
 *  TI BQ24160 Charger Driver
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */
#define DEBUG
#include <linux/i2c.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/bq24160-charger.h>
#include <linux/power_supply.h>
#ifdef CONFIG_LGE_WIRELESS_CHARGER_BQ24160
#include <mach/gpio.h>
#include <linux/msm-charger.h>
#endif
#ifdef CONFIG_HAS_WAKELOCK
#include <linux/wakelock.h>
#endif

#define BQ24160_CABLE_PWRON_INT
#undef BQ24160_HZMODE_CTRL
#define BQ24160_WORKAROUND_CHG_DONE

// define register map
#define BQ24160_REG_STAT_CTRL 		0x00		/* Status / Control Register (read/write) */

#define BQ24160_WDOG_TMR_MASK		0x80
#define BQ24160_WDOG_TMR_SHFT		7
#define BQ24160_STAT_MASK			0x70
#define BQ24160_STAT_SHFT			4
#define BQ24160_SUPPLY_SEL_MASK		0x08
#define BQ24160_SUPPLY_SEL_SHFT		3
#define BQ24160_FAULT_MASK			0x07
#define BQ24160_FAULT_SHFT			0

#define BQ24160_REG_BATTNPS_STAT	0x01		/* Battery / Supply Status Register (read/write) */

#define BQ24160_INSTAT_MASK			0xC0
#define BQ24160_INSTAT_SHFT			6
#define BQ24160_USBSTAT_MASK		0x30
#define BQ24160_USBSTAT_SHFT		4
#define BQ24160_OTGLOCK_MASK		0x08
#define BQ24160_OTGLOCK_SHFT		3
#define BQ24160_BATTSTAT_MASK		0x06
#define BQ24160_BATTSTAT_SHFT		1

#define BQ24160_REG_CTRL			0x02		/* Control Register (read/write) */

#define BQ24160_RESET_MASK			0x80
#define BQ24160_RESET_SHFT			7
#define BQ24160_IUSB_LMT_MASK		0x70
#define BQ24160_IUSB_LMT_SHFT		4
#define BQ24160_ENSTAT_MASK			0x08
#define BQ24160_ENSTAT_SHFT			3
#define BQ24160_TE_MASK				0x04
#define BQ24160_TE_SHFT				2
#define BQ24160_CE_MASK				0x02
#define BQ24160_CE_SHFT				1
#define BQ24160_HZMODE_MASK			0x01
#define BQ24160_HZMODE_SHFT			0

#define BQ24160_REG_CTRL_BATVOLT	0x03		/* Control / Battery Voltage Register (read/write) */

#define BQ24160_VBATTREG_MASK		0xFC
#define BQ24160_VBATTREG_SHFT		2
#define BQ24160_INLMT_IN_MASK		0x02
#define BQ24160_INLMT_IN_SHFT		1
#define BQ24160_DPDM_EN_MASK		0x01
#define BQ24160_DPDM_EN_SHFT		0

#define BQ24160_REG_VEND_PART_REV	0x04		/* Vendor / Part / Revision (read only) */

#define BQ24160_VENDOR_MASK			0xE0
#define BQ24160_VENDOR_SHFT			5
#define BQ24160_PN_MASK				0x18
#define BQ24160_PN_SHFT				3
#define BQ24160_REV_MASK			0x07
#define BQ24160_REV_SHFT			0

#define BQ24160_REG_BATTTERM_FCHGCRNT	0x05	/* Battery Termination / Fast Charge Current (read/write) */

#define BQ24160_ICHGCRNT_MASK		0xF8
#define BQ24160_ICHGCRNT_SHFT		3
#define BQ24160_ITERMCRNT_MASK		0x07
#define BQ24160_ITERMCRNT_SHFT		0

#define BQ24160_REG_VINDPM_STAT	0x06			/* Vin-dpm Voltage / DPPM Status */

#define BQ24160_MINSYS_STAT_MASK	0x80
#define BQ24160_MINSYS_STAT_SHFT	7
#define BQ24160_DPM_STAT_MASK		0x40
#define BQ24160_DPM_STAT_SHFT		6
#define BQ24160_USB_INDPM_MASK		0x38
#define BQ24160_USB_INDPM_SHFT		3
#define BQ24160_IN_INDPM_MASK		0x07
#define BQ24160_IN_INDPM_SHFT		0

#define BQ24160_REG_SAFETMR_NTCMON		0x07	/* Safety Timer / NTC Monitor (read/write) */

#define BQ24160_2XTMR_EN_MASK		0x80
#define BQ24160_2XTMR_EN_SHFT		7
#define BQ24160_TMR_MASK			0x60
#define BQ24160_TMR_SHFT			5
#define BQ24160_TS_EN_MASK			0x08
#define BQ24160_TS_EN_SHFT			3
#define BQ24160_TS_FAULT_MASK		0x06
#define BQ24160_TS_FAULT_SHFT		1

#define BQ24160_STAT_NO_VALID_SRC_DETECTED		0
#define BQ24160_STAT_IN_READY 					1
#define BQ24160_STAT_USB_READY 					2
#define BQ24160_STAT_CHARGING_FROM_IN 			3
#define BQ24160_STAT_CHARGING_FROM_USB 			4
#define BQ24160_STAT_CHARGE_DONE 				5
#define BQ24160_STAT_NA 						6
#define BQ24160_STAT_FAULT						7

#define BQ24160_CHG_WORK_PERIOD	((HZ) * 10)
#define BQ24160_CHG_DONE_WORK_PERIOD	((HZ) * 3)

#define WIRELESS_CHARGE_STATUS	71
#define WIRELESS_CHARGE_COMPLETE	141
#define WIRELESS_CHARGE_INT		124

struct bq24160_chip {
	struct i2c_client *client;
	struct delayed_work charge_work;
	struct delayed_work charge_done_work;
#ifdef BQ24160_HZMODE_CTRL
	struct delayed_work hzmode_ctrl_work;
#endif	
	struct power_supply charger;
	struct bq24160_platform_data *pdata;
	int irq;
	int chg_online;
	int present;
#ifdef CONFIG_LGE_WIRELESS_CHARGER_BQ24160
	struct msm_hardware_charger	adapter_hw_chg;
#endif
#ifdef CONFIG_HAS_WAKELOCK
	struct wake_lock wl;
#endif
};

#ifdef BQ24160_WORKAROUND_CHG_DONE /* work around for charge done*/
static int chg_done_cnt = 0;
#endif

static int bq24160_write_reg(struct i2c_client *client, u8 reg, u8 value)
{
	int ret = i2c_smbus_write_byte_data(client, reg, value);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}

static int bq24160_read_reg(struct i2c_client *client, u8 reg)
{
	int ret = i2c_smbus_read_byte_data(client, reg);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}

static int bq24160_set_bits(struct i2c_client *client, u8 reg, u8 mask, u8 data)
{
	u8 value = 0;
	int ret;

	value = bq24160_read_reg(client, reg);
	if (value < 0)
		goto out;
	value &= ~mask;
	value |= data;
	ret = bq24160_write_reg(client, reg, value);
	dev_dbg(&client->dev, "%s REG_#=0x%x value = 0x%x\n", __func__, reg, value);
out:
	return ret;
}

static void bq24160_charge(struct work_struct *bq24160_work)
{
#ifdef BQ24160_WORKAROUND_CHG_DONE /* work around for charge done*/
	int val;
#endif
	u8 temp = 0;
	u8 status = 0;
	int rc;
	struct bq24160_chip *bq24160_chg;

	bq24160_chg = container_of(bq24160_work, struct bq24160_chip,
			charge_work.work);

	dev_dbg(&bq24160_chg->client->dev, "%s\n", __func__);

	/* Watchdog timer reset */
	bq24160_set_bits(bq24160_chg->client, BQ24160_REG_STAT_CTRL, BQ24160_WDOG_TMR_MASK, (1<<BQ24160_WDOG_TMR_SHFT));

	if (bq24160_chg->chg_online) 
	{
		temp = bq24160_read_reg(bq24160_chg->client, BQ24160_REG_BATTNPS_STAT);
		dev_dbg(&bq24160_chg->client->dev, "%s STATUS Register[#1]: 0x%x\n", __func__,temp);

		temp = bq24160_read_reg(bq24160_chg->client, BQ24160_REG_STAT_CTRL);
		dev_dbg(&bq24160_chg->client->dev, "%s STATUS Register[#0]: 0x%x\n", __func__,temp);

		status = temp & BQ24160_STAT_MASK;
		status = status >> BQ24160_STAT_SHFT;

		dev_dbg(&bq24160_chg->client->dev, "%s STATUS: %d\n", __func__,status);
		switch(status)
		{
			case BQ24160_STAT_NO_VALID_SRC_DETECTED:
				break;
			case BQ24160_STAT_IN_READY:
				break;
			case BQ24160_STAT_USB_READY:
				break;
			case BQ24160_STAT_CHARGING_FROM_IN:
				break;
			case BQ24160_STAT_CHARGING_FROM_USB:
				break;
			case BQ24160_STAT_CHARGE_DONE:
				dev_dbg(&bq24160_chg->client->dev, "%s Charge done by Status Register!!!\n", __func__);
				rc = gpio_direction_output(WIRELESS_CHARGE_COMPLETE, 1);
				if (rc) {
					dev_err(&bq24160_chg->client->dev,"%s: gpio_direction_output failed for %d\n",
							__func__, WIRELESS_CHARGE_COMPLETE);
				}

				msm_charger_notify_event(&bq24160_chg->adapter_hw_chg, CHG_DONE_EVENT);

				wake_lock(&bq24160_chg->wl);
				schedule_delayed_work(&bq24160_chg->charge_done_work, BQ24160_CHG_DONE_WORK_PERIOD);
				break;
			case BQ24160_STAT_NA:
				break;
			case BQ24160_STAT_FAULT:
				break;
		}

#ifdef BQ24160_WORKAROUND_CHG_DONE /* work around for charge done*/
		val = gpio_get_value_cansleep(WIRELESS_CHARGE_INT);
		if (val < 0) {
			dev_err(&bq24160_chg->client->dev,
				"%s gpio_get_value failed for %d ret=%d\n", __func__,
				WIRELESS_CHARGE_INT, val);
		}
		dev_dbg(&bq24160_chg->client->dev, "%s val=%d\n", __func__, val);
		if(val)
		{
			chg_done_cnt++;
			if(chg_done_cnt >= 5)
			{
				dev_dbg(&bq24160_chg->client->dev, "%s Charge done by Interrupt High!!!\n", __func__);
				rc = gpio_direction_output(WIRELESS_CHARGE_COMPLETE, 1);
				if (rc) {
					dev_err(&bq24160_chg->client->dev,"%s: gpio_direction_output failed for %d\n",
							__func__, WIRELESS_CHARGE_COMPLETE);
				}
				msm_charger_notify_event(&bq24160_chg->adapter_hw_chg, CHG_DONE_EVENT);
				
				wake_lock(&bq24160_chg->wl);
				schedule_delayed_work(&bq24160_chg->charge_done_work, BQ24160_CHG_DONE_WORK_PERIOD);
			}	
		}
		else
		{
			chg_done_cnt = 0;
		}
#endif
		schedule_delayed_work(&bq24160_chg->charge_work,
						BQ24160_CHG_WORK_PERIOD);
	}
	else 
	{
		// Charger remove
		cancel_delayed_work(&bq24160_chg->charge_work);
	}
}

static void bq24160_charge_done(struct work_struct *bq24160_work)
{
	int rc;
	struct bq24160_chip *bq24160_chg;

	bq24160_chg = container_of(bq24160_work, struct bq24160_chip,
			charge_done_work.work);

	dev_dbg(&bq24160_chg->client->dev, "%s\n", __func__);

	rc = gpio_direction_output(WIRELESS_CHARGE_COMPLETE, 0);
	if (rc) {
		dev_err(&bq24160_chg->client->dev,"%s: gpio_direction_output failed for %d\n",
				__func__, WIRELESS_CHARGE_COMPLETE);
	}

#ifdef BQ24160_WORKAROUND_CHG_DONE /* work around for charge done*/
	chg_done_cnt = 0;
#endif
	wake_unlock(&bq24160_chg->wl);
}

#ifdef BQ24160_HZMODE_CTRL
static void bq24160_hzmode_ctrl(struct work_struct *bq24160_work)
{
    struct bq24160_chip *bq24160_chg;

	bq24160_chg = container_of(bq24160_work, struct bq24160_chip,
			hzmode_ctrl_work.work);

	dev_dbg(&bq24160_chg->client->dev, "%s\n", __func__);

	if (bq24160_chg->chg_online) 
	{
		dev_dbg(&bq24160_chg->client->dev, "%s chg_online, hzmode off\n", __func__);
		bq24160_write_reg(bq24160_chg->client, BQ24160_REG_CTRL, 0x4C);
	}
	else
	{
		dev_dbg(&bq24160_chg->client->dev, "%s chg_offline, hzmode on\n", __func__);
		bq24160_write_reg(bq24160_chg->client, BQ24160_REG_CTRL, 0x4D);
	}
	schedule_delayed_work(&bq24160_chg->hzmode_ctrl_work, BQ24160_CHG_WORK_PERIOD);
}
#endif

static int __set_charger(struct bq24160_chip *chip, int enable)
{
    u8  reg_val= 0;

	if (enable) {
		/* enable charger */
		/* REG_#0 */
		reg_val = ( (chip->pdata->tmr_rst << BQ24160_WDOG_TMR_SHFT) |
					(chip->pdata->supply_sel << BQ24160_SUPPLY_SEL_SHFT) );
		bq24160_write_reg(chip->client, BQ24160_REG_STAT_CTRL, reg_val);
		dev_dbg(&chip->client->dev, "%s REG_#0 =0x%x\n", __func__, reg_val);

		/* REG_#2  Set current limit and enable STAT in Control register */
		reg_val = ( (chip->pdata->reset << BQ24160_RESET_SHFT) |
					(chip->pdata->iusblimit << BQ24160_IUSB_LMT_SHFT) |
					(chip->pdata->enstat << BQ24160_ENSTAT_SHFT) |
					(chip->pdata->te << BQ24160_TE_SHFT) |
					(chip->pdata->ce << BQ24160_CE_SHFT) |
					(chip->pdata->hz_mode << BQ24160_HZMODE_SHFT) );
		bq24160_write_reg(chip->client, BQ24160_REG_CTRL, reg_val);
		dev_dbg(&chip->client->dev, "%s REG_#2 =0x%x\n", __func__, reg_val);

		/* REG_#3  Set Battery Regulation Voltage */
		reg_val = ( (chip->pdata->vbatt_reg<< BQ24160_VBATTREG_SHFT) |
					(chip->pdata->inlimit_in << BQ24160_INLMT_IN_SHFT) |
					(chip->pdata->dpdm_en << BQ24160_DPDM_EN_SHFT) );
		bq24160_write_reg(chip->client, BQ24160_REG_CTRL_BATVOLT, reg_val);
		dev_dbg(&chip->client->dev, "%s REG_#3 =0x%x\n", __func__, reg_val);
		
		/* REG_#5  Set Battery Termination and Fast Chg current */
		reg_val = ( (chip->pdata->chgcrnt << BQ24160_ICHGCRNT_SHFT) |
					(chip->pdata->termcrnt << BQ24160_ITERMCRNT_SHFT) );
		bq24160_write_reg(chip->client, BQ24160_REG_BATTTERM_FCHGCRNT, reg_val);
		dev_dbg(&chip->client->dev, "%s REG_#5 =0x%x\n", __func__, reg_val);

		/* REG_#6  Set Vin-DPM voltage */
		reg_val = ( (chip->pdata->minsys_stat << BQ24160_MINSYS_STAT_SHFT) |
					(chip->pdata->dpm_stat << BQ24160_DPM_STAT_SHFT) |
					(chip->pdata->vindpm_usb << BQ24160_USB_INDPM_SHFT) |
					(chip->pdata->vindpm_in << BQ24160_IN_INDPM_SHFT) );
		bq24160_write_reg(chip->client, BQ24160_REG_VINDPM_STAT, reg_val);
		dev_dbg(&chip->client->dev, "%s REG_#6 =0x%x\n", __func__, reg_val);

		/* REG_#7  Set timer and monitor */
		reg_val = ( (chip->pdata->tmr2x_en << BQ24160_2XTMR_EN_SHFT) |
					(chip->pdata->safety_tmr << BQ24160_TMR_SHFT) |
					(chip->pdata->ts_en << BQ24160_TS_EN_SHFT) |
					(chip->pdata->ts_fault << BQ24160_TS_FAULT_SHFT) );
		bq24160_write_reg(chip->client, BQ24160_REG_SAFETMR_NTCMON, reg_val);
		dev_dbg(&chip->client->dev, "%s REG_#7 =0x%x\n", __func__, reg_val);
	} else {
		/* disable charge */
	}
	dev_dbg(&chip->client->dev, "%s %s\n", __func__, (enable) ? "Enable charger" : "Disable charger");
	return 0;
}

#ifdef BQ24160_CABLE_PWRON_INT
static irqreturn_t bq24160_valid_handler(int irq, void *data)
{
	int val;
//	int rc;
	struct bq24160_chip *chip = (struct bq24160_chip *)data;

	msleep(10);
	val = gpio_get_value_cansleep(chip->pdata->valid_n_gpio);
	if (val < 0) {
		dev_err(&chip->client->dev,
			"%s gpio_get_value failed for %d ret=%d\n", __func__,
			chip->pdata->valid_n_gpio, val);
		goto err;
	}
	dev_dbg(&chip->client->dev, "%s val=%d\n", __func__, val);

	if (val) {
		if (chip->present == 1) {
			/* Charger removed */
			msm_charger_notify_event(&chip->adapter_hw_chg, CHG_REMOVED_EVENT);
			chip->present = 0;
		}
	} else {
		if (chip->present == 0) {
			/* Charger inserted */
			msm_charger_notify_event(&chip->adapter_hw_chg, CHG_INSERTED_EVENT);
			chip->present = 1;
		}
	}
err:
	return IRQ_HANDLED;
}
#else
static irqreturn_t bq24160_charger_handler(int irq, void *data)
{
    u8 temp = 0;
	int val;
	struct bq24160_chip *chip = (struct bq24160_chip *)data;

	val = gpio_get_value_cansleep(WIRELESS_CHARGE_INT);
	dev_dbg(&chip->client->dev, "%s val=%d\n", __func__, val);

	mdelay(10);
	temp = bq24160_read_reg(chip->client, BQ24160_REG_STAT_CTRL);
	dev_dbg(&chip->client->dev, "%s STATUS Register[#0]: 0x%x\n", __func__,temp);


	return IRQ_HANDLED;
}
#endif

static int bq24160_charger_get_property(struct power_supply *psy,
                                        enum power_supply_property psp,
                                        union power_supply_propval *val)
{
	struct bq24160_chip *chip = container_of(psy, struct bq24160_chip, charger);
	int ret = 0;
	int chg_status = 0;

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = chip->chg_online;
		dev_dbg(&chip->client->dev, "%s power_supply online = %d\n", __func__,val->intval);
		break;
	case POWER_SUPPLY_PROP_STATUS:
		ret = bq24160_read_reg(chip->client, BQ24160_REG_STAT_CTRL);
		if(ret >= 0)
		{
			chg_status = ret & BQ24160_STAT_MASK;
			chg_status = chg_status >> BQ24160_STAT_SHFT;
		}
		if (chip->chg_online) {
			if (chg_status == BQ24160_STAT_CHARGE_DONE) {
				val->intval = POWER_SUPPLY_STATUS_DISCHARGING;
			}
			else if ((chg_status == BQ24160_STAT_CHARGING_FROM_IN) ||
				(chg_status == BQ24160_STAT_CHARGING_FROM_USB) ) {
				val->intval = POWER_SUPPLY_STATUS_CHARGING;
			}
			else {
				val->intval = POWER_SUPPLY_STATUS_NOT_CHARGING;
			}
		}
		else {
			val->intval = POWER_SUPPLY_STATUS_DISCHARGING;
		}
		ret = 0;
		break;	
    default:
		ret = -ENODEV;
		break;
	}
	return ret;
}

static enum power_supply_property bq24160_charger_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_STATUS,
};

static struct power_supply bq24160_charger_ps = {
	.name = "wireless-charger",
	.type = POWER_SUPPLY_TYPE_MAINS,
	.properties = bq24160_charger_props,
	.num_properties = ARRAY_SIZE(bq24160_charger_props),
	.get_property = bq24160_charger_get_property,
};

#ifdef CONFIG_LGE_WIRELESS_CHARGER_BQ24160
static int bq24160_start_charging(struct msm_hardware_charger *hw_chg,
		int chg_voltage, int chg_current)
{
	struct bq24160_chip *bq24160_chg;
	int ret = 0;

	bq24160_chg = container_of(hw_chg, struct bq24160_chip, adapter_hw_chg);
	if (bq24160_chg->chg_online)
		/* we are already charging */
		return 0;

	msleep(100);
	bq24160_chg->chg_online = 1;
	__set_charger(bq24160_chg, 1);
	
	schedule_delayed_work(&bq24160_chg->charge_work, BQ24160_CHG_WORK_PERIOD);

	power_supply_changed(&bq24160_chg->charger);

	dev_dbg(&bq24160_chg->client->dev, "%s\n", __func__);
	return ret;
}

static int bq24160_stop_charging(struct msm_hardware_charger *hw_chg)
{
	struct bq24160_chip *bq24160_chg;
	int ret = 0;

	bq24160_chg = container_of(hw_chg, struct bq24160_chip, adapter_hw_chg);
	if (!(bq24160_chg->chg_online))
		/* we arent charging */
		return 0;

	bq24160_chg->chg_online = 0;
	cancel_delayed_work(&bq24160_chg->charge_work);

	power_supply_changed(&bq24160_chg->charger);

	dev_dbg(&bq24160_chg->client->dev, "%s\n", __func__);
	return ret;
}

static int bq24160_charging_switched(struct msm_hardware_charger *hw_chg)
{
	struct bq24160_chip *bq24160_chg;

	bq24160_chg = container_of(hw_chg, struct bq24160_chip, adapter_hw_chg);
	dev_dbg(&bq24160_chg->client->dev, "%s\n", __func__);
	return 0;
}

#endif

static __devinit int bq24160_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{

	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct bq24160_chip *chip;
    int ret = 0;
//	int status;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE))
		return -EIO;

	chip = kzalloc(sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	INIT_DELAYED_WORK(&chip->charge_work, bq24160_charge);
	INIT_DELAYED_WORK(&chip->charge_done_work, bq24160_charge_done);

	chip->client = client;
	chip->pdata = client->dev.platform_data;

	i2c_set_clientdata(client, chip);

	chip->charger = bq24160_charger_ps;

	ret = power_supply_register(&client->dev, &chip->charger);
	if (ret) {
		dev_err(&client->dev, "failed: power supply register\n");
		i2c_set_clientdata(client, NULL);
		goto out;
	}

#ifdef CONFIG_LGE_WIRELESS_CHARGER_BQ24160
	/* fill hw_chg structure for registering msm_charger */
	chip->adapter_hw_chg.type = CHG_TYPE_AC;
	chip->adapter_hw_chg.rating = 1;
	chip->adapter_hw_chg.name = "bq24160-adapter";
	chip->adapter_hw_chg.start_charging = bq24160_start_charging;
	chip->adapter_hw_chg.stop_charging = bq24160_stop_charging;
	chip->adapter_hw_chg.charging_switched = bq24160_charging_switched;

#if defined(BQ24160_CABLE_PWRON_INT)
	/* setup Cable Poweron MPP */
	if (chip->pdata->chg_detection_config)
		ret = chip->pdata->chg_detection_config();
	if (ret) {
		dev_err(&client->dev, "%s valid config failed ret=%d\n",
			__func__, ret);
		goto out;
	}

	/* gpio request for MPP11 */
	ret = gpio_request(chip->pdata->valid_n_gpio, "bq24160_irq_gpio");
	if (ret) {
		dev_err(&client->dev, "%s gpio_request failed for %d ret=%d\n",
			__func__, chip->pdata->valid_n_gpio, ret);
		goto out;
	}
#else
	ret = gpio_request(WIRELESS_CHARGE_INT, "bq24160_irq_gpio");
	if (ret) {
		dev_err(&client->dev, "%s gpio_request failed for %d ret=%d\n",
			__func__, chip->pdata->valid_n_gpio, ret);
		goto out;
	}
	gpio_direction_input(WIRELESS_CHARGE_INT);
	gpio_to_irq(WIRELESS_CHARGE_INT);
#endif

#ifdef BQ24160_WORKAROUND_CHG_DONE /* work around for charge done*/
	ret = gpio_request(WIRELESS_CHARGE_INT, "bq24160_int");
	if (ret) {
		dev_err(&client->dev, "%s gpio_request failed for %d ret=%d\n",
			__func__, WIRELESS_CHARGE_INT, ret);
		goto out;
	}
	gpio_direction_input(WIRELESS_CHARGE_INT);
	gpio_to_irq(WIRELESS_CHARGE_INT);
#endif

	ret = gpio_request(WIRELESS_CHARGE_COMPLETE, "WIRELESS_CHARGE_COMPLETE");
	if(ret) {
		dev_err(&client->dev,"%s: WIRELESS_CHARGE_COMPLETE %d request failed. ret = %d\n",
				__func__, WIRELESS_CHARGE_COMPLETE, ret);
		goto out;
	}
	ret = gpio_tlmm_config(GPIO_CFG(WIRELESS_CHARGE_COMPLETE, 0, GPIO_CFG_OUTPUT,  GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);

	ret = gpio_request(WIRELESS_CHARGE_STATUS, "WIRELESS_CHARGE_STATUS");
	if(ret) {
		dev_err(&client->dev,"%s: WIRELESS_CHARGE_STATUS %d request failed. ret = %d\n",
				__func__, WIRELESS_CHARGE_STATUS, ret);
		goto out;
	}
	ret = gpio_tlmm_config(GPIO_CFG(WIRELESS_CHARGE_STATUS, 0, GPIO_CFG_OUTPUT,  GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);

	ret = gpio_direction_output(WIRELESS_CHARGE_STATUS, 0);
	if (ret) {
		pr_err("%s: gpio_direction_output failed for %d\n",
				__func__, WIRELESS_CHARGE_STATUS);
	}
	
	ret = msm_charger_register(&chip->adapter_hw_chg);
	if (ret) {
		dev_err(&client->dev,
			"%s msm_charger_register failed for ret =%d\n",
			__func__, ret);
		goto out;
	}
#endif

#if defined(BQ24160_CABLE_PWRON_INT)
	ret = request_threaded_irq(client->irq, NULL, bq24160_valid_handler,
		IRQF_TRIGGER_FALLING | IRQF_TRIGGER_RISING, client->name, chip);
#else
	ret = request_threaded_irq(client->irq, NULL, bq24160_charger_handler,
		IRQF_ONESHOT | IRQF_TRIGGER_LOW, client->name, chip);
#endif

	if (unlikely(ret < 0))
	{
		dev_err(&client->dev, "%s failed to request IRQ %d\n",__func__, ret);
		goto out;
	}
	set_irq_wake(client->irq, 1);

	ret = gpio_get_value_cansleep(chip->pdata->valid_n_gpio);
	if (ret < 0) {
		dev_err(&client->dev,
			"%s gpio_get_value failed for %d ret=%d\n", __func__,
			chip->pdata->valid_n_gpio, ret);
		/* assume absent */
		ret = 1;
	}
	dev_dbg(&client->dev, "%s MPP11 initial value = %d\n", __func__, ret);

	__set_charger(chip, 1);	//just for test

	if(!ret)
	{
		msm_charger_notify_event(&chip->adapter_hw_chg, CHG_INSERTED_EVENT);
		chip->present = 1;

		/* set to high value during wireless charging */
		ret = gpio_direction_output(WIRELESS_CHARGE_STATUS, 0);
		if (ret) {
			pr_err("%s: gpio_direction_output failed for %d\n",
					__func__, WIRELESS_CHARGE_STATUS);
		}
	}

#ifdef CONFIG_HAS_WAKELOCK
	wake_lock_init(&chip->wl, WAKE_LOCK_SUSPEND, "bq24160");
#endif

#ifdef BQ24160_HZMODE_CTRL
	INIT_DELAYED_WORK(&chip->hzmode_ctrl_work, bq24160_hzmode_ctrl);
	schedule_delayed_work(&chip->hzmode_ctrl_work, BQ24160_CHG_WORK_PERIOD);
#endif

	return 0;
out:
	kfree(chip);
	wake_lock_destroy(&chip->wl);
	return ret;
}

static __devexit int bq24160_remove(struct i2c_client *client)
{
    struct bq24160_chip *chip = i2c_get_clientdata(client);

	free_irq(client->irq, chip);
	power_supply_unregister(&bq24160_charger_ps);
	kfree(chip);
	wake_lock_destroy(&chip->wl);

	return 0;
}

static const struct i2c_device_id bq24160_id[] = {
	{ "bq24160", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, bq24160_id);

static struct i2c_driver bq24160_i2c_driver = {
	.driver = {
		.name = "bq24160",
	},
	.probe		= bq24160_probe,
	.remove		= __devexit_p(bq24160_remove),
	.id_table	= bq24160_id,
};

static int __init bq24160_init(void)
{
	return i2c_add_driver(&bq24160_i2c_driver);
}
module_init(bq24160_init);

static void __exit bq24160_exit(void)
{
	i2c_del_driver(&bq24160_i2c_driver);
}
module_exit(bq24160_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sungwook Park <sungwook.park@lge.com>");
MODULE_DESCRIPTION("Power supply driver for BQ24160");
MODULE_ALIAS("platform:bq24160-charger");
