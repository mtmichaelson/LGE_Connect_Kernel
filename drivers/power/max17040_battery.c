/*
 *  max17040_battery.c
 *  fuel-gauge systems for lithium-ion (Li+) batteries
 *
 *  Copyright (C) 2009 Samsung Electronics
 *  Minkyu Kang <mk7.kang@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/power_supply.h>
#include <linux/max17040_battery.h>
#include <linux/slab.h>

#define MAX17040_VCELL_MSB	0x02
#define MAX17040_VCELL_LSB	0x03
#define MAX17040_SOC_MSB	0x04
#define MAX17040_SOC_LSB	0x05
#define MAX17040_MODE_MSB	0x06
#define MAX17040_MODE_LSB	0x07
#define MAX17040_VER_MSB	0x08
#define MAX17040_VER_LSB	0x09
#define MAX17040_RCOMP_MSB	0x0C
#define MAX17040_RCOMP_LSB	0x0D
#ifdef CONFIG_LGE_FUEL_GAUGE
#define MAX17040_OCV_MSB	0x0E
#define MAX17040_OCV_LSB	0x0F
#endif
#define MAX17040_CMD_MSB	0xFE
#define MAX17040_CMD_LSB	0xFF

#define MAX17040_DELAY		1000
#define MAX17040_BATTERY_FULL	95

#define LGE_DEBUG	1
#ifdef CONFIG_LGE_FUEL_GAUGE
static struct i2c_client *max17040_i2c_client;
static struct workqueue_struct *local_workqueue;
#endif

struct max17040_chip {
	struct i2c_client		*client;
	struct delayed_work		work;
	struct power_supply		battery;
	struct max17040_platform_data	*pdata;

	/* State Of Connect */
	int online;
	/* battery voltage */
	int vcell;
	/* battery capacity */
	int soc;
	/* State Of Charge */
	int status;
};

static int max17040_get_property(struct power_supply *psy,
			    enum power_supply_property psp,
			    union power_supply_propval *val)
{
	struct max17040_chip *chip = container_of(psy,
				struct max17040_chip, battery);

	switch (psp) {
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = chip->status;
		break;
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = chip->online;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		val->intval = chip->vcell;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		val->intval = chip->soc;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

#ifdef CONFIG_LGE_FUEL_GAUGE
static int max17040_write_data(struct i2c_client *client, int reg, const u8 *values, int length)
{
		int ret;

		ret = i2c_smbus_write_i2c_block_data(client, reg, length, values);

		if (ret < 0)
				dev_err(&client->dev, "%s: err %d\n", __func__, ret);

		return ret;
}

static int max17040_read_data(struct i2c_client *client, int reg, u8 *values, int length)
{
		int ret;

		ret = i2c_smbus_read_i2c_block_data(client, reg, length, values);

		if (ret < 0)
				dev_err(&client->dev, "%s: err %d\n", __func__, ret);

		return ret;
}
#else
static int max17040_write_reg(struct i2c_client *client, int reg, u8 value)
{
	int ret;

	ret = i2c_smbus_write_byte_data(client, reg, value);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}

static int max17040_read_reg(struct i2c_client *client, int reg)
{
	int ret;

	ret = i2c_smbus_read_byte_data(client, reg);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}
#endif

#ifndef CONFIG_LGE_FUEL_GAUGE
static void max17040_reset(struct i2c_client *client)
{
	max17040_write_reg(client, MAX17040_CMD_MSB, 0x54);
	max17040_write_reg(client, MAX17040_CMD_LSB, 0x00);
}
#endif

void max17040_quick_start(void)
{
	u8 buf[5];
	buf[0] = 0x40; buf[1] = 0x00;
	max17040_write_data(max17040_i2c_client, MAX17040_MODE_MSB, &buf[0], 2);
}
EXPORT_SYMBOL(max17040_quick_start);


#ifdef CONFIG_LGE_FUEL_GAUGE
int max17040_get_mvolts(void)
{
	u8 buf[5];
	int vbatt_mv;

	max17040_read_data(max17040_i2c_client, MAX17040_VCELL_MSB, &buf[0], 2);
	vbatt_mv = (buf[0] << 4) + (buf[1] >> 4);

	vbatt_mv = (vbatt_mv * 125) / 100;
#ifdef LGE_DEBUG
	pr_info("max17040_get_mvolts: Battery voltage is %d\n", vbatt_mv);
#endif

	return vbatt_mv;
}

int max17040_get_capacity_percent(void)
{
	u8 buf[5];
	long batt_soc = 50;
	max17040_read_data(max17040_i2c_client, MAX17040_SOC_MSB, &buf[0], 2);
	
	batt_soc = buf[0];
	batt_soc = ((((buf[0]*256)+buf[1]) * 3906) / MAX17040_BATTERY_FULL) / 10000; 
#if 0
	batt_soc = (batt_soc * 100)/MAX17040_BATTERY_FULL;

	if(batt_soc > 74)
	{
		batt_soc= batt_soc + 1;
	}
#endif
	if (batt_soc >= 100)
	{
		batt_soc = 100;
	}
	else if (batt_soc < 0)
	{
		batt_soc = 0;
	}
#ifdef LGE_DEBUG
	pr_info("max17040_get_capacity_percent: Battery SOC is %d\n", (int)batt_soc);
#endif
	return (int)batt_soc;
}

void max17040_update_rcomp(int temp)
{
	u8 startingRcomp = 0xB8;	//MS840
	int tempCoHot = 110;	//1.1
	int tempCoCold = 500;	//5
	int newRcomp = 0;
	u8 buf[5];

	max17040_read_data(max17040_i2c_client, MAX17040_RCOMP_MSB, &buf[2], 2);
	if (temp > 20)
		newRcomp = startingRcomp - (int)((temp - 20)*tempCoHot/100);
	else if (temp < 20)
		newRcomp = startingRcomp - (int)((temp - 20)*tempCoCold/100);
	else
		newRcomp = startingRcomp;

	if (newRcomp > 0xFF)
		buf[0] = 0xFF;
	else if (newRcomp < 0)
		buf[0] = 0;
	else
		buf[0] = newRcomp;

	if (buf[0] != buf[2] && buf[0] != startingRcomp) {
		buf[1] = 0x00;
		max17040_write_data(max17040_i2c_client, MAX17040_RCOMP_MSB, &buf[0], 2);
#ifdef LGE_DEBUG
		pr_info("RCOMP: new rcomp is %02X(%02X)\n", buf[0], buf[2]);
#endif
	}
}
EXPORT_SYMBOL(max17040_update_rcomp);

#ifdef CONFIG_LGE_AT_COMMAND_ABOUT_POWER
u8 at_cmd_buf[5] = {0xff,0xff,0xff,0xff,0xff};
void max17040_set_battery_atcmd(int flag, int value)
{
	u8 buf[5];

	if (flag == 0) {
		buf[0] = 0x40; buf[1] = 0x00;
		max17040_write_data(max17040_i2c_client, MAX17040_MODE_MSB, &buf[0], 2);
	}
	else if (flag == 1) {
		at_cmd_buf[0] = 1;
		at_cmd_buf[1] = value;
	}
	else if (flag == 2) {
		at_cmd_buf[0] = 0;
	}
}
EXPORT_SYMBOL(max17040_set_battery_atcmd);
#endif
int max17040_get_battery_mvolts(void)
{
	return max17040_get_mvolts();
}
EXPORT_SYMBOL(max17040_get_battery_mvolts);

int max17040_get_battery_capacity_percent(void)
{
#ifdef CONFIG_LGE_AT_COMMAND_ABOUT_POWER  
	if (at_cmd_buf[0] == 1) 
		return at_cmd_buf[1];
#endif
	return max17040_get_capacity_percent();
}
EXPORT_SYMBOL(max17040_get_battery_capacity_percent);
#endif

static void max17040_get_vcell(struct i2c_client *client)
{
	struct max17040_chip *chip = i2c_get_clientdata(client);
#ifdef CONFIG_LGE_FUEL_GAUGE
	u8 buf[5];

	max17040_read_data(client, MAX17040_VCELL_MSB, &buf[0], 2);

	chip->vcell = (buf[0] << 4) + (buf[1] >> 4);
#else
	u8 msb;
	u8 lsb;

	msb = max17040_read_reg(client, MAX17040_VCELL_MSB);
	lsb = max17040_read_reg(client, MAX17040_VCELL_LSB);

	chip->vcell = (msb << 4) + (lsb >> 4);
#endif
}

static void max17040_get_soc(struct i2c_client *client)
{
	struct max17040_chip *chip = i2c_get_clientdata(client);
#ifdef CONFIG_LGE_FUEL_GAUGE
	u8 buf[5];
	long soc;

	max17040_read_data(client, MAX17040_SOC_MSB, &buf[0], 2);

	soc = buf[0];
	chip->soc = (int)soc;
#else
	u8 msb;
	u8 lsb;
	
	msb = max17040_read_reg(client, MAX17040_SOC_MSB);
	lsb = max17040_read_reg(client, MAX17040_SOC_LSB);

	chip->soc = msb;
#endif
}

static void max17040_get_version(struct i2c_client *client)
{
#ifdef CONFIG_LGE_FUEL_GAUGE
	u8 buf[5];

	max17040_read_data(client, MAX17040_VER_MSB, &buf[0], 2);

	dev_info(&client->dev, "MAX17040 Fuel-Gauge Ver %d%d\n", buf[0], buf[1]);
#else
	u8 msb;
	u8 lsb;

	msb = max17040_read_reg(client, MAX17040_VER_MSB);
	lsb = max17040_read_reg(client, MAX17040_VER_LSB);

	dev_info(&client->dev, "MAX17040 Fuel-Gauge Ver %d%d\n", msb, lsb);
#endif
}

static void max17040_get_online(struct i2c_client *client)
{
	struct max17040_chip *chip = i2c_get_clientdata(client);

	if (chip->pdata->battery_online)
		chip->online = chip->pdata->battery_online();
	else
		chip->online = 1;
}

static void max17040_get_status(struct i2c_client *client)
{
	struct max17040_chip *chip = i2c_get_clientdata(client);

	if (!chip->pdata->charger_online || !chip->pdata->charger_enable) {
		chip->status = POWER_SUPPLY_STATUS_UNKNOWN;
		return;
	}

	if (chip->pdata->charger_online()) {
		if (chip->pdata->charger_enable())
			chip->status = POWER_SUPPLY_STATUS_CHARGING;
		else
			chip->status = POWER_SUPPLY_STATUS_NOT_CHARGING;
	} else {
		chip->status = POWER_SUPPLY_STATUS_DISCHARGING;
	}

	if (chip->soc > MAX17040_BATTERY_FULL)
		chip->status = POWER_SUPPLY_STATUS_FULL;
}

static void max17040_work(struct work_struct *work)
{
	struct max17040_chip *chip;

	chip = container_of(work, struct max17040_chip, work.work);

	max17040_get_vcell(chip->client);
	max17040_get_soc(chip->client);
	max17040_get_online(chip->client);
	max17040_get_status(chip->client);

	//schedule_delayed_work(&chip->work, MAX17040_DELAY);
	queue_delayed_work(local_workqueue, &chip->work, MAX17040_DELAY);
}

static enum power_supply_property max17040_battery_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CAPACITY,
};


static int __devinit max17040_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct max17040_chip *chip;
	int ret;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE))
		return -EIO;

#ifdef CONFIG_LGE_FUEL_GAUGE
	max17040_i2c_client = client;
#endif

	chip = kzalloc(sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	chip->client = client;
	chip->pdata = client->dev.platform_data;

	i2c_set_clientdata(client, chip);

#ifdef CONFIG_LGE_FUEL_GAUGE
	/* kiwone.seo@lge.com 2011.01.06*/
	/* name is chaged to remove confict chip name which is same in msm_charger.c and prevent from operating fuel gauge */
	chip->battery.name		= "battery_fuel_gauge";
#else
	chip->battery.name		= "battery";
#endif
	chip->battery.type		= POWER_SUPPLY_TYPE_BATTERY;
	chip->battery.get_property	= max17040_get_property;
	chip->battery.properties	= max17040_battery_props;
	chip->battery.num_properties	= ARRAY_SIZE(max17040_battery_props);

	ret = power_supply_register(&client->dev, &chip->battery);
	if (ret) {
		dev_err(&client->dev, "failed: power supply register\n");
		kfree(chip);
		return ret;
	}

	max17040_get_version(client);

	INIT_DELAYED_WORK_DEFERRABLE(&chip->work, max17040_work);
	//schedule_delayed_work(&chip->work, MAX17040_DELAY);
	queue_delayed_work(local_workqueue, &chip->work, MAX17040_DELAY);

	return 0;
}

static int __devexit max17040_remove(struct i2c_client *client)
{
	struct max17040_chip *chip = i2c_get_clientdata(client);

	power_supply_unregister(&chip->battery);
	cancel_delayed_work(&chip->work);
	kfree(chip);
	return 0;
}

#ifdef CONFIG_PM

static int max17040_suspend(struct i2c_client *client,
		pm_message_t state)
{
	struct max17040_chip *chip = i2c_get_clientdata(client);

	cancel_delayed_work(&chip->work);
	return 0;
}

static int max17040_resume(struct i2c_client *client)
{
	struct max17040_chip *chip = i2c_get_clientdata(client);

	//schedule_delayed_work(&chip->work, MAX17040_DELAY);
	queue_delayed_work(local_workqueue, &chip->work, MAX17040_DELAY);
	return 0;
}

#else

#define max17040_suspend NULL
#define max17040_resume NULL

#endif /* CONFIG_PM */

static const struct i2c_device_id max17040_id[] = {
	{ "max17040", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, max17040_id);

static struct i2c_driver max17040_i2c_driver = {
	.driver	= {
		.name	= "max17040",
	},
	.probe		= max17040_probe,
	.remove		= __devexit_p(max17040_remove),
	.suspend	= max17040_suspend,
	.resume		= max17040_resume,
	.id_table	= max17040_id,
};

static int __init max17040_init(void)
{

	local_workqueue = create_workqueue("max17040 fuel gauge");
	
	if (!local_workqueue)
	return -ENOMEM;

	return i2c_add_driver(&max17040_i2c_driver);
}
module_init(max17040_init);

static void __exit max17040_exit(void)
{
	if (local_workqueue)
		destroy_workqueue(local_workqueue);
	
	local_workqueue = NULL;	

	i2c_del_driver(&max17040_i2c_driver);
}
module_exit(max17040_exit);

MODULE_AUTHOR("Minkyu Kang <mk7.kang@samsung.com>");
MODULE_DESCRIPTION("MAX17040 Fuel Gauge");
MODULE_LICENSE("GPL");
