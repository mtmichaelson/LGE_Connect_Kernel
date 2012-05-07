/* drivers/misc/hallic_catkit.c
 *
 * Copyright (C) 2010 LGE, Inc.
 * Author: Cho, EunYoung [ey.cho@lge.com]
 *
 * modified by kwangdo.yi@lge.com
 * modified by kiwone.seo@lge.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/input.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>  
#include <linux/earlysuspend.h>
#include <linux/switch.h>
#include <mach/gpio.h>
#include <linux/mfd/pmic8058.h>
#include <linux/slab.h>


/* Miscellaneous device */
#define GPIO_CAR_CRADLE_DET 17
#define GPIO_POUCH_DET 18

/* Macros assume PMIC GPIOs start at 0 */
#define PM8058_GPIO_BASE			NR_MSM_GPIOS
#define PM8058_GPIO_PM_TO_SYS(pm_gpio)		(pm_gpio + PM8058_GPIO_BASE)
#define PM8058_IRQ_BASE				(NR_MSM_IRQS + NR_GPIO_IRQS)


#define GPIO_CAR_CRADLE PM8058_GPIO_PM_TO_SYS(GPIO_CAR_CRADLE_DET-1)
#define GPIO_CAR_CRADLE_INT PM8058_GPIO_IRQ(PM8058_IRQ_BASE, GPIO_CAR_CRADLE_DET-1)

#define GPIO_POUCH PM8058_GPIO_PM_TO_SYS(GPIO_POUCH_DET-1)
#define GPIO_POUCH_INT PM8058_GPIO_IRQ(PM8058_IRQ_BASE, GPIO_POUCH_DET-1)

static void hall_ic_dock_work_func(struct work_struct *work);
static struct workqueue_struct *hallic_dock_wq;


static int suspend_flag = 0;
#ifdef CONFIG_HAS_EARLYSUSPEND
static struct early_suspend hall_ic_early_suspend;
#endif


struct hall_ic_dock_device {
	struct switch_dev sdev;
	struct work_struct work;
	int s_hall_ic_carkit_gpio;
	int s_hall_ic_desk_gpio;	
};

static struct hall_ic_dock_device *dock_dev = NULL;

#if 1
enum {
	GPIO_UNDOCKED=1,
	GPIO_CARKIT_DETECT=0,
	GPIO_POUCH_DETECT=0,
};
#else
enum {
	GPIO_CARKIT_DETECT=0,
	GPIO_DESK_DETECT=0,
	GPIO_UNDOCKED = 1,
};
#endif

enum {
	HALL_IC_EARLY_SUSPEND 	= 2,
	HALL_IC_EARLY_RESUME 	= 0,
	HALL_IC_SUSPEND 		= 1,
	HALL_IC_RESUME 			= 0,
};

enum {
	DOCK_STATE_UNDOCKED	= 0,
	DOCK_STATE_DESK = 1, /* multikit */
	DOCK_STATE_CAR = 2,  /* carkit */
	DOCK_STATE_POUCH = 3, /* pouch */
	DOCK_STATE_UNKNOWN,
};

static int reported_dock_state = DOCK_STATE_UNDOCKED;

void hall_ic_dock_report_event(int state) 
{
	if(reported_dock_state != state)
	{
		printk(KERN_INFO"%s: report_state:%d\n",__func__,state);

		switch_set_state(&dock_dev->sdev, state);
		reported_dock_state = state;
	}

	return;
}
EXPORT_SYMBOL(hall_ic_dock_report_event);

int hall_ic_get_dock_state(void)
{
	return reported_dock_state;
}

EXPORT_SYMBOL(hall_ic_get_dock_state);
#if 0
static void hall_timer(unsigned long arg)
{
	printk("### hall_timer \n");
	queue_work(hallic_dock_wq, &dock_dev->work);
	return;
}
#endif

static void hall_ic_dock_work_func(struct work_struct *work)
{
//	struct hall_ic_dock_device *dev = container_of(work, struct hall_ic_dock_device, work);
	int state;

	if(gpio_get_value_cansleep(GPIO_POUCH) == GPIO_POUCH_DETECT)
	{
   		printk("### pouch detect \n");
		state = DOCK_STATE_POUCH; //DOCK_STATE_DESK;
	}
	else if(gpio_get_value_cansleep(GPIO_CAR_CRADLE) ==  GPIO_CARKIT_DETECT)
	{
		printk("### carkit detect \n");
		state = DOCK_STATE_CAR;
	}
	else
	{
   		printk("### undock detect \n");	
		state = DOCK_STATE_UNDOCKED;
	}

	printk(KERN_INFO"%s:  curr:%d, \n",__func__,state);

	hall_ic_dock_report_event(state);

}

static irqreturn_t hall_ic_dock_irq_handler(int irq, void *dev_id)
{
	struct hall_ic_dock_device *dev = dev_id;

	printk("### hall_ic_dock_irq_handler \n");

	queue_work(hallic_dock_wq, &dev->work);
	return IRQ_HANDLED;
}

static ssize_t hall_ic_dock_print_name(struct switch_dev *sdev, char *buf)
{
	switch (switch_get_state(sdev)) {
		case DOCK_STATE_UNDOCKED:
			return sprintf(buf, "UNDOCKED\n");
		case DOCK_STATE_DESK:
			return sprintf(buf, "DESK\n");
		case DOCK_STATE_CAR:
			return sprintf(buf, "CARKIT\n");
		case DOCK_STATE_POUCH:
			return sprintf(buf, "POUCH\n");
	}
	return -EINVAL;
}

#ifdef CONFIG_HAS_EARLYSUSPEND
static void hall_early_suspend(struct early_suspend *h) 
{
	printk(KERN_INFO"%s: \n",__func__);
	suspend_flag = HALL_IC_EARLY_SUSPEND;

	return;
}

static void hall_late_resume(struct early_suspend *h)
{
	printk(KERN_INFO"%s: \n",__func__);	
	suspend_flag = HALL_IC_EARLY_RESUME;
	return;
}
#endif

static int hall_ic_dock_suspend(struct platform_device *pdev, pm_message_t state) 
{
	suspend_flag = HALL_IC_SUSPEND;
	return 0;
}

static int hall_ic_dock_resume(struct platform_device *pdev) 
{
	suspend_flag = HALL_IC_RESUME;
	return 0;
}

static ssize_t dock_mode_store(
		struct device *dev, struct device_attribute *attr, 
		const char *buf, size_t size)
{
	if (!strncmp(buf, "undock", size - 1)) 
		hall_ic_dock_report_event(DOCK_STATE_UNDOCKED);
	else if (!strncmp(buf, "desk", size - 1)) 
		hall_ic_dock_report_event(DOCK_STATE_DESK);
	else if (!strncmp(buf, "car", size -1))
		hall_ic_dock_report_event(DOCK_STATE_CAR);
	else if (!strncmp(buf, "pouch", size -1))
		hall_ic_dock_report_event(DOCK_STATE_POUCH);
	else
		return -EINVAL;

	return size;
}

static DEVICE_ATTR(report, S_IRUGO | S_IWUSR, NULL , dock_mode_store);

static int hall_ic_dock_probe(struct platform_device *pdev)
{
	struct hall_ic_dock_device *dev;
	int ret, err;
	int state;

	dev = kzalloc(sizeof(struct hall_ic_dock_device), GFP_KERNEL);
	dock_dev = dev;

	dev->sdev.name = "dock";
	dev->sdev.print_name = hall_ic_dock_print_name;

	ret = switch_dev_register(&dev->sdev);
	if (ret < 0)
		goto err_switch_dev_register;

	platform_set_drvdata(pdev, dev);

	INIT_WORK(&dev->work, hall_ic_dock_work_func);

	ret = gpio_request(GPIO_CAR_CRADLE, "carkit_detect");
	if(ret < 0)
		goto err_request_carkit_detect_gpio;

	ret = gpio_direction_input(GPIO_CAR_CRADLE);
	if (ret < 0)
		goto err_set_carkit_detect_gpio;
	
	ret = request_threaded_irq(GPIO_CAR_CRADLE_INT,NULL, hall_ic_dock_irq_handler,
			IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,"hall-ic-carkit", dev);

	if (ret) {
		printk("\nHALL IC CARKIT IRQ Check-fail\n pdev->client->irq %d\n",dev->s_hall_ic_carkit_gpio);
		goto err_request_carkit_detect_irq;
	}

	err = set_irq_wake(GPIO_CAR_CRADLE_INT, 1);
	if (err) {
		pr_err("hall-ic-carkit: set_irq_wake failed for gpio %d, "
				"irq %d\n", GPIO_CAR_CRADLE, GPIO_CAR_CRADLE_INT);
	}



	ret = gpio_request(GPIO_POUCH, "pouch_detect");
	if(ret < 0)
		goto err_request_carkit_detect_gpio;

	ret = gpio_direction_input(GPIO_POUCH);
	if (ret < 0)
		goto err_set_carkit_detect_gpio;

	ret = request_threaded_irq(GPIO_POUCH_INT,NULL, hall_ic_dock_irq_handler,
			IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,"hall-ic-pouch", dev);

	if (ret) {
		printk("\nHALL IC CARKIT IRQ Check-fail\n pdev->client->irq %d\n",dev->s_hall_ic_carkit_gpio);
		goto err_request_carkit_detect_irq;
	}

	err = set_irq_wake(GPIO_POUCH_INT, 1);
	if (err) {
		pr_err("hall-ic-carkit: set_irq_wake failed for gpio %d, "
				"irq %d\n", GPIO_POUCH, GPIO_POUCH_INT);
	}

#if 0
	dev->s_hall_ic_desk_gpio = gpio_to_irq(GPIO_DESK_IRQ);
	ret = request_irq(dev->s_hall_ic_desk_gpio, hall_ic_dock_irq_handler,
			IRQF_TRIGGER_RISING|IRQF_TRIGGER_FALLING,
			"hall-ic-multikit", dev); 

	if (ret) {
		printk("\nHALL IC MULTIKIT IRQ Check-fail\n pdev->client->irq %d\n",dev->s_hall_ic_desk_gpio);
		goto err_request_multikit_detect_irq;
	}

	err = set_irq_wake(dev->s_hall_ic_desk_gpio, 1);
	if (err) {
		pr_err("hall-ic-multikit: set_irq_wake failed for gpio %d, "
				"irq %d\n", GPIO_DESK_IRQ, dev->s_hall_ic_desk_gpio);
	}
#endif

	ret = device_create_file(&pdev->dev, &dev_attr_report);
	if (ret) {
		printk( "hall-ic-dock_probe: device create file Fail\n");
		device_remove_file(&pdev->dev, &dev_attr_report);
		goto err_request_irq;
	}

	
#ifdef CONFIG_HAS_EARLYSUSPEND
	hall_ic_early_suspend.suspend = hall_early_suspend;
	hall_ic_early_suspend.resume = hall_late_resume;
	hall_ic_early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN - 45;
	register_early_suspend(&hall_ic_early_suspend);
#endif

	/* check initial dock state */
	if(gpio_get_value_cansleep(GPIO_POUCH) == GPIO_POUCH_DETECT)
	{
   		printk("### pouch detect \n");
		state = DOCK_STATE_POUCH; //DOCK_STATE_DESK;
	}
	else if(gpio_get_value_cansleep(GPIO_CAR_CRADLE) ==  GPIO_CARKIT_DETECT)
	{
		printk("### carkit detect \n");
		state = DOCK_STATE_CAR;
	}
	else
	{
   		printk("### undock detect \n");	
		state = DOCK_STATE_UNDOCKED;
	}

	printk(KERN_INFO"%s:  curr:%d, \n",__func__,state);

	hall_ic_dock_report_event(state);


	printk(KERN_ERR "hall_ic_dock: hall_ic_dock_probe: Done\n");
	return 0;

err_request_irq:
	free_irq(GPIO_CAR_CRADLE_INT, 0);
#if 0	
	free_irq(dev->s_hall_ic_desk_gpio, 0);
#endif
//err_request_multikit_detect_irq:
	free_irq(GPIO_CAR_CRADLE_INT, 0);
err_request_carkit_detect_irq:
//err_set_multikit_detect_gpio:
err_set_carkit_detect_gpio:
#if 0	
	gpio_free(GPIO_DESK_IRQ);
#endif
//err_request_multikit_detect_gpio:
	gpio_free(GPIO_CAR_CRADLE);
err_request_carkit_detect_gpio:
	switch_dev_unregister(&dev->sdev);
	kfree(dev);
err_switch_dev_register:
	printk(KERN_ERR "hall_ic_dock: Failed to register driver\n");
	return ret;
}

static int hall_ic_dock_remove(struct platform_device *pdev) 
{
	struct hall_ic_dock_device *dev = dock_dev;

	// kwangdo.yi imsi del_timer_sync(&dev->timer);
	gpio_free(GPIO_CAR_CRADLE);
	free_irq(GPIO_CAR_CRADLE_INT, 0);

	gpio_free(GPIO_POUCH);
	free_irq(GPIO_POUCH_INT, 0);

	switch_dev_unregister(&dev->sdev);

	return 0;
}

static struct platform_driver hall_ic_dock_driver = {
	.probe		= hall_ic_dock_probe,
	.remove		= hall_ic_dock_remove,
	.suspend 	= hall_ic_dock_suspend,
	.resume		= hall_ic_dock_resume,
	.driver		= {
		.name		= "hall-ic-dock",
		.owner		= THIS_MODULE,
	},
};

static int __init hall_ic_dock_init(void)
{
	hallic_dock_wq = create_singlethread_workqueue("hallic_dock_wq");
	if (!hallic_dock_wq){
		return -ENOMEM;
	}

	return platform_driver_register(&hall_ic_dock_driver);
}

static void __exit hall_ic_dock_exit(void)
{
	destroy_workqueue(hallic_dock_wq);
	platform_driver_unregister(&hall_ic_dock_driver);
}

module_init(hall_ic_dock_init);
module_exit(hall_ic_dock_exit);

MODULE_LICENSE("GPL");
