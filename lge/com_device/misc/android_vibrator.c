/*
 * android vibrator driver (msm7x27, Motor IC)
 *
 * Copyright (C) 2009 LGE, Inc. 
 * 
 * Author: Jinkyu Choi <jinkyu@lge.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */
 
#include <linux/platform_device.h>
#include <mach/gpio.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/err.h>
#include <mach/board_lge.h>
//#include <mach/timed_output.h>
#include <../../../drivers/staging/android/timed_output.h>
#define LG_VIBRATOR_GAIN 115 // 128 -> 115 req by HW
#define CONFIG_LGE_LOCAL_WORK_VIB
#define MPCS_FEEDBACK_VIB

#ifdef CONFIG_LGE_LOCAL_WORK_VIB
static struct workqueue_struct *local_workqueue ;
#endif

struct timed_vibrator_data {
	struct timed_output_dev dev;
	struct hrtimer timer;
	spinlock_t lock;
	atomic_t vib_status;			/* on/off */

	int 		max_timeout;
	atomic_t vibe_gain;				/* default max gain */
	atomic_t vib_timems;			/* vibrator duration */	
	struct android_vibrator_platform_data *vibe_data;
	struct work_struct work_vibrator_off;
	struct work_struct work_vibrator_on; 
};

static int android_vibrator_force_set(struct timed_vibrator_data *vib, int nForce)
{
	/* Check the Force value with Max and Min force value */
	int vib_dutation_ms = 0;
//    printk(KERN_INFO "LGE: %s  nForce : %d , vib->vib_status =%d\n", __func__, nForce,atomic_read(&vib->vib_status));
#if 0    
	if (nForce > 128) nForce = 128;
	if (nForce < -128) nForce = -128;
#endif	
	/* TODO: control the gain of vibrator */
//	hrtimer_cancel(&vib->timer);
	if (nForce == 0) {
		//if (!atomic_read(&vib->vib_status)) return 0;

		vib->vibe_data->ic_enable_set(0);
		vib->vibe_data->pwm_set(0, nForce);		
		vib->vibe_data->power_set(0); /* should be checked for vibrator response time */

	    atomic_set(&vib->vib_status, false);

	} else {
		//if (atomic_read(&vib->vib_status)) return 0;
		cancel_work_sync(&vib->work_vibrator_off);
		hrtimer_cancel(&vib->timer);
		vib_dutation_ms = atomic_read(&vib->vib_timems);
#ifdef MPCS_FEEDBACK_VIB //defined(CONFIG_LGE_AUDIO) && defined(CONFIG_MACH_LGE_I_BOARD_VZW)
		if(vib_dutation_ms < 40) nForce = 40;
#endif		
		vib->vibe_data->power_set(1); /* should be checked for vibrator response time */
		vib->vibe_data->pwm_set(1, nForce);
		vib->vibe_data->ic_enable_set(1);

	    atomic_set(&vib->vib_status, true);

		hrtimer_start(&vib->timer, ktime_set(vib_dutation_ms / 1000, (vib_dutation_ms % 1000) * 1000000), HRTIMER_MODE_REL);
//		printk(KERN_ERR "LGE:%s duration = %d, status = %d\n", __func__,vib_dutation_ms, atomic_read(&vib->vib_status));
		
	}	
	return 0;
}

static void android_vibrator_on(struct work_struct *work)
{
	struct timed_vibrator_data *vib = container_of(work, struct timed_vibrator_data, work_vibrator_on);
	int gain = atomic_read(&vib->vibe_gain);
	android_vibrator_force_set(vib, gain);
}

static void android_vibrator_off(struct work_struct *work)
{
	struct timed_vibrator_data *vib = container_of(work, struct timed_vibrator_data, work_vibrator_off);
	android_vibrator_force_set(vib, 0);
}

static enum hrtimer_restart vibrator_timer_func(struct hrtimer *timer)
{
	struct timed_vibrator_data *vib = container_of(timer, struct timed_vibrator_data, timer);
	
#ifdef CONFIG_LGE_LOCAL_WORK_VIB	
	queue_work(local_workqueue,&vib->work_vibrator_off);
#else
	schedule_work(&vib->work_vibrator_off); 
#endif
	
	return HRTIMER_NORESTART;
}

static int vibrator_get_time(struct timed_output_dev *dev)
{
	struct timed_vibrator_data *vib = container_of(dev, struct timed_vibrator_data, dev);

	if (hrtimer_active(&vib->timer)) {
		ktime_t r = hrtimer_get_remaining(&vib->timer);
		return r.tv.sec * 1000 + r.tv.nsec / 1000000;
	} else
		return 0;
}

static void vibrator_enable(struct timed_output_dev *dev, int value)
{
	struct timed_vibrator_data *vib = container_of(dev, struct timed_vibrator_data, dev);
	unsigned long	flags;
#if 0	
	int gain = atomic_read(&vib->vibe_gain);
	printk(KERN_INFO "LGE:Android_Vibrator[%d] %s  gain = %d , value = %d \n",__LINE__, __func__, gain,value);	
#endif
	spin_lock_irqsave(&vib->lock, flags);
//    hrtimer_cancel(&vib->timer);	
	if (value > 0) {
//		flush_scheduled_work();
		cancel_work_sync(&vib->work_vibrator_on);
		if (value > vib->max_timeout)
			value = vib->max_timeout;
		atomic_set(&vib->vib_timems, value);
//		android_vibrator_force_set(vib, gain);

#ifdef CONFIG_LGE_LOCAL_WORK_VIB	
		queue_work(local_workqueue,&vib->work_vibrator_on);
#else
		schedule_work(&vib->work_vibrator_on); 
#endif


//		hrtimer_start(&vib->timer, ktime_set(value / 1000, (value % 1000) * 1000000), HRTIMER_MODE_REL);
	} else {
//		android_vibrator_force_set(vib, 0);
#ifdef CONFIG_LGE_LOCAL_WORK_VIB	
		queue_work(local_workqueue,&vib->work_vibrator_off);
#else
		schedule_work(&vib->work_vibrator_off); 
#endif

	}
	spin_unlock_irqrestore(&vib->lock, flags);
}

static ssize_t vibrator_amp_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct timed_output_dev *dev_ =(struct timed_output_dev *)dev_get_drvdata(dev);
	struct timed_vibrator_data *vib = container_of(dev_, struct timed_vibrator_data, dev);
    int gain = atomic_read(&(vib->vibe_gain));

    return sprintf(buf, "%d\n", gain);
}
 
static ssize_t vibrator_amp_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	struct timed_output_dev *dev_ =(struct timed_output_dev *)dev_get_drvdata(dev);
	struct timed_vibrator_data *vib = container_of(dev_, struct timed_vibrator_data, dev);
    int gain;
 
    sscanf(buf, "%d", &gain);
#if 0
	if (gain > 128 || gain < -128) {
		printk(KERN_ERR "%s invalid value: should be -128 ~ +128\n", __FUNCTION__);
		return -EINVAL;
	}
#endif
    atomic_set(&vib->vibe_gain, gain);
 
    return size;
}

static DEVICE_ATTR(amp, S_IRUGO | S_IWUSR, vibrator_amp_show, vibrator_amp_store);

struct timed_vibrator_data android_vibrator_data = {
	.dev.name = "vibrator",
	.dev.enable = vibrator_enable,
	.dev.get_time = vibrator_get_time,
	.max_timeout = 30000, /* max time for vibrator enable 30 sec. */
	.vibe_data = NULL,
};

static int android_vibrator_probe(struct platform_device *pdev)
{

	int ret = 0;
	struct timed_vibrator_data *vib;

	platform_set_drvdata(pdev, &android_vibrator_data);
	vib = (struct timed_vibrator_data *)platform_get_drvdata(pdev);

	vib->vibe_data = (struct android_vibrator_platform_data *)pdev->dev.platform_data;

	if (vib->vibe_data->vibrator_init() < 0) {
		printk(KERN_ERR "%s Android Vreg, GPIO set failed\n", __FUNCTION__);
		return -1;
	}

	atomic_set(&vib->vibe_gain, LG_VIBRATOR_GAIN);
	atomic_set(&vib->vib_status, false);

//	android_vibrator_force_set(vib, 0); /* disable vibrator just for initializing */


	INIT_WORK(&vib->work_vibrator_off, android_vibrator_off);
	INIT_WORK(&vib->work_vibrator_on, android_vibrator_on);

	hrtimer_init(&vib->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	vib->timer.function = vibrator_timer_func;
	spin_lock_init(&vib->lock);

	ret = timed_output_dev_register(&vib->dev);
	if (ret < 0) {
		timed_output_dev_unregister(&vib->dev);
		return -ENODEV;		
	}

	ret = device_create_file(vib->dev.dev, &dev_attr_amp);
	if (ret < 0) {
		timed_output_dev_unregister(&vib->dev);
		device_remove_file(vib->dev.dev, &dev_attr_amp);
		return -ENODEV;
	}
	
	printk(KERN_INFO "LGE: Android Vibrator Initialization was done\n");	

	return 0;
}

static int android_vibrator_remove(struct platform_device *pdev)
{
	struct timed_vibrator_data *vib = (struct timed_vibrator_data *)platform_get_drvdata(pdev);

//	android_vibrator_force_set(vib, 0);
	schedule_work(&vib->work_vibrator_off); 

	timed_output_dev_unregister(&vib->dev);
	
	return 0;
}

#ifdef CONFIG_PM
static int android_vibrator_suspend(struct platform_device *pdev, pm_message_t state)
{
#if 0 
	struct timed_vibrator_data *vib = (struct timed_vibrator_data *)platform_get_drvdata(pdev);

	printk(KERN_INFO "LGE: Android Vibrator Driver Suspend\n");
//	android_vibrator_force_set(vib, 0);	
	schedule_work(&vib->work_vibrator_off); 
#endif
	return 0;
}

static int android_vibrator_resume(struct platform_device *pdev)
{
#if 0
	struct timed_vibrator_data *vib = (struct timed_vibrator_data *)platform_get_drvdata(pdev);

	printk(KERN_INFO "LGE: Android Vibrator Driver Resume\n");

	if (vib->vibe_data->vibrator_init() < 0) {
		printk(KERN_ERR "%s Android Vreg, GPIO set failed\n", __FUNCTION__);
		return -1;
	}

//	android_vibrator_force_set(vib, 0);
	schedule_work(&vib->work_vibrator_off); 
#endif

	return 0;
}
#endif

static void android_vibrator_shutdown(struct platform_device *pdev)
{
	struct timed_vibrator_data *vib = (struct timed_vibrator_data *)platform_get_drvdata(pdev);

//	android_vibrator_force_set(vib, 0);
	schedule_work(&vib->work_vibrator_off);

}

static struct platform_driver android_vibrator_driver = {
	.probe = android_vibrator_probe,
	.remove = android_vibrator_remove,
	.shutdown = android_vibrator_shutdown,
#ifdef CONFIG_PM
	.suspend = android_vibrator_suspend,
	.resume = android_vibrator_resume,
#else
	.suspend = NULL,
	.resume = NULL,
#endif
	.driver = {
		.name = "android-vibrator",
	},
};

static int __init android_vibrator_init(void)
{
	printk(KERN_INFO "LGE: Android Vibrator Driver Init\n");
	
#ifdef CONFIG_LGE_LOCAL_WORK_VIB	
	local_workqueue = create_workqueue("lge_vib") ;
	
	if(!local_workqueue)
		return -ENOMEM;
#endif

	return platform_driver_register(&android_vibrator_driver);
}

static void __exit android_vibrator_exit(void)
{
	printk(KERN_INFO "LGE: Android Vibrator Driver Exit\n");

#ifdef CONFIG_LGE_LOCAL_WORK_VIB	
	if(local_workqueue)
		destroy_workqueue(local_workqueue);

	local_workqueue = NULL;
#endif

	platform_driver_unregister(&android_vibrator_driver);
} 

/* to let init lately */
/* module_init(android_vibrator_init); */
late_initcall_sync(android_vibrator_init);
module_exit(android_vibrator_exit);

MODULE_AUTHOR("LG Electronics Inc.");
MODULE_DESCRIPTION("Android Common Vibrator Driver");
MODULE_LICENSE("GPL");

