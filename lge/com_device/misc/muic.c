/* Copyright (c) 2010,  LG Electronics Inc. All rights reserved. */

#include <linux/module.h>
#include <linux/kernel.h>	// printk()
#include <linux/init.h>		// __init, __exit
#include <linux/uaccess.h>	// copy_from/to_user()
#include <linux/interrupt.h>	// request_irq()
#include <linux/irq.h>		// set_irq_type()
#include <linux/types.h>	// kernel data types
#include <asm/system.h>
// kernel/arch/arm/include/asm/gpio.h includes kernel/arch/arm/plat-omap/include/mach/gpio.h which,
// in turn, includes kernel/include/asm-generic/gpio.h.
// <mach/gpio.h> declares gpio_get|set_value(), gpio_to_irq().
// <asm-generic/gpio.h> declares struct gpio_chip, gpio_request(), gpio_free(), gpio_direction_input|output().
// The actual descriptions are in kernel/drivers/gpio/gpiolib.c and kernel/arch/arm/plat-omap/gpio.c.
#include <asm/gpio.h>
#include <linux/i2c.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/delay.h>	// usleep()
#include <linux/proc_fs.h>
#include <linux/workqueue.h>	// INIT_WORK()
#include <linux/wakelock.h>
#include <linux/i2c/twl.h>		//for akm power
#include <linux/regulator/consumer.h>	//for akm power
#include <muic.h>
#include <linux/mfd/pmic8058.h>

/* Macros assume PMIC GPIOs start at 0 */
#define PM8058_GPIO_BASE			NR_MSM_GPIOS
#define PM8058_GPIO_PM_TO_SYS(pm_gpio)		(pm_gpio + PM8058_GPIO_BASE)
#define PM8058_GPIO_SYS_TO_PM(sys_gpio)		(sys_gpio - PM8058_GPIO_BASE)
#define PM8058_MPP_BASE			(PM8058_GPIO_BASE + PM8058_GPIOS)
#define PM8058_MPP_PM_TO_SYS(pm_gpio)		(pm_gpio + PM8058_MPP_BASE)
#define PM8058_MPP_SYS_TO_PM(sys_gpio)		(sys_gpio - PM8058_MPP_BASE)
#define PM8058_IRQ_BASE				(NR_MSM_IRQS + NR_GPIO_IRQS)

//------------------------------------------------------------------------------------------------------//
/* Initialize MUIC - Default setting.
 *
 * CONTROL_1:
 * 
 *	ID_2P2	= 0. Enable to distinguish MUIC_EARMIC from MUIC_TV_OUT_LOAD and MUIC_OTG.
 *			 Enable for MUIC_EARMIC operation.
 *	ID_620	= 0. Enable only to distinguish MUIC_TV_OUT_LOAD from MUIC_OTG.
 *	ID_200	= 1.
 *	VLDO	= 0. Enable to apply 2.3V for MUIC_EARMIC operation.
 *	SEMREN	= 1.
 *	ADC_EN	= 0. Because it is automatically enabled upon any change in ID resistor.
 *	CP_EN	= 0. Enalbe for USB 2.0 (MUIC_AP_USB, MUIC_CP_USB, and MUIC_OTG).
 *			 Enable for Audio charge pump (MUIC_EARMIC, MUIC_TV_OUT_LOAD).
 * 
 * CONTROL_2: 
 *
 *	INTPOL	= 0.
 *	INT_EN	= 1.
 *	MIC_LP	= 0.
 *	CP_AUD	= 1. Disable for Audio operation (MUIC_EARMIC, MUIC_TV_OUT_LOAD).
 *	CHG_TYP = 1.
 *	USB_DET_DIS = 0. Negative enabled.
 *
 * SW_CONTROL: 
 *
 *	MIC_ON	= 0. Enable for MUIC_EARMIC and MUIC_TV_OUT_LOAD.
 *	DP	= 111 (open).
 *	DM	= 111 (open).
 */
//------------------------------------------------------------------------------------------------------//

static struct i2c_client *muic_client;
static struct work_struct muic_wq;

//store INT Register value
static u8 int_stat_val;
//store STATUS register value
static u8 status_val;
charger_type chg_type;
cable_id_type cable_type;
/*
 * Function: Read the MUIC register whose internal address is addr
 *           and save the u8 content into value.
 * Return value: Negative errno upon failure, 0 upon success.
 */
s32 ts5usba_muic_i2c_read_byte(u8 addr, u8 *value){
	*value = i2c_smbus_read_byte_data(muic_client, (u8)addr);
	if(*value < 0){
		printk(KERN_INFO "[MUIC] muic_i2c_read_byte failed.\n");
		return *value;
	}
	else{
		return 0;
	}
}

/*
 * Function: Write u8 value to the MUIC register whose internal address is addr.
 * Return value: Negative errno upon failure, 0 upon success.
 */
s32 ts5usba_muic_i2c_write_byte(u8 addr, u8 value){
	s32 ret;
	ret = i2c_smbus_write_byte_data(muic_client, (u8)addr, (u8)value);
	if(ret < 0) printk(KERN_INFO "[MUIC] muic_i2c_write_byte failed.\n");
	return ret;
}

void ts5usba_muic_udelay(u32 microsec){
	u32 microseconds;
	microseconds = microsec;
	udelay(microseconds);
}

u8 ts5usba_muic_detect_charger_type(void){

	s32 ret = 0; 

	//Read STATUS Register.
	ret = ts5usba_muic_i2c_read_byte(TS5USBA_CHIP_STATUS, &status_val);

	if(ret < 0){
		printk(KERN_INFO "[MUIC] STATUS reading failed\n");
		return ret;
	}

	//DCPORT ==1 : Dedicated Charger.
	if((status_val&TS5USBA_DC_PORT_MASK)!=0)
		return DEDICATED_CHARGER;
	//CHPORT ==1 : Charger Host.
	else if((status_val&TS5USBA_CH_PORT_MASK)!=0)
		return CHARGING_HOST;
	else 
		return INVALID_CHARGER;
}

void ts5usba_muic_set_USB_mode(void){
  ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_1_ADDR,TS5USBA_ID_2P2_MASK|
		     TS5USBA_SEMREN_MASK|TS5USBA_DP_EN_MASK);  
  ts5usba_muic_i2c_write_byte(TS5USBA_SW_CONTROL,TS5USBA_DP_DM_USB<<TS5USBA_DP_MASK_SHIFT|
		     TS5USBA_DP_DM_USB<<TS5USBA_DM_MASK_SHIFT);	
}

void ts5usba_muic_set_LT_mode(void){
  ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_1_ADDR,TS5USBA_ID_2P2_MASK|
		     TS5USBA_SEMREN_MASK|TS5USBA_DP_EN_MASK);  
  ts5usba_muic_i2c_write_byte(TS5USBA_SW_CONTROL,TS5USBA_DP_DM_USB<<TS5USBA_DP_MASK_SHIFT|
		     TS5USBA_DP_DM_USB<<TS5USBA_DM_MASK_SHIFT);		
}

void ts5usba_muic_set_TA_mode(void){
  ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_1_ADDR,TS5USBA_ID_2P2_MASK|TS5USBA_SEMREN_MASK);  
  ts5usba_muic_i2c_write_byte(TS5USBA_SW_CONTROL,TS5USBA_DP_DM_OPEN<<TS5USBA_DP_MASK_SHIFT|
		     TS5USBA_DP_DM_OPEN<<TS5USBA_DM_MASK_SHIFT);	
}

void ts5usba_muic_set_UART_mode(void){
  ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_1_ADDR,TS5USBA_ID_2P2_MASK|TS5USBA_SEMREN_MASK);  
  ts5usba_muic_i2c_write_byte(TS5USBA_SW_CONTROL,TS5USBA_DP_DM_UART<<TS5USBA_DP_MASK_SHIFT|
		     TS5USBA_DP_DM_UART<<TS5USBA_DM_MASK_SHIFT);	
}


void ts5usba_muic_detect_cable_type(u8 initRegData){
	u8 cable_adc;

	//Read ADC Value for Cable type;
	cable_adc = initRegData&TS5USBA_IDNU_MASK;

	/*
	0-ohm   : 0000
	24K-ohm : 0001
	56K-ohm : 0010   (LT)
	100K-ohm : 0011
	130K-ohm : 0100
	180K-ohm : 0101	(USB/TA)
	240K-ohm : 0110
	330K-ohm : 0111
	430K-ohm : 1000	
	620K-ohm : 1001
	910K-ohm : 1010
	*/

	printk("cable_adc : %d\n", cable_adc);
	
	switch(cable_adc){
	case TS5USBA_ID_56K_VAL : //LT
		ts5usba_muic_set_LT_mode();
		cable_type = FACTORY_USB;
		break;
	case TS5USBA_ID_180K_VAL : //USB or TA
		ts5usba_muic_set_USB_mode();
		cable_type = FACTORY_USB;
		break;

	case TS5USBA_ID_240K_VAL :   // 1A USB cable
		ts5usba_muic_set_USB_mode();
		cable_type = FACTORY_USB;
		break;
#ifndef SKW_TEST 
// kiwone.seo@lge.com, temporarily we always set usb_id as FACTORY_USB
// because, some developer doesn't have a standard USB.
// we must modify this someday.
	default:
		ts5usba_muic_set_USB_mode();
		cable_type = FACTORY_USB;
		break;
#else
	case TS5USBA_ID_24K_VAL : 
	case TS5USBA_ID_100K_VAL : 
	case TS5USBA_ID_130K_VAL : 
	case TS5USBA_ID_330K_VAL : 
	case TS5USBA_ID_430K_VAL : 
	case TS5USBA_ID_620K_VAL : 
	case TS5USBA_ID_910K_VAL : 
	case TS5USBA_ID_OPEN_VAL : 
		cable_type = USB_ONLY;
		default:
			break;
#endif		
	}
		
		
}

void ts5usba_muic_vbus_process(u8 intRegData){
#if 1 //Temporay
	
	/*check charger type.*/
	if(!(intRegData&TS5USBA_CHGDET_MASK)){
		chg_type = CHARGER_TYPE_NONE;
	}else{
		//why check chg type????
		chg_type = ts5usba_muic_detect_charger_type();
	}
	
	//why check chg type????
	//if(chg_type != INVALID_CHARGER)
		ts5usba_muic_detect_cable_type(intRegData);
#else
	/*check charger type.*/
	if(!(intRegData&TS5USBA_CHGDET_MASK)){
		chg_type = CHARGER_TYPE_NONE;
	}else{
		chg_type = ts5usba_muic_detect_charger_type();

		if(chg_type != INVALID_CHARGER)
			ts5usba_muic_detect_cable_type(intRegData);
	}
#endif	
}

void ts5usba_muic_mr_comp_process(u8 intRegData){
}

void ts5usba_muic_set_idle_process(u8 intRegData){
}

/* hyungsic.you since LGT board uses muic, remove later after making board config */
#ifndef SKW_TEST//must remove later
static s32 ts5usba_muic_initialize(void)
{
	s32 ret;

	printk(KERN_WARNING "[MUIC] muic_initialize()\n");

	//1. DP/DM Open 
	ret = ts5usba_muic_i2c_write_byte(TS5USBA_SW_CONTROL, TS5USBA_DP_DM_OPEN<<TS5USBA_DP_MASK_SHIFT|
     TS5USBA_DP_DM_OPEN<<TS5USBA_DM_MASK_SHIFT);

    if( ret < 0 ) return ret ;
    
	//2. 2.6V, 200K, SEMREN
	ret = ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_1_ADDR, TS5USBA_ID_200_MASK|TS5USBA_SEMREN_MASK);
    if( ret < 0 ) return ret ;

	//3. CHG_TYP
	ret = ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_2_ADDR, TS5USBA_CHG_TPY_MASK);
    if( ret < 0 ) return ret ;

	//4.delay 250ms
	ts5usba_muic_udelay(250000);

	//5. INT_EN, CHG_TYP
	ret = ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_2_ADDR, TS5USBA_INT_EN_MASK |TS5USBA_CHG_TPY_MASK);
    if( ret < 0 ) return ret ;
	
	return ret ;
}
#else
void ts5usba_muic_initialize(void){
	s32 ret;

	printk(KERN_WARNING "[MUIC] muic_initialize()\n");

	//1. DP/DM Open 
	ret = ts5usba_muic_i2c_write_byte(TS5USBA_SW_CONTROL, TS5USBA_DP_DM_OPEN<<TS5USBA_DP_MASK_SHIFT|
     TS5USBA_DP_DM_OPEN<<TS5USBA_DM_MASK_SHIFT);

	//2. 2.6V, 200K, SEMREN
	ret = ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_1_ADDR, TS5USBA_ID_200_MASK|TS5USBA_SEMREN_MASK);

	//3. CHG_TYP
	ret = ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_2_ADDR, TS5USBA_CHG_TPY_MASK);

	//4.delay 250ms
	ts5usba_muic_udelay(250000);

	//5. INT_EN, CHG_TYP
	ret = ts5usba_muic_i2c_write_byte(TS5USBA_CONTROL_2_ADDR, TS5USBA_INT_EN_MASK |TS5USBA_CHG_TPY_MASK);
	
	return;
}
#endif//SKW_TEST//must remove later

s32 ts5usba_device_detection(s32 upon_irq){
	s32 ret = 0;

	/* Upon an MUIC IRQ (MUIC_INT_N falls),
	 * wait 70ms before reading INT_STAT and STATUS.
	 * After the reads, MUIC_INT_N returns to high
	 * (but the INT_STAT and STATUS contents will be held).
	 *
	 * Do this only if TS5USBA33402_device_detection() was called upon IRQ. */
	if(upon_irq) ts5usba_muic_udelay(70000);

	/* Read INT_STAT */
	ret = ts5usba_muic_i2c_read_byte(TS5USBA_INT_STATUS, &int_stat_val);
	if(ret < 0){
		printk(KERN_INFO "[MUIC] INT_STAT reading failed\n");
		return ret;
	}

	if((int_stat_val&TS5USBA_VBUS_MASK)!=0)
		ts5usba_muic_vbus_process(int_stat_val);
	else if(!(int_stat_val&TS5USBA_MR_COMP_MASK))
		ts5usba_muic_mr_comp_process(int_stat_val);
	else
		ts5usba_muic_set_idle_process(int_stat_val);

	return ret;

}


static void ts5usba_muic_wq_func(struct work_struct *muic_wq){
	s32 ret = 0;
	u32 retry_no;
	printk(KERN_INFO "[MUIC] muic_wq_func()\n");
	ret = ts5usba_device_detection(UPON_IRQ);
	/* If an erronous situation occurs, try again */
	retry_no = 0;
	while(ret < 0 && retry_no < 3){
		printk(KERN_INFO "[MUIC] muic_wq_func(): TS5USBA33402_device_detection() failed %d times\n",
			retry_no);
		ret = ts5usba_device_detection(NOT_UPON_IRQ);
		retry_no ++;
	}
}

static irqreturn_t ts5usba_muic_interrupt_handler(s32 irq, void *data){
	printk(KERN_INFO "[MUIC] MUIC IRQ occurs!\n");
	schedule_work(&muic_wq);
	return IRQ_HANDLED;
}

static s32 ts5usba_muic_probe(struct i2c_client *client, const struct i2c_device_id *id){

	s32 ret = 0;
	u32 retry_no;

	s32 sys_gpio; 
	
	muic_client = client;

	printk("[INFORPC] %s\n", __func__);

//--------------------------------------
	sys_gpio = PM8058_GPIO_PM_TO_SYS(MUIC_INT_GPIO);
//--------------------------------------

	/* Initialize GPIO 15 (MUIC_INT_N).
	 * Check if other driver already occupied it.
	 */
	ret = gpio_request(sys_gpio, "MUIC IRQ GPIO");
	if(ret < 0){
		printk(KERN_INFO "[MUIC] GPIO 40 MUIC_INT_N is already occupied by other driver!\n");
		return -ENOSYS;
	}

	/* Initialize GPIO direction before use or IRQ setting */
	ret = gpio_direction_input(sys_gpio);
	if(ret < 0){
		printk(KERN_INFO "[MUIC] GPIO 40 MUIC_INT_N direction initialization failed!\n");
		return -ENOSYS;
	}

	/* Register MUIC work queue function */
	INIT_WORK(&muic_wq, ts5usba_muic_wq_func);

/* hyungsic.you since LGT board uses muic, remove later after making board config */
#ifndef SKW_TEST
	/* Initialize MUIC - Finally MUIC INT becomes enabled */
	ret = ts5usba_muic_initialize();

    if( ret < 0 ) {
		printk(KERN_INFO "[MUIC] initialization failed!\n");
        return ret ;
    }
#else
	ts5usba_muic_initialize();
#endif
	/* Set up an IRQ line and enable the involved interrupt handler.
	 * From this point, a MUIC_INT_N can invoke muic_interrupt_handler().
	 * muic_interrupt_handler merely calls schedule_work() with muic_wq_func().
	 * muic_wq_func() actually performs the accessory detection.
	 */
#if 1
	ret = request_threaded_irq(PM8058_GPIO_IRQ(PM8058_IRQ_BASE,MUIC_INT_GPIO),NULL, ts5usba_muic_interrupt_handler,
			IRQF_TRIGGER_FALLING | IRQF_DISABLED,	 "muic_irq", &client->dev);
#else
	ret = request_irq(MSM_GPIO_TO_INT(sys_gpio),
			  ts5usba_muic_interrupt_handler,
			  IRQF_TRIGGER_FALLING,
			  "muic_irq",
			  &client->dev);

	printk("error : %d\n", ret);
#endif

	if (ret < 0){
		printk(KERN_INFO "[MUIC] MUIC_INT_N IRQ line set up failed!\n");
		free_irq(gpio_to_irq(sys_gpio), &client->dev);
		return -ENOSYS;
	}
#if 0
	/* Make the interrupt on MUIC INT wake up OMAP which is in suspend mode */
	ret = enable_irq_wake(gpio_to_irq(MUIC_INT_GPIO));
	if(ret < 0){
		printk(KERN_INFO "[MUIC]MUIC_INT_N wake up source setting failed!\n");
		disable_irq_wake(gpio_to_irq(MUIC_INT_GPIO));
		return -ENOSYS;
	}
#endif
	/* Prepare a human accessible method to control MUIC */
	//yongman.kwon@lge.com : this function will be implemented later.
	//create_hub_muic_proc_file();

#if 1
	ret = ts5usba_device_detection(NOT_UPON_IRQ);

	/* If an erronous situation occurs, try again */
	retry_no = 0;
	while(ret < 0 && retry_no < 3){
		printk(KERN_INFO "[MUIC] probe(): TS5USBA33402_device_detection() failed %d times\n", retry_no);
		ret = ts5usba_device_detection(NOT_UPON_IRQ);
		retry_no ++;
	}
#endif

	printk(KERN_WARNING "[MUIC] muic_probe()done!\n");

	return ret;
}

static s32 ts5usba_muic_remove(struct i2c_client *client){
	free_irq(gpio_to_irq(MUIC_INT_GPIO), &client->dev);
	gpio_free(MUIC_INT_GPIO);

	i2c_set_clientdata(client, NULL);

	return 0;
}
static s32 ts5usba_muic_suspend(struct i2c_client *client, pm_message_t state){
	client->dev.power.power_state = state;
	return 0;
}
		
static s32 ts5usba_muic_resume(struct i2c_client *client){
	client->dev.power.power_state = PMSG_ON;
	return 0;
}

static const struct i2c_device_id ts5usba_muic_ids[] = {
	{"ts5usba_i2c_muic", 0},
	{/* end of list */},
};


static struct i2c_driver ts5usba_muic_driver = {
	.probe	 	= ts5usba_muic_probe,
	.remove	 	= ts5usba_muic_remove,
	.suspend 	= ts5usba_muic_suspend,
	.resume  	= ts5usba_muic_resume,
	.id_table	= ts5usba_muic_ids,
	.driver	 	= {
	.name       = "ts5usba_i2c_muic",
	.owner      = THIS_MODULE,
	},
};

static s32 __init ts5usba_muic_init(void){
    printk(KERN_WARNING "[MUIC] muic_init()\n");
	return i2c_add_driver(&ts5usba_muic_driver);
}

static void __exit ts5usba_muic_exit(void){
	i2c_del_driver(&ts5usba_muic_driver);
}

module_init(ts5usba_muic_init);
module_exit(ts5usba_muic_exit);

MODULE_AUTHOR("LG Electronics");
MODULE_DESCRIPTION("TS5USBA MUIC Driver");
MODULE_LICENSE("GPL");

