/*
 * Copyright (C) 2010 NXP Semiconductors
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/i2c.h>
#include <linux/irq.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
//#include <linux/nfc_nxp_pn544pn65n.h>
#include "nfc_nxp_pn544pn65n.h"

#define MAX_BUFFER_SIZE	512
#define PN544_RESET_CMD 	0
#define PN544_DOWNLOAD_CMD	1
#define PN544_INTERRUPT_CMD	2	//seokmin added for debugging
#define PN544_READ_POLLING_CMD 3	//seokmin added for debugging

//20110421, seunghyup.ryoo@lge.com,  [START]
//#define PN544_PROTOCOL_DATAVIEW_ENABLED
//#define PN544_PROTOCOL_ANALYZE_ENABLED
//20110421, seunghyup.ryoo@lge.com,  [END]

struct pn544_dev	{
	wait_queue_head_t	read_wq;
	struct mutex		read_mutex;
	struct i2c_client	*client;
	struct miscdevice	pn544_device;
	unsigned int 		ven_gpio;
	unsigned int 		firm_gpio;
	unsigned int		irq_gpio;
	bool			irq_enabled;
	spinlock_t		irq_enabled_lock;
};

static int	stReadIntFlag = 0;	//seokmin added for debugging
static struct i2c_client *pn544_client = NULL;	//seokmin

static void pn544_disable_irq(struct pn544_dev *pn544_dev)
{
	unsigned long flags;

	spin_lock_irqsave(&pn544_dev->irq_enabled_lock, flags);
	if (pn544_dev->irq_enabled) {
		disable_irq_nosync(pn544_dev->client->irq);
		pn544_dev->irq_enabled = false;
	}
	spin_unlock_irqrestore(&pn544_dev->irq_enabled_lock, flags);
}

static irqreturn_t pn544_dev_irq_handler(int irq, void *dev_id)
{
	struct pn544_dev *pn544_dev = dev_id;

	printk("pn544_dev_irq_handler : %d\n", irq);

	pn544_disable_irq(pn544_dev);

	/* Wake up waiting readers */
	wake_up(&pn544_dev->read_wq);

	return IRQ_HANDLED;
}


//20110328, seunghyup.ryoo@lge.com,  [START]
// for Test Purpose!!
#if 0
int pn544_i2c_recv(struct i2c_client *client, char *buf, int count)
{
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg;
	int ret;

	msg.addr = client->addr;
	msg.flags = I2C_M_RD;
	msg.len = count;
	msg.buf = buf;

	ret = i2c_transfer(adap, &msg, 1);
	//printk("%s : Address = %04X\n", __func__, client->addr);

	/* If everything went ok (i.e. 1 msg transmitted), return #bytes
	   transmitted, else error code. */
	return (ret == 1) ? count : ret;
}

int pn544_i2c_send(struct i2c_client *client, const char *buf, int count)
{
	int ret;
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg;

	msg.addr = client->addr;
	msg.flags = 0;
	msg.len = count;
	msg.buf = (char *)buf;

	ret = i2c_transfer(adap, &msg, 1);
	//printk("%s : Address = %04X\n", __func__, client->addr);
	
	/* If everything went ok (i.e. 1 msg transmitted), return #bytes
	   transmitted, else error code. */
	return (ret == 1) ? count : ret;
}
#endif
//20110328, seunghyup.ryoo@lge.com,  [END]


static ssize_t pn544_dev_read(struct file *filp, char __user *buf,
		size_t count, loff_t *offset)
{
	struct pn544_dev *pn544_dev = filp->private_data;
	char tmp[MAX_BUFFER_SIZE];
	int ret;
	int irq_gpio_val = 0;

#ifdef PN544_PROTOCOL_DATAVIEW_ENABLED
	int i, pos;
	char msg[32];
#ifdef PN544_PROTOCOL_ANALYZE_ENABLED
	char llc_len = 0;
	char llc_head = 0;
	char hcp_head = 0;
	char hcpm_head = 0;
#endif //#ifdef PN544_PROTOCOL_ANALYZE_ENABLED
#endif //#ifdef PN544_PROTOCOL_DATAVIEW_ENABLED

	if (count > MAX_BUFFER_SIZE)
		count = MAX_BUFFER_SIZE;

	pr_debug("%s : reading %zu bytes.\n", __func__, count);

	mutex_lock(&pn544_dev->read_mutex);

	if(!stReadIntFlag){ 	 //seokmin added for debugging
		//pr_info("%s : seokmin test routine!\n", __func__);
		irq_gpio_val = gpio_get_value(pn544_dev->irq_gpio);
		printk("IRQ GPIO = %d\n", irq_gpio_val);
		if (irq_gpio_val == 0) {
			
			if (filp->f_flags & O_NONBLOCK) {
				printk("f_falg has O_NONBLOCK. EAGAIN!\n");
				ret = -EAGAIN;
				goto fail;
			}

			pn544_dev->irq_enabled = true;
			enable_irq(pn544_dev->client->irq);
			ret = wait_event_interruptible(pn544_dev->read_wq, gpio_get_value(pn544_dev->irq_gpio));
			pn544_disable_irq(pn544_dev);
			printk("wait_event_interruptible : %d\n", ret);			

			if (ret)
				goto fail;

		}
	}	//seokmin

	/* Read data */
//20110328, seunghyup.ryoo@lge.com,  [START]
	memset(tmp, 0x00, MAX_BUFFER_SIZE);
	ret = i2c_master_recv(pn544_dev->client, tmp, count);
//	ret = pn544_i2c_recv(pn544_dev->client, tmp, count);
//20110328, seunghyup.ryoo@lge.com,  [END]
	mutex_unlock(&pn544_dev->read_mutex);

	if (ret < 0) {
		pr_err("%s: i2c_master_recv returned %d\n", __func__, ret);
		return ret;
	}
	if (ret > count) {
		pr_err("%s: received too many bytes from i2c (%d)\n",
			__func__, ret);
		return -EIO;
	}
	if (copy_to_user(buf, tmp, ret)) {
		pr_warning("%s : failed to copy to user space\n", __func__);
		return -EFAULT;
	}

//20110421, seunghyup.ryoo@lge.com,  [START]
#ifdef PN544_PROTOCOL_DATAVIEW_ENABLED
	printk("%s : Received %d bytes successfully!\n", __func__, ret);
	pos = 0;
	memset(msg, 0x00, 32);
	for (i=0;i<ret;i++) {
		if ((i%8 == 0) && (i>0)) {
			printk("[R]%04d : %s\n", i-8, msg);
			pos = 0;
			memset(msg, 0x00, 32);
		}
		sprintf(&msg[pos], "%02X ", tmp[i]);
		pos += 3;
	}
	if (msg[0] != 0) {
		printk("[R]%04d : %s\n", ((i-1)/8)*8, msg);
	}
#endif //#ifdef PN544_PROTOCOL_DATAVIEW_ENABLED
#ifdef PN544_PROTOCOL_ANALYZE_ENABLED
	printk("=============== RECEIVED PACKET ANALYSIS ===============\n");
	if (ret == 1) {
		llc_len = tmp[0];
		llc_head = 0;
		hcp_head = 0;
		hcpm_head = 0;
	}
	else if (ret == 3) {
		llc_len = 0;
		llc_head = tmp[0];
		hcp_head = 0;
		hcpm_head = 0;

	}
	else if (ret > 3) {
		llc_len = 0;
		llc_head = tmp[0];
		hcp_head = tmp[1];
		hcpm_head = tmp[2];
	}

	// LLC Frame : Length
	if (llc_len>0 && llc_len<0x80) {
		printk("LLC Length : %d\n", llc_len);
	}
	// LLC Frame : Header
	if (llc_head != 0) {
		if (llc_head < 0xC0) {
			printk("LLC Header : I-Frame (NS = %d, NR = %d)\n", (llc_head&0x38)>>3, (llc_head&0x07));
		}
		else if (llc_head < 0x0E) {
			printk("LLC Header : S-Frame (Type = %d, NR = %d)\n", (llc_head&0x18)>>3, (llc_head&0x07));
		}
		else {
			printk("LLC Header : U-Frame (Modifier = %d)\n", (llc_head&0x1F));
		}
	}
	if (llc_head < 0x0E) {
		// HCP : Header
		if (hcp_head != 0) {
			printk("HCP Header : CB = %d, pID = %d\n", (hcp_head&0x80)>>7, (hcp_head&0x7F));
		}
		// HCP : Message Header
		if (hcpm_head !=0) {
			printk("HCPM Header : Type = %d, Ins = %d\n", (hcpm_head&0xC0)>>6, (hcpm_head&0x3F));
		}
	}
	
	printk("=============== RECEIVED PACKET ANALYSIS ===============\n");
#endif //#ifdef PN544_PROTOCOL_ANALYZE_ENABLED
//20110421, seunghyup.ryoo@lge.com,  [END]
	
	return ret;

fail:
	mutex_unlock(&pn544_dev->read_mutex);
	return ret;
}

static ssize_t pn544_dev_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *offset)
{
	struct pn544_dev  *pn544_dev;
	char tmp[MAX_BUFFER_SIZE];
	int ret;

#ifdef PN544_PROTOCOL_DATAVIEW_ENABLED
	int i, pos;
	char msg[32];
#ifdef PN544_PROTOCOL_ANALYZE_ENABLED
	char llc_len = 0;
	char llc_head = 0;
	char hcp_head = 0;
	char hcpm_head = 0;
#endif //#ifdef PN544_PROTOCOL_ANALYZE_ENABLED
#endif //#ifdef PN544_PROTOCOL_DATAVIEW_ENABLED

	pn544_dev = filp->private_data;

	if (count > MAX_BUFFER_SIZE)
		count = MAX_BUFFER_SIZE;

	memset(tmp, 0x00, MAX_BUFFER_SIZE);
	if (copy_from_user(tmp, buf, count)) {
		pr_err("%s : failed to copy from user space\n", __func__);
		return -EFAULT;
	}

	//pr_debug("%s : writing %zu bytes.\n", __func__, count);
	/* Write data */
	printk("write: pn544_write len=:%d\n", count);

	ret = i2c_master_send(pn544_dev->client, tmp, count);
	if (ret != count) {
		pr_err("%s : i2c_master_send returned %d\n", __func__, ret);
		ret = -EIO;
	}

//20110421, seunghyup.ryoo@lge.com,  [START]
#ifdef PN544_PROTOCOL_DATAVIEW_ENABLED
	else {
		printk("%s : Send %d bytes successfully!\n", __func__, ret);
		pos = 0;
		memset(msg, 0x00, 32);
		for (i=0;i<ret;i++) {
			if ((i%8 == 0) && (i>0)) {
				printk("[S]%04d : %s\n", i-8, msg);
				pos = 0;
				memset(msg, 0x00, 32);
			}
			sprintf(&msg[pos], "%02X ", tmp[i]);
			pos += 3;
		}
		if (msg[0] != 0) {
			printk("[S]%04d : %s\n", ((i-1)/8)*8, msg);
		}
	}
#endif //#ifdef PN544_PROTOCOL_DATAVIEW_ENABLED
#ifdef PN544_PROTOCOL_ANALYZE_ENABLED
	printk("=============== SEND PACKET ANALYSIS ===============\n");
	if (ret == 4) {
		llc_len = tmp[0];
		llc_head = tmp[1];
		hcp_head = 0;
		hcpm_head = 0;
	}
	else if (ret > 4) {
		llc_len = tmp[0];
		llc_head = tmp[1];
		hcp_head = tmp[2];
		hcpm_head = tmp[3];
	}

	// LLC Frame : Length
	if (llc_len>0 && llc_len<0x80) {
		printk("LLC Length : %d\n", llc_len);
	}
	// LLC Frame : Header
	if (llc_head != 0) {
		if (llc_head < 0xC0) {
			printk("LLC Header : I-Frame (NS = %d, NR = %d)\n", (llc_head&0x38)>>3, (llc_head&0x07));
		}
		else if (llc_head < 0x0E) {
			printk("LLC Header : S-Frame (Type = %d, NR = %d)\n", (llc_head&0x18)>>3, (llc_head&0x07));
		}
		else {
			printk("LLC Header : U-Frame (Modifier = %d)\n", (llc_head&0x1F));
		}
	}
	if (llc_head < 0x0E) {
		// HCP : Header
		if (hcp_head != 0) {
			printk("HCP Header : CB = %d, pID = %d\n", (hcp_head&0x80)>>7, (hcp_head&0x7F));
		}
		// HCP : Message Header
		if (hcpm_head !=0) {
			printk("HCPM Header : Type = %d, Ins = %d\n", (hcpm_head&0xC0)>>6, (hcpm_head&0x3F));
		}
	}
	printk("=============== SEND PACKET ANALYSIS ===============\n");
#endif //#ifdef PN544_PROTOCOL_ANALYZE_ENABLED
//20110421, seunghyup.ryoo@lge.com,  [END]

	return ret;
}

static int pn544_dev_open(struct inode *inode, struct file *filp)
{
/*	seokmin
	struct pn544_dev *pn544_dev = container_of(filp->private_data,
						struct pn544_dev,
						pn544_device);

	filp->private_data = pn544_dev;
*/
	filp->private_data = i2c_get_clientdata(pn544_client);
	pr_debug("%s : %d,%d\n", __func__, imajor(inode), iminor(inode));

	return 0;
}

static int pn544_dev_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	struct pn544_dev *pn544_dev = filp->private_data;
	int ret;

	pr_info("%s\n",__func__);
	switch (cmd) {
	case PN544_SET_PWR:
		if (arg == 2) {
			/* power on with firmware download (requires hw reset)
			 */
			pr_info("%s power on with firmware\n", __func__);
			// for HDK_8x60 Board
			gpio_tlmm_config(GPIO_CFG(pn544_dev->irq_gpio, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			gpio_tlmm_config(GPIO_CFG(pn544_dev->ven_gpio, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			gpio_tlmm_config(GPIO_CFG(pn544_dev->firm_gpio, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			msleep(10);
			// End : for HDK_8x60 Board
			gpio_set_value(pn544_dev->ven_gpio, 1);
			gpio_set_value(pn544_dev->firm_gpio, 1);
			msleep(10);
			gpio_set_value(pn544_dev->ven_gpio, 0);
			msleep(10);
			gpio_set_value(pn544_dev->ven_gpio, 1);
			msleep(10);
		} else if (arg == 1) {
			/* power on */
			pr_info("%s power on\n", __func__);
			// for HDK_8x60 Board
			gpio_tlmm_config(GPIO_CFG(pn544_dev->irq_gpio, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			gpio_tlmm_config(GPIO_CFG(pn544_dev->ven_gpio, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			gpio_tlmm_config(GPIO_CFG(pn544_dev->firm_gpio, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			msleep(10);
			// End : for HDK_8x60 Board
			gpio_set_value(pn544_dev->firm_gpio, 0);
			gpio_set_value(pn544_dev->ven_gpio, 1);
			msleep(10);
			ret = gpio_get_value(pn544_dev->ven_gpio);
			printk("ioctl: pn544_set_pwr %d\n", ret);
		} else  if (arg == 0) {
			/* power off */
			pr_info("%s power off\n", __func__);
			gpio_set_value(pn544_dev->firm_gpio, 0);
			gpio_set_value(pn544_dev->ven_gpio, 0);
			msleep(10);
			ret = gpio_get_value(pn544_dev->ven_gpio);
			printk("ioctl: pn544_set_pwr %d\n", ret);
			// for HDK_8x60 Board
			ret = gpio_get_value(43);
			// End : for HDK_8x60 Board
			printk("ioctl: pn544_set_pwr off (SDA) : %d\n", ret);
			
			//gpio_tlmm_config(GPIO_CFG(130, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			//gpio_set_value(130, 0);
			//ret = gpio_get_value(130);
			//printk("ioctl : gpio_130 : %d\n", ret);
			//gpio_set_value(130, 1);
			//ret = gpio_get_value(130);
			//printk("ioctl : gpio_130 : %d\n", ret);

			// for HDK_8x60 Board
			gpio_tlmm_config(GPIO_CFG(pn544_dev->irq_gpio, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			gpio_tlmm_config(GPIO_CFG(pn544_dev->ven_gpio, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			gpio_tlmm_config(GPIO_CFG(pn544_dev->firm_gpio, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), GPIO_CFG_ENABLE);
			msleep(10);
			// End : for HDK_8x60 Board
		} else {
			pr_err("%s bad arg %ld\n", __func__, arg);
			return -EINVAL;
		}
		break;
//seokmin added for debugging
	case PN544_INTERRUPT_CMD:
		{
//			pn544_disable_irq = level;
			printk("ioctl: pn544_interrupt enable level:%ld\n", arg);
			break;
		}
	case PN544_READ_POLLING_CMD:
		{
			stReadIntFlag = arg;
			printk("ioctl: pn544_polling flag set:%ld\n", arg);
			break;
		}
	default:
		pr_err("%s bad ioctl %d\n", __func__, cmd);
		return -EINVAL;
	}

	return 0;
}

static const struct file_operations pn544_dev_fops = {
	.owner	= THIS_MODULE,
	.llseek	= no_llseek,
	.read	= pn544_dev_read,
	.write	= pn544_dev_write,
	.open	= pn544_dev_open,
	.ioctl  = pn544_dev_ioctl,
};

static int pn544_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	int ret;
	struct nxp_pn544pn65n_platform_data *platform_data;
	struct pn544_dev *pn544_dev = NULL;

	printk("================ pn544_probe() start ================\n");

	pn544_client = client;//seokmin 
	
	platform_data = client->dev.platform_data;

	if (platform_data == NULL) {
		pr_err("%s : nfc probe fail\n", __func__);
		return  -ENODEV;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		pr_err("%s : need I2C_FUNC_I2C\n", __func__);
		return  -ENODEV;
	}

	ret = gpio_request(platform_data->irq_gpio, "nfc_int");
	if (ret) {
		printk("pn544_probe() : nfc_int request failed!\n");
		return  -ENODEV;
	}
	ret = gpio_request(platform_data->ven_gpio, "nfc_ven");
	if (ret) {
		printk("pn544_probe() : nfc_ven request failed!\n");
		goto err_ven;
	}
	ret = gpio_request(platform_data->firm_gpio, "nfc_firm");
	if (ret) {
		printk("pn544_probe() : nfc_firm request failed!\n");
		goto err_firm;
	}

	pn544_dev = kzalloc(sizeof(*pn544_dev), GFP_KERNEL);
	if (pn544_dev == NULL) {
		dev_err(&client->dev,
				"failed to allocate memory for module data\n");
		ret = -ENOMEM;
		goto err_exit;
	}

	pn544_dev->irq_gpio = platform_data->irq_gpio;
	pn544_dev->ven_gpio  = platform_data->ven_gpio;
	pn544_dev->firm_gpio  = platform_data->firm_gpio;
	pn544_dev->client   = client;
	pr_info("IRQ : %d\nVEN : %d\nFIRM : %d\n", pn544_dev->irq_gpio, pn544_dev->ven_gpio, pn544_dev->firm_gpio);

	/* init mutex and queues */
	init_waitqueue_head(&pn544_dev->read_wq);
	mutex_init(&pn544_dev->read_mutex);
	spin_lock_init(&pn544_dev->irq_enabled_lock);

	pn544_dev->pn544_device.minor = MISC_DYNAMIC_MINOR;
	pn544_dev->pn544_device.name = "pn544";
	pn544_dev->pn544_device.fops = &pn544_dev_fops;

	ret = misc_register(&pn544_dev->pn544_device);
	if (ret) {
		pr_err("%s : misc_register failed\n", __FILE__);
		goto err_misc_register;
	}

	/* request irq.  the irq is set whenever the chip has data available
	 * for reading.  it is cleared when all data has been read.
	 */
	pr_info("%s : requesting IRQ %d\n", __func__, client->irq);
	pn544_dev->irq_enabled = true;
	ret = request_irq(client->irq, pn544_dev_irq_handler,
			  IRQF_TRIGGER_HIGH, client->name, pn544_dev);
	if (ret) {
		dev_err(&client->dev, "request_irq failed\n");
		goto err_request_irq_failed;
	}
	pn544_disable_irq(pn544_dev);
	i2c_set_clientdata(client, pn544_dev);	

	printk("================ pn544_probe() end ================\n");
	
	return 0;

err_request_irq_failed:
	misc_deregister(&pn544_dev->pn544_device);

err_misc_register:
	mutex_destroy(&pn544_dev->read_mutex);
	kfree(pn544_dev);

err_exit:
	gpio_free(pn544_dev->irq_gpio);

err_firm:
	gpio_free(pn544_dev->ven_gpio);

err_ven:
	gpio_free(pn544_dev->firm_gpio);

	pr_info("================ pn544_probe() end with error! ================\n");

	return ret;
}

static int pn544_remove(struct i2c_client *client)
{
	struct pn544_dev *pn544_dev;

	pn544_dev = i2c_get_clientdata(client);
	free_irq(client->irq, pn544_dev);
	misc_deregister(&pn544_dev->pn544_device);
	mutex_destroy(&pn544_dev->read_mutex);
	gpio_free(pn544_dev->irq_gpio);
	gpio_free(pn544_dev->ven_gpio);
	gpio_free(pn544_dev->firm_gpio);
	kfree(pn544_dev);

	return 0;
}

static const struct i2c_device_id pn544_id[] = {
	{ "pn544", 0 },
	{ }
};

static struct i2c_driver pn544_driver = {
	.id_table	= pn544_id,
	.probe		= pn544_probe,
	.remove		= pn544_remove,
	.driver		= {
		.owner	= THIS_MODULE,
		.name	= "pn544",
	},
};

/*
 * module load/unload record keeping
 */

static int __init pn544_dev_init(void)
{
	pr_info("Loading pn544 driver\n");
	return i2c_add_driver(&pn544_driver);
}
module_init(pn544_dev_init);

static void __exit pn544_dev_exit(void)
{
	pr_info("Unloading pn544 driver\n");
	i2c_del_driver(&pn544_driver);
}
module_exit(pn544_dev_exit);

MODULE_AUTHOR("Sylvain Fonteneau");
MODULE_DESCRIPTION("NFC PN544 driver");
MODULE_LICENSE("GPL");
