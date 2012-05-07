/* arch/arm/mach-msm/lge/board-c1_mps-bt.c
 * Copyright (C) 2009 LGE, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/types.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <asm/setup.h>
#include <mach/gpio.h>
#include <mach/vreg.h>
#include <mach/board_lge.h>
#include <linux/delay.h>
#include <linux/rfkill.h>
#include "gpiomux.h"
#include "gpio.h"


#define BT_WAKE 137
#define BT_RESET_N 138
#define BT_HOST_WAKE 127
#define BT_PCM_DOUT 111
#define BT_PCM_DIN 112
#define BT_PCM_SYNC 113
#define BT_PCM_CLK 114
#define BT_RFR 53
#define BT_CTS 54
#define BT_RX 55
#define BT_TX 56

#if 0 //implement bt power routine using existing api (configure_uart_gpios,configure_pcm_gpios)
static unsigned bt_config_power_on[] = {
	GPIO_CFG(BT_RFR, 2, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* RFR */
	GPIO_CFG(BT_CTS, 2, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* CTS */
	GPIO_CFG(BT_RX, 2, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* Rx */
	GPIO_CFG(BT_TX, 3, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* Tx */
	GPIO_CFG(BT_PCM_DOUT, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* PCM_DOUT */
	GPIO_CFG(BT_PCM_DIN, 1, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* PCM_DIN */
	GPIO_CFG(BT_PCM_SYNC, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* PCM_SYNC */
	GPIO_CFG(BT_PCM_CLK, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* PCM_CLK */
	GPIO_CFG(BT_WAKE, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* WAKE */
	GPIO_CFG(BT_HOST_WAKE, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* HOST_WAKE */
	GPIO_CFG(BT_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* RESET_N */
};
static unsigned bt_config_power_off[] = {
	GPIO_CFG(BT_RFR, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* RFR */
	GPIO_CFG(BT_CTS, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* CTS */
	GPIO_CFG(BT_RX, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* Rx */
	GPIO_CFG(BT_TX, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* Tx */
	GPIO_CFG(BT_PCM_DOUT, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* PCM_DOUT */
	GPIO_CFG(BT_PCM_DIN, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* PCM_DIN */
	GPIO_CFG(BT_PCM_SYNC, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* PCM_SYNC */
	GPIO_CFG(BT_PCM_CLK, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* PCM_CLK */
	GPIO_CFG(BT_WAKE, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* WAKE */
	GPIO_CFG(BT_HOST_WAKE, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* HOST_WAKE */
	GPIO_CFG(BT_RESET_N, 0, GPIO_CFG_INPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),	/* RESET_N */	
};
#endif

static unsigned bt_config_power_on[] = {
	GPIO_CFG(BT_WAKE, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* WAKE */
	GPIO_CFG(BT_HOST_WAKE, 0, GPIO_CFG_INPUT,  GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* HOST_WAKE */
	GPIO_CFG(BT_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), /* BT_RESET */
};
static unsigned bt_config_power_off[] = {
	GPIO_CFG(BT_WAKE, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* WAKE */
	GPIO_CFG(BT_HOST_WAKE, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),	/* HOST_WAKE */
	GPIO_CFG(BT_RESET_N, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), /* BT_RESET */
};

static int configure_uart_gpios(int on)
{
	int ret = 0, i;
	int uart_gpios[] = {53, 54, 55, 56};
	for (i = 0; i < ARRAY_SIZE(uart_gpios); i++) {
		if (on) {
			ret = msm_gpiomux_get(uart_gpios[i]);
			if (unlikely(ret))
				break;
		} else {
			ret = msm_gpiomux_put(uart_gpios[i]);
			if (unlikely(ret))
				return ret;
		}
	}
	if (ret)
		for (; i >= 0; i--)
			msm_gpiomux_put(uart_gpios[i]);
	return ret;
}

static int configure_pcm_gpios(int on)
{
	int ret = 0, i;
	int pcm_gpios[] = {111, 112, 113, 114};
	for (i = 0; i < ARRAY_SIZE(pcm_gpios); i++) {
		if (on) {
			ret = msm_gpiomux_get(pcm_gpios[i]);
			if (unlikely(ret))
				break;
		} else {
			ret = msm_gpiomux_put(pcm_gpios[i]);
			if (unlikely(ret))
				return ret;
		}
	}
	if (ret)
		for (; i >= 0; i--)
			msm_gpiomux_put(pcm_gpios[i]);
	return ret;
} 
static int c1_mps_bluetooth_power(int on)
{
  int ret, pin;

  printk(KERN_ERR "[LG_BTUI] %s power : %d ", __func__, on);

  if(on)
    {

      if(configure_uart_gpios(1))
        {
          printk(KERN_ERR "bluetooth_power on fail");
          return -EIO;
        }

      if(configure_pcm_gpios(1))
        {
          printk(KERN_ERR "bluetooth_power on fail");
          return -EIO;
        }

      for (pin = 0; pin < ARRAY_SIZE(bt_config_power_on); pin++)
        {
          ret = gpio_tlmm_config(bt_config_power_on[pin],GPIO_CFG_ENABLE);
          if (ret) 
            {
              printk(KERN_ERR "%s: gpio_tlmm_config(%#x)=fg%d\n",__func__, bt_config_power_on[pin], ret);
              return -EIO;
            }

		gpio_direction_output(BT_RESET_N, 0);
		mdelay(100);
		gpio_direction_output(BT_RESET_N, 1);
		mdelay(100);
        }
    }
  else
    {
      gpio_direction_output(BT_RESET_N,0);

      if(configure_uart_gpios(0))
        {
          printk(KERN_ERR"bluetooth_power on fail");
          return -EIO;
        }

      if(configure_pcm_gpios(0))
        {
          printk(KERN_ERR "bluetooth_power on fail");
          return -EIO;
        }

      for (pin = 0; pin < ARRAY_SIZE(bt_config_power_off); pin++)
        {
          ret = gpio_tlmm_config(bt_config_power_off[pin],GPIO_CFG_ENABLE);
          if (ret) 
            {
              printk(KERN_ERR "%s: gpio_tlmm_config(%#x)=%d\n",__func__, bt_config_power_off[pin], ret);
              return -EIO;
            }
        }
    }
  return 0;
}

#if 0 //implement bt power routine using existing api (configure_uart_gpios,configure_pcm_gpios)
static int c1_mps_bluetooth_power(int on)
{
	int pin, rc;

	printk(KERN_DEBUG "%s\n", __func__);
	printk( "%s %d\n", __func__, on);

	if (on) {
		for (pin = 0; pin < ARRAY_SIZE(bt_config_power_on); pin++) {
			rc = gpio_tlmm_config(bt_config_power_on[pin],
					      GPIO_CFG_ENABLE);
			if (rc) {
				printk(KERN_ERR
				       "%s: gpio_tlmm_config(%#x)=%d\n",
				       __func__, bt_config_power_on[pin], rc);
				return -EIO;
			}
		}
	
		gpio_set_value(BT_RESET_N, 0);
		mdelay(100);
		gpio_set_value(BT_RESET_N, 1);
		mdelay(100);

	} else {
	
		gpio_set_value(BT_RESET_N, 0);
		for (pin = 0; pin < ARRAY_SIZE(bt_config_power_off); pin++) {
			rc = gpio_tlmm_config(bt_config_power_off[pin],
					      GPIO_CFG_ENABLE);
			if (rc) {
				printk(KERN_ERR
				       "%s: gpio_tlmm_config(%#x)=%d\n",
				       __func__, bt_config_power_off[pin], rc);
				return -EIO;
			}
		}
	}
	return 0;
}
#endif

#if 1  //i'm not sure why phone reset when bt toggle is added to  platform  [BT_TOGGLE]

static int c1_mps_bluetooth_toggle_radio(void *data, bool state)
{
	int ret;
	int (*power_control)(int enable);

	 printk(KERN_ERR "[LG_BTUI] %s : Called c1_mps_bluetooth_toggle_radio",__func__);  	 	
    power_control = ((struct bluetooth_platform_data *)data)->bluetooth_power;
	ret = (*power_control)((state == RFKILL_USER_STATE_SOFT_BLOCKED) ? 1 : 0);
	return ret;
}

static struct bluetooth_platform_data c1_mps_bluetooth_data = {
	.bluetooth_power = c1_mps_bluetooth_power,
	.bluetooth_toggle_radio = c1_mps_bluetooth_toggle_radio,
};

#endif
static struct platform_device msm_bt_power_device = {
	.name = "bt_power",
	.id	 = -1,
#if 1 //i'm not sure why phone reset when bt toggle is added to  platform  [BT_TOGGLE]
	.dev = {
		.platform_data = &c1_mps_bluetooth_data,	
#else
	.dev = {
		.platform_data = &c1_mps_bluetooth_power,
#endif
	},		
};
static void __init bt_power_init(void)
{
	 int rc;
	  printk(KERN_ERR "[LG_BTUI] %s : Called BT Poweer Init",__func__);  	 	
	  rc = gpio_request(BT_RESET_N, "bt_reset_n");
	  if (rc)
	   {
	     printk(KERN_ERR "%s: bt reset  %d request failed\n",__func__,BT_RESET_N );
    	 return;
	   }
}
 
static struct resource bluesleep_resources[] = {
	{
		.name	= "gpio_host_wake",
		.start	= BT_HOST_WAKE,
		.end	= BT_HOST_WAKE,
		.flags	= IORESOURCE_IO,
	},
	{
		.name	= "gpio_ext_wake",
		.start	= BT_WAKE,
		.end	= BT_WAKE,
		.flags	= IORESOURCE_IO,
	},
	{
		.name	= "host_wake",
		.start	= MSM_GPIO_TO_INT(BT_HOST_WAKE),
		.end	= MSM_GPIO_TO_INT(BT_HOST_WAKE),
		.flags	= IORESOURCE_IRQ,
	},
};

static struct bluesleep_platform_data c1_mps_bluesleep_data = {
	.bluetooth_port_num = 0,
};


static struct platform_device msm_bluesleep_device = {
	.name = "bluesleep",
	.id		= -1,
	.num_resources	= ARRAY_SIZE(bluesleep_resources),
	.resource	= bluesleep_resources,
	.dev = {
		.platform_data = &c1_mps_bluesleep_data,
	},	
};


static struct platform_device *bt_devices[] __initdata = {
		&msm_bt_power_device, 
		&msm_bluesleep_device,
};

void __init lge_add_btpower_devices(void)
{	
	bt_power_init();
	printk(KERN_ERR "[LG_BTUI] %s : Called BT Poweer Init",__func__); 
	
	platform_add_devices(bt_devices, ARRAY_SIZE(bt_devices));
//	platform_device_register(&msm_bt_power_device);
//	platform_device_register(&msm_bluesleep_device);
}
