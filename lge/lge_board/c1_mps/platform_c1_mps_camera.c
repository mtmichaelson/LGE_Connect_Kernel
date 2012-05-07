/*
 * Copyright (C) 2011 LGE, Inc.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/mfd/pmic8901.h>
#include <linux/regulator/pmic8901-regulator.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/machine.h>
#include <linux/bootmem.h>
#include <mach/board.h>
#include <mach/msm_bus_board.h>
#include "board_c1_mps.h"
#include "devices_c1_mps.h"


/* MT9P017 Main Camera - 5M Bayer Camera*/
#define M_CAM_MCLK						32
#define M_CAM_SDA						47
#define M_CAM_SCL						48
#define M_CAM_RESET_N					157
#define M_CAM_I2C_SLAVE_ADDR			0x6C>>2

#define M_CAM_VCM_EN					156

/* MT9V113 VT Camera - 0.3M SOC Camera*/
#define VT_CAM_RESET_N					57
#define VT_CAM_I2C_SLAVE_ADDR			0x7A>>1

/* LM3559 Flash LED driver*/
#define FLASH_LED_I2C_SLAVE_ADDR		0xA6>>1

#define FLASH_LED_EN				    154

/*========================================================================
	  MSM VPE (video preprocessing)
  ======================================================================*/
#ifdef CONFIG_MSM_VPE
static struct resource msm_vpe_resources[] = {
	{
		.start	= 0x05300000,
		.end	= 0x05300000 + SZ_1M - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= INT_VPE,
		.end	= INT_VPE,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device msm_vpe_device = {
	.name = "msm_vpe",
	.id   = 0,
	.num_resources = ARRAY_SIZE(msm_vpe_resources),
	.resource = msm_vpe_resources,
};
#endif

#ifdef CONFIG_LGE_CAMERA
static uint32_t camera_off_gpio_table[] = {
	GPIO_CFG(M_CAM_MCLK, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), 
	GPIO_CFG(M_CAM_SDA, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_8MA),
	GPIO_CFG(M_CAM_SCL, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_8MA), 
	GPIO_CFG(M_CAM_RESET_N, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), 
	GPIO_CFG(VT_CAM_RESET_N, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), 
};
static uint32_t camera_on_gpio_table[] = {
	GPIO_CFG(M_CAM_MCLK, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), 
	GPIO_CFG(M_CAM_SDA, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_8MA), 
	GPIO_CFG(M_CAM_SCL, 1, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_8MA), 
	GPIO_CFG(M_CAM_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), 
	GPIO_CFG(VT_CAM_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA), 	
};

static void config_gpio_table(uint32_t *table, int len)
{
	int n, rc;
	for (n = 0; n < len; n++) {
		rc = gpio_tlmm_config(table[n], GPIO_CFG_ENABLE);
		if (rc) {
			pr_err("%s: gpio_tlmm_config(%#x)=%d\n",
				__func__, table[n], rc);
			break;
		}
	}
}

static int config_camera_on_gpios(void)
{
	int rc = 0;

	config_gpio_table(camera_on_gpio_table,
		ARRAY_SIZE(camera_on_gpio_table));

	return rc;
}

static void config_camera_off_gpios(void)
{
	config_gpio_table(camera_off_gpio_table,
		ARRAY_SIZE(camera_off_gpio_table));
}

static int config_camera_on_gpios_vt_cam(void)
{
	int rc = 0;

	config_gpio_table(camera_on_gpio_table,
		ARRAY_SIZE(camera_on_gpio_table));

	return rc;
}

static void config_camera_off_gpios_vt_cam(void)
{
	config_gpio_table(camera_off_gpio_table,
		ARRAY_SIZE(camera_off_gpio_table));
}

struct msm_camera_device_platform_data msm_camera_device_data = {
	.camera_gpio_on  = config_camera_on_gpios,
	.camera_gpio_off = config_camera_off_gpios,
	.ioext.csiphy = 0x04800000,
	.ioext.csisz  = 0x00000400,
	.ioext.csiirq = CSI_0_IRQ,
	.ioclk.mclk_clk_rate = 24000000,
	.ioclk.vfe_clk_rate  = 228570000,
};

struct msm_camera_device_platform_data msm_camera_device_data_vt_cam = {
	.camera_gpio_on  = config_camera_on_gpios_vt_cam,
	.camera_gpio_off = config_camera_off_gpios_vt_cam,
	.ioext.csiphy = 0x04900000,
	.ioext.csisz  = 0x00000400,
	.ioext.csiirq = CSI_1_IRQ,
	.ioclk.mclk_clk_rate = 24000000,
	.ioclk.vfe_clk_rate  = 228570000,
};

struct resource msm_camera_resources[] = {
	{
		.start	= 0x04500000,
		.end	= 0x04500000 + SZ_1M - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= VFE_IRQ,
		.end	= VFE_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

/*========================================================================
	  LGE Flash LED (LM3559)
  ======================================================================*/
#ifdef CONFIG_LGE_FLASH_LM3559
struct led_flash_platform_data {
	int gpio_en;
};

static struct led_flash_platform_data lm3559_flash_pdata = {
	.gpio_en		= FLASH_LED_EN,
};
	
static struct i2c_board_info cam_i2c_flash_info[] = {
	{
		I2C_BOARD_INFO("lm3559",FLASH_LED_I2C_SLAVE_ADDR),
		.type = "lm3559",
		.platform_data = &lm3559_flash_pdata,
	}
};
#endif

/*========================================================================
	  LGE Camera Sensor  (Main Camera : MT9P017 , VT Camera : MT9V113)
  ======================================================================*/
#ifdef CONFIG_LGE_SENSOR_MT9P017
static struct msm_camera_sensor_flash_data flash_mt9p017 = {
	.flash_type		= MSM_CAMERA_FLASH_NONE,
};

static struct msm_camera_sensor_info msm_camera_sensor_mt9p017_data = {
	.sensor_name	= "mt9p017",
	.sensor_reset	= M_CAM_RESET_N,
	.sensor_pwd		= 85,
	.vcm_pwd		= M_CAM_VCM_EN,
	.vcm_enable		= 1,
	.pdata			= &msm_camera_device_data,
	.resource		= msm_camera_resources,
	.num_resources	= ARRAY_SIZE(msm_camera_resources),
	.flash_data		= &flash_mt9p017,
	.csi_if			= 1
};
struct platform_device msm_camera_sensor_mt9p017 = {
	.name	= "msm_camera_mt9p017",
	.dev	= {
		.platform_data = &msm_camera_sensor_mt9p017_data,
	},
};
#endif
#ifdef CONFIG_LGE_SENSOR_MT9V113
static struct msm_camera_sensor_flash_data flash_mt9v113 = {
	.flash_type		= MSM_CAMERA_FLASH_NONE,
};

static struct msm_camera_sensor_info msm_camera_sensor_mt9v113_data = {
	.sensor_name	= "mt9v113",
	.sensor_reset	= VT_CAM_RESET_N,
	.sensor_pwd		= 85,
	.vcm_pwd		= 1,
	.vcm_enable		= 0,
	.pdata			= &msm_camera_device_data_vt_cam,
	.resource		= msm_camera_resources,
	.num_resources	= ARRAY_SIZE(msm_camera_resources),
	.flash_data		= &flash_mt9v113,
	.csi_if			= 1
};

struct platform_device msm_camera_sensor_vtcam = {
//	.id 	= 0,
	.name	= "msm_camera_mt9v113",
	.dev	= {
		.platform_data = &msm_camera_sensor_mt9v113_data,
	},
};
#endif

static struct i2c_board_info msm_camera_boardinfo[] __initdata = {
	#ifdef CONFIG_LGE_SENSOR_MT9P017
	{
		I2C_BOARD_INFO("mt9p017", M_CAM_I2C_SLAVE_ADDR),
	},
	#endif
	#ifdef CONFIG_LGE_SENSOR_MT9V113
	{
		I2C_BOARD_INFO("mt9v113", VT_CAM_I2C_SLAVE_ADDR),
	},
	#endif
};
#endif /*CONFIG_LGE_CAMERA*/

/*========================================================================
	  MSM GEMINI (JPEG Hardware)
  ======================================================================*/
#ifdef CONFIG_MSM_GEMINI
static struct resource msm_gemini_resources[] = {
	{
		.start  = 0x04600000,
		.end    = 0x04600000 + SZ_1M - 1,
		.flags  = IORESOURCE_MEM,
	},
	{
		.start  = INT_JPEG,
		.end    = INT_JPEG,
		.flags  = IORESOURCE_IRQ,
	},
};

static struct platform_device msm_gemini_device = {
	.name           = "msm_gemini",
	.resource       = msm_gemini_resources,
	.num_resources  = ARRAY_SIZE(msm_gemini_resources),
};
#endif

static struct platform_device *camera_devices[] __initdata = {
#ifdef CONFIG_LGE_SENSOR_MT9P017
		&msm_camera_sensor_mt9p017,
#endif
#ifdef CONFIG_LGE_SENSOR_MT9V113
		&msm_camera_sensor_vtcam,
#endif
#ifdef CONFIG_MSM_GEMINI
		&msm_gemini_device,
#endif
#ifdef CONFIG_MSM_VPE
		&msm_vpe_device,
#endif
};

#ifdef CONFIG_I2C
#define I2C_SURF 1
#define I2C_FFA  (1 << 1)
#define I2C_RUMI (1 << 2)
#define I2C_SIM  (1 << 3)
#define I2C_FLUID (1 << 4)

struct i2c_registry {
	u8                     machs;
	int                    bus;
	struct i2c_board_info *info;
	int                    len;
};

static struct i2c_registry camera_i2c_devices[] __initdata = {
#ifdef CONFIG_LGE_FLASH_LM3559 
		{
			I2C_SURF | I2C_FFA | I2C_FLUID,
			MSM_GSBI3_QUP_I2C_BUS_ID,
			cam_i2c_flash_info,
			ARRAY_SIZE(cam_i2c_flash_info),
		},
#endif
#ifdef CONFIG_LGE_CAMERA
	 	{
			I2C_SURF | I2C_FFA | I2C_FLUID,
			MSM_GSBI4_QUP_I2C_BUS_ID,
			msm_camera_boardinfo,
			ARRAY_SIZE(msm_camera_boardinfo),
		},
#endif
};

void __init i2c_register_camera_info(void){

	int i;

	/* Run the array and install devices as appropriate */
	for (i = 0; i < ARRAY_SIZE(camera_i2c_devices); ++i) {
		i2c_register_board_info(camera_i2c_devices[i].bus,
						camera_i2c_devices[i].info,
						camera_i2c_devices[i].len);
	}
}
#endif /*CONFIG_I2C*/

void __init msm_camera_init(void){
	platform_add_devices(camera_devices, ARRAY_SIZE(camera_devices));
}


