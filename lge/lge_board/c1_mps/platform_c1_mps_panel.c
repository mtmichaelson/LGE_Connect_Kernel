/* lge/lge_board/i_atnt/platform_i_atnt_panel.c
 *
 * Copyright (C) 2010 LGE, Inc.
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

#include <linux/i2c.h>
#include "devices_c1_mps.h"
#include "board_c1_mps.h"

#ifdef CONFIG_FB_MSM_LCDC_DSUB
/* VGA = 1440 x 900 x 4(bpp) x 2(pages)
   prim = 1024 x 600 x 4(bpp) x 2(pages)
   This is the difference. */
#define MSM_FB_DSUB_PMEM_ADDER (0x9E3400-0x4B0000)
#else
#define MSM_FB_DSUB_PMEM_ADDER (0)
#endif

#ifdef CONFIG_FB_MSM_MIPI_DSI
/* 960 x 540 x 3 x 2 */
//#define MIPI_DSI_WRITEBACK_SIZE 0x300000
/*  I - pjt 1280 x 736 x 3 x 2 */
//#define MIPI_DSI_WRITEBACK_SIZE 0x564000
/*  cayman  800 x 480 x 3 x 2*/
#define MIPI_DSI_WRITEBACK_SIZE 0x232800
#else
#define MIPI_DSI_WRITEBACK_SIZE 0
#endif

#ifdef CONFIG_FB_MSM_TRIPLE_BUFFER
/* prim = 1024 x 600 x 4(bpp) x 3(pages) */
//#define MSM_FB_PRIM_BUF_SIZE 0x708000
/* prim = 1280 x 736 x 4(bpp) x 3(pages) */
//#define MSM_FB_PRIM_BUF_SIZE 0xAC8000
/* prim = 800 x 480 x 4(bpp) x 3(pages) */
#define MSM_FB_PRIM_BUF_SIZE 0x465000
#else
/* prim = 1024 x 600 x 4(bpp) x 2(pages) */
//#define MSM_FB_PRIM_BUF_SIZE 0x4B0000
/* prim = 1280 x 736 x 4(bpp) x 2(pages) */
#define MSM_FB_PRIM_BUF_SIZE 0x730000
#endif

#ifdef CONFIG_FB_MSM_HDMI_MSM_PANEL
/* prim = 1024 x 600 x 4(bpp) x 2(pages)
 * hdmi = 1920 x 1080 x 2(bpp) x 1(page)
 * Note: must be multiple of 4096 */
#define MSM_FB_SIZE roundup(MSM_FB_PRIM_BUF_SIZE + 0x3F4800 + MIPI_DSI_WRITEBACK_SIZE + MSM_FB_DSUB_PMEM_ADDER, 4096)
#elif defined(CONFIG_FB_MSM_TVOUT)
/* prim = 1024 x 600 x 4(bpp) x 2(pages)
 * tvout = 720 x 576 x 2(bpp) x 2(pages)
 * Note: must be multiple of 4096 */
#define MSM_FB_SIZE roundup(MSM_FB_PRIM_BUF_SIZE + 0x195000 + \
			MIPI_DSI_WRITEBACK_SIZE + MSM_FB_DSUB_PMEM_ADDER, 4096)
#else /* CONFIG_FB_MSM_HDMI_MSM_PANEL */
#if 1 /*to get free memory*/
#define MSM_FB_SIZE roundup(MSM_FB_PRIM_BUF_SIZE +  \
			MIPI_DSI_WRITEBACK_SIZE + MSM_FB_DSUB_PMEM_ADDER, 4096)
#else
#define MSM_FB_SIZE 0x500000
#endif
#endif /* CONFIG_FB_MSM_HDMI_MSM_PANEL */

#define MSM_PMEM_SF_SIZE 0x1000 /* 4k bytes */

#define MSM_PMEM_KERNEL_EBI1_SIZE  0x600000
#define MSM_PMEM_ADSP_SIZE         0x1200000
#define MSM_PMEM_AUDIO_SIZE        0x279000

#define MSM_SMI_BASE          0x38000000
/* Kernel SMI PMEM Region for video core, used for Firmware */
/* and encoder,decoder scratch buffers */
/* Kernel SMI PMEM Region Should always precede the user space */
/* SMI PMEM Region, as the video core will use offset address */
/* from the Firmware base */
#define PMEM_KERNEL_SMI_BASE  (MSM_SMI_BASE)
#define PMEM_KERNEL_SMI_SIZE  0x600000
/* User space SMI PMEM Region for video core*/
/* used for encoder, decoder input & output buffers  */
#define MSM_PMEM_SMIPOOL_BASE (PMEM_KERNEL_SMI_BASE + PMEM_KERNEL_SMI_SIZE)
#define MSM_PMEM_SMIPOOL_SIZE 0x3A00000

static unsigned fb_size = MSM_FB_SIZE;
static int __init fb_size_setup(char *p)
{
	fb_size = memparse(p, NULL);
	return 0;
}
early_param("fb_size", fb_size_setup);

#ifdef CONFIG_KERNEL_PMEM_EBI_REGION
static unsigned pmem_kernel_ebi1_size = MSM_PMEM_KERNEL_EBI1_SIZE;
static int __init pmem_kernel_ebi1_size_setup(char *p)
{
	pmem_kernel_ebi1_size = memparse(p, NULL);
	return 0;
}
early_param("pmem_kernel_ebi1_size", pmem_kernel_ebi1_size_setup);
#endif /* CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT */
#ifdef CONFIG_ANDROID_PMEM
static unsigned pmem_sf_size = MSM_PMEM_SF_SIZE;
static int __init pmem_sf_size_setup(char *p)
{
	pmem_sf_size = memparse(p, NULL);
	return 0;
}
early_param("pmem_sf_size", pmem_sf_size_setup);

static unsigned pmem_adsp_size = MSM_PMEM_ADSP_SIZE;

static int __init pmem_adsp_size_setup(char *p)
{
	pmem_adsp_size = memparse(p, NULL);
	return 0;
}
early_param("pmem_adsp_size", pmem_adsp_size_setup);

static unsigned pmem_audio_size = MSM_PMEM_AUDIO_SIZE;

static int __init pmem_audio_size_setup(char *p)
{
	pmem_audio_size = memparse(p, NULL);
	return 0;
}
early_param("pmem_audio_size", pmem_audio_size_setup);
#endif /* CONFIG_FB_MSM_HDMI_MSM_PANEL */

static struct resource msm_fb_resources[] = {
	{
		.flags  = IORESOURCE_DMA,
	}
};

#ifdef CONFIG_FB_MSM_LCDC_AUTO_DETECT
static int msm_fb_detect_panel(const char *name)
{
	if (machine_is_msm8x60_fluid()) {
		uint32_t soc_platform_version = socinfo_get_platform_version();
		if (SOCINFO_VERSION_MAJOR(soc_platform_version) < 3) {
#ifdef CONFIG_FB_MSM_LCDC_SAMSUNG_OLED_PT
			if (!strncmp(name, LCDC_SAMSUNG_OLED_PANEL_NAME,
					strlen(LCDC_SAMSUNG_OLED_PANEL_NAME)))
				return 0;
#endif
		} else { /*P3 and up use AUO panel */
#ifdef CONFIG_FB_MSM_LCDC_AUO_WVGA
			if (!strncmp(name, LCDC_AUO_PANEL_NAME,
					strlen(LCDC_AUO_PANEL_NAME)))
				return 0;
#endif
		}
		if (!strncmp(name, LCDC_SAMSUNG_WSVGA_PANEL_NAME,
				strlen(LCDC_SAMSUNG_WSVGA_PANEL_NAME)))
			return -ENODEV;
	} else {
		if (!strncmp(name, LCDC_SAMSUNG_WSVGA_PANEL_NAME,
				strlen(LCDC_SAMSUNG_WSVGA_PANEL_NAME)))
			return 0;
		if (!strncmp(name, LCDC_SAMSUNG_OLED_PANEL_NAME,
				strlen(LCDC_SAMSUNG_OLED_PANEL_NAME)))
			return -ENODEV;
	}
	pr_warning("%s: not supported '%s'", __func__, name);
	return -ENODEV;
}

static struct msm_fb_platform_data msm_fb_pdata = {
	.detect_client = msm_fb_detect_panel,
};
#endif /* CONFIG_FB_MSM_LCDC_AUTO_DETECT */

static struct platform_device msm_fb_device = {
	.name   = "msm_fb",
	.id     = 0,
	.num_resources     = ARRAY_SIZE(msm_fb_resources),
	.resource          = msm_fb_resources,
#ifdef CONFIG_FB_MSM_LCDC_AUTO_DETECT
	.dev.platform_data = &msm_fb_pdata,
#endif /* CONFIG_FB_MSM_LCDC_AUTO_DETECT */
};

#ifdef CONFIG_FB_MSM_HDMI_MSM_PANEL
static struct resource hdmi_msm_resources[] = {
	{
		.name  = "hdmi_msm_qfprom_addr",
		.start = 0x00700000,
		.end   = 0x007060FF,
		.flags = IORESOURCE_MEM,
	},
	{
		.name  = "hdmi_msm_hdmi_addr",
		.start = 0x04A00000,
		.end   = 0x04A00FFF,
		.flags = IORESOURCE_MEM,
	},
	{
		.name  = "hdmi_msm_irq",
		.start = HDMI_IRQ,
		.end   = HDMI_IRQ,
		.flags = IORESOURCE_IRQ,
	},
};

static int hdmi_enable_5v(int on);
static int hdmi_core_power(int on, int show);
static int hdmi_cec_power(int on);

static struct msm_hdmi_platform_data hdmi_msm_data = {
	.irq = HDMI_IRQ,
	.enable_5v = hdmi_enable_5v,
	.core_power = hdmi_core_power,
	.cec_power = hdmi_cec_power,
};

static struct platform_device hdmi_msm_device = {
	.name = "hdmi_msm",
	.id = 0,
	.num_resources = ARRAY_SIZE(hdmi_msm_resources),
	.resource = hdmi_msm_resources,
	.dev.platform_data = &hdmi_msm_data,
};
#endif /* CONFIG_FB_MSM_HDMI_MSM_PANEL */

#ifdef CONFIG_FB_MSM_MIPI_DSI

/* minjong.gong@lge.com, 2011.01.31 - lgd lcd for MWC board*/
#define LCD_RESET_N		50
/* minjong.gong@lge.com, 2011.01.31 - lgd lcd for MWC board*/
#define MDP_VSYNC_GPIO 28

static void mipi_config_gpio(int on)
{
	if(on)
	{
		/* Sub lcd  reset */
		gpio_tlmm_config(LCD_RESET_N,0);
		gpio_direction_output(LCD_RESET_N,1);
	}
}
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT) || defined(CONFIG_LGE_DISPLAY_MIPI_LGD_CMD_WVGA_PT)
extern void lm3537_lcd_backlight_set_level(int level);
static int mipi_lgd_backlight_level(int level, int max, int min)
{
	lm3537_lcd_backlight_set_level(level);
	return 0;
}

static struct msm_panel_common_pdata mipi_lgd_pdata = {
	.backlight_level = mipi_lgd_backlight_level,
	.panel_config_gpio = mipi_config_gpio,
};

static struct platform_device mipi_dsi_lgd_panel_device = {
	.name = "mipi_lgd",
	.id = 0,
	.dev = {
		.platform_data = &mipi_lgd_pdata,
	}
};

#else
extern void aat2862_lcd_backlight_set_level( int level);
static int mipi_sharp_backlight_level(int level, int max, int min)
{
	aat2862_lcd_backlight_set_level(level);

	return 0;
}

static struct msm_panel_common_pdata mipi_sharp_pdata = {
	.backlight_level = mipi_sharp_backlight_level,
	.panel_config_gpio = mipi_config_gpio,
};

static struct platform_device mipi_dsi_sharp_panel_device = {
	.name = "mipi_sharp",
	.id = 0,
	.dev = {
		.platform_data = &mipi_sharp_pdata,
	}
};
#endif

#ifdef CONFIG_LGE_BACKLIGHT_AAT2862
extern void aat2862_set_ldo(bool enable, int ldo_num, int level);
static struct regulator* reg_8901_l3 = NULL;
static int mipi_panel_power(int on)
{
	int flag_on = !!on;
	static int mipi_power_save_on;
	int rc;

	if (mipi_power_save_on == flag_on)
		return 0;

	mipi_power_save_on = flag_on;

	if (reg_8901_l3 == NULL) {
		reg_8901_l3 = regulator_get(NULL, "8901_l3");
		if (IS_ERR(reg_8901_l3)) {
			reg_8901_l3 = NULL;
		}
	}

	if(on){
		aat2862_set_ldo(1,0,0x4);
		aat2862_set_ldo(1,1,0xC);

		rc = regulator_set_voltage(reg_8901_l3, 3000000, 3000000);
		if (!rc)
			rc = regulator_enable(reg_8901_l3);
		if (rc) {
			pr_err("'%s' regulator enable failed, rc=%d\n",
					"8901_l3", rc);
			return rc;
		}
	}
	else{
		aat2862_set_ldo(0,0,0x0);
		aat2862_set_ldo(0,1,0x0);

		rc = regulator_disable(reg_8901_l3);
		if (rc)
			pr_warning("'%s' regulator disable failed, rc=%d\n",
					"8901_l3", rc);
		pr_info("%s(off): success\n", __func__);

	}
	return 0;
}
#else
static struct regulator* reg_8901_l2 = NULL;
static struct regulator* reg_8901_l3 = NULL;
static struct regulator* reg_8901_mvs = NULL;
static int mipi_panel_power(int on)
{
	int flag_on = !!on;
	static int mipi_power_save_on;
	int rc;

	if (mipi_power_save_on == flag_on)
		return 0;

	mipi_power_save_on = flag_on;

	if (reg_8901_l2 == NULL) {
		reg_8901_l2 = regulator_get(NULL, "8901_l2");
		if (IS_ERR(reg_8901_l2)) {
			reg_8901_l2 = NULL;
		}
	}	
	if (reg_8901_mvs == NULL) {
		reg_8901_mvs = regulator_get(NULL, "8901_mvs0");
		if (IS_ERR(reg_8901_mvs)) {
			reg_8901_mvs = NULL;
		}
	}
	if (reg_8901_l3 == NULL) {
		reg_8901_l3 = regulator_get(NULL, "8901_l3");
		if (IS_ERR(reg_8901_l3)) {
			reg_8901_l3 = NULL;
		}
	}

	if(on){
		rc = regulator_set_voltage(reg_8901_l2, 2850000, 2850000);
		if (!rc)
			rc = regulator_enable(reg_8901_l2);
		if (rc) {
			pr_err("'%s' regulator enable failed, rc=%d\n",
					"8901_l2", rc);
			return rc;
		}
		udelay(100); // 100us
		
		if (!rc)
			rc = regulator_enable(reg_8901_mvs); // +1V8_LCD_IO
		if (rc) {
			pr_err("'%s' regulator enable failed, rc=%d\n",
					"8901_mvs", rc);
			return rc;
		}
		udelay(500); // 100us

		rc = regulator_set_voltage(reg_8901_l3, 2850000, 2850000);
		if (!rc)
			rc = regulator_enable(reg_8901_l3);
		if (rc) {
			pr_err("'%s' regulator enable failed, rc=%d\n",
					"8901_l3", rc);
			return rc;
		}
		udelay(100); // 100us
	}
	else{

        gpio_set_value(MDP_VSYNC_GPIO,0);
		gpio_tlmm_config(GPIO_CFG(MDP_VSYNC_GPIO, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
		rc = regulator_disable(reg_8901_l3);
		if (rc)
			pr_warning("'%s' regulator disable failed, rc=%d\n",
					"8901_l2", rc);
		udelay(100); // 100us		
		rc = regulator_disable(reg_8901_mvs);
		if (rc)
			pr_warning("'%s' regulator disable failed, rc=%d\n",
					"8901_mvs", rc);
		udelay(100); // 100us
		rc = regulator_disable(reg_8901_l2);
		if (rc)
			pr_warning("'%s' regulator disable failed, rc=%d\n",
					"8901_l3", rc);
		udelay(100); // 100us
		pr_info("%s(off): success\n", __func__);

	}
	return 0;
}
#endif /* CONFIG_LGE_BACKLIGHT_AAT2862 */
struct mipi_dsi_platform_data mipi_pdata = {
    //.vsync_gpio = MDP_VSYNC_GPIO,
	.dsi_power_save = mipi_panel_power,
};


#else
static struct platform_device mipi_dsi_toshiba_panel_device = {
	.name = "mipi_toshiba",
	.id = 0,
};

#endif /* CONFIG_FB_MSM_MIPI_DSI */

void __init msm8x60_allocate_msm_fb_memory_regions(void)
{
	void *addr;
	unsigned long size;

	size = MSM_FB_SIZE;
	addr = alloc_bootmem(size);
	msm_fb_resources[0].start = __pa(addr);
	msm_fb_resources[0].end = msm_fb_resources[0].start + size - 1;
	pr_info("allocating %lu bytes at %p (%lx physical) for fb\n",
		size, addr, __pa(addr));
}

static struct platform_device *panel_devices[] __initdata = {
	&msm_fb_device,

#ifdef CONFIG_FB_MSM_MIPI_DSI

/* jaeseong.gim@lge.com. 2011-01-16 */
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT) || defined(CONFIG_LGE_DISPLAY_MIPI_LGD_CMD_WVGA_PT)
	&mipi_dsi_lgd_panel_device,
#else
	&mipi_dsi_sharp_panel_device,
#endif /*CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT */
#endif /*CONFIG_FB_MSM_MIPI_DSI */
#ifdef CONFIG_FB_MSM_HDMI_MSM_PANEL
	&hdmi_msm_device,
#endif /* CONFIG_FB_MSM_HDMI_MSM_PANEL */

};

//start, linear mode, shoogi.lee@lge.com, 2011_04_20
struct backlight_platform_data {
   void (*platform_init)(void);
   int gpio;
   unsigned int mode;
   int max_current;
   int init_on_boot;
   int min_brightness;
   int default_brightness;
   int max_brightness;   
};

static struct backlight_platform_data lm3537_data = {
	.gpio = 49,
	.max_current = 0x17,

	/* max_current table - linear mapping
	0x03 = 5 mA full-scale current
	0x07 = 8.5 A full-scale current
	0x0B= 12 mA full-scale current
	0x0F = 15.5 mA full-scale current
	0x13 = 19 mA full-scale current
	0x17 = 22.5 mA full-scale current
	0x1B = 26 mA full-scale current
	0x1F= 29.5 mA full-scale current
	*/

	.min_brightness = 0x05, //0x09,
	.default_brightness = 0x33,
	.max_brightness = 0x71,
};

//end, linear mode, shoogi.lee@lge.com, 2011_04_20

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

#define LM3537_BACKLIGHT_ADDRESS 0x38
static struct i2c_board_info msm_i2c_backlight_info[] = {
	{
		I2C_BOARD_INFO("lm3537", LM3537_BACKLIGHT_ADDRESS),
		.platform_data = &lm3537_data,
	}
};

static struct i2c_registry backlight_device __initdata = {
	I2C_SURF | I2C_FFA,
	MSM_GSBI3_QUP_I2C_BUS_ID,
	msm_i2c_backlight_info,
	ARRAY_SIZE(msm_i2c_backlight_info),
};

void __init i2c_register_backlight_info(void){
	i2c_register_board_info(backlight_device.bus,
							backlight_device.info,
							backlight_device.len);
}

void __init msm_panel_init(void){
	platform_add_devices(panel_devices, ARRAY_SIZE(panel_devices));
}

#if !defined(CONFIG_GPIO_SX150X) && !defined(CONFIG_GPIO_SX150X_MODULE)
static inline void display_common_power(int on) {}
#endif

#ifdef CONFIG_FB_MSM_HDMI_MSM_PANEL
#define _GET_REGULATOR(var, name) do {				\
	var = regulator_get(NULL, name);			\
	if (IS_ERR(var)) {					\
		pr_err("'%s' regulator not found, rc=%ld\n",	\
			name, IS_ERR(var));			\
		var = NULL;					\
		return -ENODEV;					\
	}							\
} while (0)

static int hdmi_enable_5v(int on)
{
	static struct regulator *reg_8901_hdmi_mvs;	/* HDMI_5V */
	static struct regulator *reg_8901_mpp0;		/* External 5V */
	static int prev_on;
	int rc;

	if (on == prev_on)
		return 0;

	if (!reg_8901_hdmi_mvs)
		_GET_REGULATOR(reg_8901_hdmi_mvs, "8901_hdmi_mvs");
	if (!reg_8901_mpp0)
		_GET_REGULATOR(reg_8901_mpp0, "8901_mpp0");

	if (on) {
		rc = regulator_enable(reg_8901_mpp0);
		if (rc) {
			pr_err("'%s' regulator enable failed, rc=%d\n",
				"reg_8901_mpp0", rc);
			return rc;
		}
		rc = regulator_enable(reg_8901_hdmi_mvs);
		if (rc) {
			pr_err("'%s' regulator enable failed, rc=%d\n",
				"8901_hdmi_mvs", rc);
			return rc;
		}
		pr_info("%s(on): success\n", __func__);
	} else {
		rc = regulator_disable(reg_8901_hdmi_mvs);
		if (rc)
			pr_warning("'%s' regulator disable failed, rc=%d\n",
				"8901_hdmi_mvs", rc);
		rc = regulator_disable(reg_8901_mpp0);
		if (rc)
			pr_warning("'%s' regulator disable failed, rc=%d\n",
				"reg_8901_mpp0", rc);
		pr_info("%s(off): success\n", __func__);
	}

	prev_on = on;

	return 0;
}

static int hdmi_core_power(int on, int show)
{
	static struct regulator *reg_8058_l16;		/* VDD_HDMI */
	static int prev_on;
	int rc;

	if (on == prev_on)
		return 0;

	if (!reg_8058_l16)
		_GET_REGULATOR(reg_8058_l16, "8058_l16");

	if (on) {
		rc = regulator_set_voltage(reg_8058_l16, 1800000, 1800000);
		if (!rc)
			rc = regulator_enable(reg_8058_l16);
		if (rc) {
			pr_err("'%s' regulator enable failed, rc=%d\n",
				"8058_l16", rc);
			return rc;
		}
		rc = gpio_request(170, "HDMI_DDC_CLK");
		if (rc) {
			pr_err("'%s'(%d) gpio_request failed, rc=%d\n",
				"HDMI_DDC_CLK", 170, rc);
			goto error1;
		}
		rc = gpio_request(171, "HDMI_DDC_DATA");
		if (rc) {
			pr_err("'%s'(%d) gpio_request failed, rc=%d\n",
				"HDMI_DDC_DATA", 171, rc);
			goto error2;
		}
		rc = gpio_request(172, "HDMI_HPD");
		if (rc) {
			pr_err("'%s'(%d) gpio_request failed, rc=%d\n",
				"HDMI_HPD", 172, rc);
			goto error3;
		}
		pr_info("%s(on): success\n", __func__);
	} else {
		gpio_free(170);
		gpio_free(171);
		gpio_free(172);
		rc = regulator_disable(reg_8058_l16);
		if (rc)
			pr_warning("'%s' regulator disable failed, rc=%d\n",
				"8058_l16", rc);
		pr_info("%s(off): success\n", __func__);
	}

	prev_on = on;

	return 0;

error3:
	gpio_free(171);
error2:
	gpio_free(170);
error1:
	regulator_disable(reg_8058_l16);
	return rc;
}

static int hdmi_cec_power(int on)
{
	static struct regulator *reg_8901_l3;		/* HDMI_CEC */
	static int prev_on;
	int rc;

	if (on == prev_on)
		return 0;

	if (!reg_8901_l3)
		_GET_REGULATOR(reg_8901_l3, "8901_l3");

	if (on) {
		rc = regulator_set_voltage(reg_8901_l3, 3300000, 3300000);
		if (!rc)
			rc = regulator_enable(reg_8901_l3);
		if (rc) {
			pr_err("'%s' regulator enable failed, rc=%d\n",
				"8901_l3", rc);
			return rc;
		}
		rc = gpio_request(169, "HDMI_CEC_VAR");
		if (rc) {
			pr_err("'%s'(%d) gpio_request failed, rc=%d\n",
				"HDMI_CEC_VAR", 169, rc);
			goto error;
		}
		pr_info("%s(on): success\n", __func__);
	} else {
		gpio_free(169);
		rc = regulator_disable(reg_8901_l3);
		if (rc)
			pr_warning("'%s' regulator disable failed, rc=%d\n",
				"8901_l3", rc);
		pr_info("%s(off): success\n", __func__);
	}

	prev_on = on;

	return 0;
error:
	regulator_disable(reg_8901_l3);
	return rc;
}

#undef _GET_REGULATOR

#endif /* CONFIG_FB_MSM_HDMI_MSM_PANEL */

#ifdef CONFIG_MSM_BUS_SCALING
static struct msm_bus_vectors mdp_init_vectors[] = {
	/* For now, 0th array entry is reserved.
	 * Please leave 0 as is and don't use it
	 */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 0,
		.ib = 0,
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};

static struct msm_bus_vectors mdp_sd_smi_vectors[] = {
	/* Default case static display/UI/2d/3d if FB SMI */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 175110000,
		.ib = 218887500,	
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};

static struct msm_bus_vectors mdp_sd_ebi_vectors[] = {
	/* Default case static display/UI/2d/3d if FB SMI */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 0,
		.ib = 0,
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 334080000,   
		.ib = 417600000 * 2,	
	},
};
static struct msm_bus_vectors mdp_vga_vectors[] = {
	/* VGA and less video */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,	
		.ab = 216000000,
		.ib = 270000000, //270000000 * 2,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 216000000,
		.ib = 270000000 * 2,
	},
};

static struct msm_bus_vectors mdp_720p_vectors[] = {
	/* 720p and less video */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 230400000,
		.ib = 288000000, //288000000 * 2,
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,	
		.ab = 230400000,
		.ib = 288000000 * 2,
	},
};

static struct msm_bus_vectors mdp_1080p_vectors[] = {
	/* 1080p and less video */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 334080000,
		.ib = 417600000, //417600000 * 2,
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 334080000,
		.ib = 550000000 * 2,
	},
};

static struct msm_bus_paths mdp_bus_scale_usecases[] = {
	{
		ARRAY_SIZE(mdp_init_vectors),
		mdp_init_vectors,
	},
	{
		ARRAY_SIZE(mdp_sd_smi_vectors),
		mdp_sd_smi_vectors,
	},
	{
		ARRAY_SIZE(mdp_sd_ebi_vectors),
		mdp_sd_ebi_vectors,
	},
	{
		ARRAY_SIZE(mdp_vga_vectors),
		mdp_vga_vectors,
	},
	{
		ARRAY_SIZE(mdp_720p_vectors),
		mdp_720p_vectors,
	},
	{
		ARRAY_SIZE(mdp_1080p_vectors),
		mdp_1080p_vectors,
	},
};
static struct msm_bus_scale_pdata mdp_bus_scale_pdata = {
	mdp_bus_scale_usecases,
	ARRAY_SIZE(mdp_bus_scale_usecases),
	.name = "mdp",
};

#endif
#ifdef CONFIG_MSM_BUS_SCALING
static struct msm_bus_vectors dtv_bus_init_vectors[] = {
	/* For now, 0th array entry is reserved.
	 * Please leave 0 as is and don't use it
	 */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 0,
		.ib = 0,
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};
static struct msm_bus_vectors dtv_bus_def_vectors[] = {
	/* For now, 0th array entry is reserved.
	 * Please leave 0 as is and don't use it
	 */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 566092800,
		.ib = 707616000,
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 566092800,
		.ib = 707616000,
	},
};
static struct msm_bus_paths dtv_bus_scale_usecases[] = {
	{
		ARRAY_SIZE(dtv_bus_init_vectors),
		dtv_bus_init_vectors,
	},
	{
		ARRAY_SIZE(dtv_bus_def_vectors),
		dtv_bus_def_vectors,
	},
};
static struct msm_bus_scale_pdata dtv_bus_scale_pdata = {
	dtv_bus_scale_usecases,
	ARRAY_SIZE(dtv_bus_scale_usecases),
	.name = "dtv",
};

static struct lcdc_platform_data dtv_pdata = {
	.bus_scale_table = &dtv_bus_scale_pdata,
};
#endif



#ifdef CONFIG_FB_MSM_TVOUT
static struct regulator *reg_8058_l13;

static int atv_dac_power(int on)
{
	int rc = 0;
	#define _GET_REGULATOR(var, name) do {				\
		var = regulator_get(NULL, name);			\
		if (IS_ERR(var)) {					\
			pr_info("'%s' regulator not found, rc=%ld\n",	\
				name, IS_ERR(var));			\
			var = NULL;					\
			return -ENODEV;					\
		}							\
	} while (0)

	if (!reg_8058_l13)
		_GET_REGULATOR(reg_8058_l13, "8058_l13");
	#undef _GET_REGULATOR

	if (on) {
		rc = regulator_set_voltage(reg_8058_l13, 2050000, 2050000);
		if (rc) {
			pr_info("%s: '%s' regulator set voltage failed,\
				rc=%d\n", __func__, "8058_l13", rc);
			return rc;
		}

		rc = regulator_enable(reg_8058_l13);
		if (rc) {
			pr_err("%s: '%s' regulator enable failed,\
				rc=%d\n", __func__, "8058_l13", rc);
			return rc;
		}
	} else {
		rc = regulator_force_disable(reg_8058_l13);
		if (rc)
			pr_warning("%s: '%s' regulator disable failed, rc=%d\n",
				__func__, "8058_l13", rc);
	}
	return rc;

}
#endif

#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT) || defined(CONFIG_LGE_DISPLAY_MIPI_LGD_CMD_WVGA_PT)
int mdp_core_clk_rate_table[] = {
	200000000,
	200000000,
	200000000,
	200000000,
};
#else
int mdp_core_clk_rate_table[] = {
	128000000,
	128000000,
	128000000,
	200000000,
	200000000,
};
#endif

static struct msm_panel_common_pdata mdp_pdata = {
	//.gpio = MDP_VSYNC_GPIO,
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT) || defined(CONFIG_LGE_DISPLAY_MIPI_LGD_CMD_WVGA_PT)
	.mdp_core_clk_rate = 200000000,
#else
	.mdp_core_clk_rate = 128000000,
#endif
	.mdp_core_clk_table = mdp_core_clk_rate_table,
	.num_mdp_clk = ARRAY_SIZE(mdp_core_clk_rate_table),
#ifdef CONFIG_MSM_BUS_SCALING
	.mdp_bus_scale_table = &mdp_bus_scale_pdata,
#endif
};

#ifdef CONFIG_FB_MSM_TVOUT

#ifdef CONFIG_MSM_BUS_SCALING
static struct msm_bus_vectors atv_bus_init_vectors[] = {
	/* For now, 0th array entry is reserved.
	 * Please leave 0 as is and don't use it
	 */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 0,
		.ib = 0,
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};
static struct msm_bus_vectors atv_bus_def_vectors[] = {
	/* For now, 0th array entry is reserved.
	 * Please leave 0 as is and don't use it
	 */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 236390400,
		.ib = 265939200,
	},
	/* Master and slaves can be from different fabrics */
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 236390400,
		.ib = 265939200,
	},
};
static struct msm_bus_paths atv_bus_scale_usecases[] = {
	{
		ARRAY_SIZE(atv_bus_init_vectors),
		atv_bus_init_vectors,
	},
	{
		ARRAY_SIZE(atv_bus_def_vectors),
		atv_bus_def_vectors,
	},
};
static struct msm_bus_scale_pdata atv_bus_scale_pdata = {
	atv_bus_scale_usecases,
	ARRAY_SIZE(atv_bus_scale_usecases),
	.name = "atv",
};
#endif

static struct tvenc_platform_data atv_pdata = {
	.poll		 = 0,
	.pm_vid_en	 = atv_dac_power,
#ifdef CONFIG_MSM_BUS_SCALING
	.bus_scale_table = &atv_bus_scale_pdata,
#endif
};
#endif

void __init msm_fb_add_devices(void)
{
	msm_fb_register_device("mdp", &mdp_pdata); 
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT) || defined(CONFIG_LGE_DISPLAY_MIPI_LGD_CMD_WVGA_PT)
	msm_fb_register_device("mipi_dsi", &mipi_pdata);
#endif
#ifdef CONFIG_MSM_BUS_SCALING
	msm_fb_register_device("dtv", &dtv_pdata);
#endif
#ifdef CONFIG_FB_MSM_TVOUT
	msm_fb_register_device("tvenc", &atv_pdata);
	msm_fb_register_device("tvout_device", NULL);
#endif
}
