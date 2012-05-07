/* Copyright (c) 2008-2010, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
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

#include "../../../drivers/video/msm/msm_fb.h"
#include "../../../drivers/video/msm/mipi_dsi.h"
#include "lcd_mipi_sharp.h"
#include <linux/gpio.h>

static struct msm_panel_common_pdata *mipi_sharp_pdata;

static struct dsi_buf sharp_tx_buf;
static struct dsi_buf sharp_rx_buf;

char cmd_ctl_test_key2[3] = {0xF1,0x5A,0x5A};
char clo_ctl3[4] = {0xB7,0x00,0x11,0x11};
char interface_select_ctl[3] = {0xB8,0x2B,0x21};
char cmd_disctl_lane[10] = {0xF2,0x00,0x00,0xC8, 0xC8,0x57,0x57,0x10,0x02,0x00};
char cmd_panel_ctl2[18] = {0xF7,0x00,0x01,0x00,0xF2,0x08,0x00,0x08,0x20,0x08,0x07,0x1D,0x00,0x03,0x00,0x4B,0x00,0x8C};
char dsi_pad_ctl[3] = {0xB9,0x00,0x06};
char te_on[2] = {0x35,0x00};
char cmd_ctl_test_key1[3] = {0xF1,0xA5,0xA5};
char column_address_set1[5] = {0x2A,0x00,0x00,0x01,0xDF};
char column_address_set2[5] = {0x2B,0x00,0x00,0x03,0x1F};
char set_manual_brightness[2] = {0x51,0x00};
char turn_on_backlight_ctl[2] = {0x53,0x24};
char mie_mode[2] = {0x55,0x00};
char exit_sleep[2] = {0x11,0x00};
char display_on[2] = {0x29,0x00};

/* initialize device */
static struct dsi_cmd_desc sharp_power_on_set[] = {
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, 3, cmd_ctl_test_key2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, 4, clo_ctl3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, 3, interface_select_ctl},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, 3, dsi_pad_ctl},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, 2, te_on},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, 3, cmd_ctl_test_key1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, 5, column_address_set1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, 5, column_address_set2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 100, 2, mie_mode},

	{DTYPE_DCS_WRITE, 1, 0, 0, 120, 2, exit_sleep},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, sizeof(cmd_ctl_test_key2), cmd_ctl_test_key2}, //level2 command control test key2
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, sizeof(cmd_disctl_lane), cmd_disctl_lane},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, sizeof(cmd_panel_ctl2), cmd_panel_ctl2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 50, sizeof(cmd_ctl_test_key1), cmd_ctl_test_key1}, //level2 command control test key2
	{DTYPE_DCS_WRITE, 1, 0, 0, 50, 2, display_on},

};

char enter_sleep[2] = {0x10,0x00};
char display_off[2] = {0x28,0x00};

static struct dsi_cmd_desc sharp_power_off_set[] = {
	{DTYPE_DCS_WRITE, 1, 0, 0, 0, 2, display_off},
	{DTYPE_DCS_WRITE, 1, 0, 0, 0, 2, enter_sleep}
};

//void mipi_sharp_lcd_reset(void)
//{	
	//gpio_tlmm_config(GPIO_CFG(LCD_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
	
	//gpio_set_value(LCD_RESET_N,1);
	//mdelay(5);
	//gpio_set_value(LCD_RESET_N,0);
    //mdelay(2);
    //gpio_set_value(LCD_RESET_N,1);
    //mdelay(5);
//}

//extern void aat2862_lcd_power_on(void);

//void mipi_sharp_panel_init(void)
//{		
	//aat2862_lcd_power_on();
	//mdelay(100);
//}

static int mipi_sharp_lcd_on(struct platform_device *pdev)
{
	struct msm_fb_data_type *mfd;
	mfd = platform_get_drvdata(pdev);
	if (!mfd)
		return -ENODEV;
	if (mfd->key != MFD_KEY)
		return -EINVAL;

	printk(KERN_INFO"%s: mipi sharp lcd on started \n", __func__);

	mipi_dsi_op_mode_config(DSI_CMD_MODE);
	mipi_dsi_cmds_tx(&sharp_tx_buf, sharp_power_on_set, ARRAY_SIZE(sharp_power_on_set));

	return 0;
}

static int mipi_sharp_lcd_off(struct platform_device *pdev)
{
	struct msm_fb_data_type *mfd;
	mfd = platform_get_drvdata(pdev);
	if (!mfd)
		return -ENODEV;
	if (mfd->key != MFD_KEY)
		return -EINVAL;

	printk(KERN_INFO"%s: mipi sharp lcd off started \n", __func__);
	
	mipi_dsi_op_mode_config(DSI_CMD_MODE);
	mipi_dsi_cmds_tx(&sharp_tx_buf, sharp_power_off_set, ARRAY_SIZE(sharp_power_off_set));

	return 0;
	
}

static void mipi_sharp_set_backlight_board(struct msm_fb_data_type *mfd) 
{
	int level;	

	level=(int)mfd->bl_level;
	mipi_sharp_pdata->backlight_level(level, 0, 0);
}

static int mipi_sharp_lcd_probe(struct platform_device *pdev)
{
	if (pdev->id == 0) {
		mipi_sharp_pdata = pdev->dev.platform_data;
		return 0;
	}

	printk(KERN_INFO"%s: mipi sharp lcd probe start\n", __func__);

	msm_fb_add_device(pdev);

	return 0;
}

static struct platform_driver this_driver = {
	.probe  = mipi_sharp_lcd_probe,
	.driver = {
		.name   = "mipi_sharp",
	},
};

static struct msm_fb_panel_data sharp_panel_data = {
	.on		= mipi_sharp_lcd_on,
	.off		= mipi_sharp_lcd_off,
	.set_backlight = mipi_sharp_set_backlight_board,
};

static int ch_used[3];

int mipi_sharp_device_register(struct msm_panel_info *pinfo,
					u32 channel, u32 panel)
{
	struct platform_device *pdev = NULL;
	int ret;

	if ((channel >= 3) || ch_used[channel])
		return -ENODEV;

	ch_used[channel] = TRUE;

	pdev = platform_device_alloc("mipi_sharp", (panel << 8)|channel);
	if (!pdev)
		return -ENOMEM;

	sharp_panel_data.panel_info = *pinfo;

	ret = platform_device_add_data(pdev, &sharp_panel_data,
		sizeof(sharp_panel_data));
	if (ret) {
		printk(KERN_ERR
		  "%s: platform_device_add_data failed!\n", __func__);
		goto err_device_put;
	}

	ret = platform_device_add(pdev);
	if (ret) {
		printk(KERN_ERR
		  "%s: platform_device_register failed!\n", __func__);
		goto err_device_put;
	}

	return 0;

err_device_put:
	platform_device_put(pdev);
	return ret;
}

static int __init mipi_sharp_lcd_init(void)
{
	mipi_dsi_buf_alloc(&sharp_tx_buf, DSI_BUF_SIZE);
	mipi_dsi_buf_alloc(&sharp_rx_buf, DSI_BUF_SIZE);

	return platform_driver_register(&this_driver);
}

module_init(mipi_sharp_lcd_init);
