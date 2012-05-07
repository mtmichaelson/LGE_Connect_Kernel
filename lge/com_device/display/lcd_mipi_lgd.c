/*This program is free software; you can redistribute it and/or modify
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
#include "lcd_mipi_lgd.h"
#include <linux/gpio.h>

static struct msm_panel_common_pdata *mipi_lgd_pdata;

static struct dsi_buf lgd_tx_buf;
static struct dsi_buf lgd_rx_buf;

static int is_lcd_power_on = 0;

#define LGIT_CABC
#define LCD_RESET_N	50

// display mode setting
static char display_inversion[] = {0x20,0x00};
static char time_out[] = {0x03, 0x00};
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT)
static char video_switch[] = {0x01, 0x47};
#endif
static char tearing_effect_line_on[] = {0x35,0x00};
static char interface_pixel_format[] = {0x3A, 0x77};
//static char display_control0[] = {0xB1,0x06,0x43,0x0A};
static char panel_characteristics_setting[] = {0xB2, 0x00, 0xC8};
static char panel_drive_setting[] = {0xB3, 0x00};
static char display_mode_control[] = {0xB4, 0x04};
static char display_control1[] = {0xB5, 0x15, 0x10, 0x10, 0x00, 0x20};
static char display_control2[] = {0xB6, 0x0B, 0x0F, 0x3C, 0x13, 0x13, 0xE8};
//static char display_control3[] = {0xB7, 0x48, 0x06, 0x0C, 0x00, 0x00};

// power setting
static char internal_oscillator_setting[] = {0xC0, 0x01, 0x15};
static char power_control3[] = {0xC3, 0x07, 0x03, 0x04, 0x04, 0x04};
static char power_control4[] = {0xC4, 0x12, 0x24, 0x13, 0x13, 0x02, 0x49};
static char power_control5[] = {0xC5, 0x67};
static char power_control6[] = {0xC6, 0x41, 0x63};

#if defined(LGIT_CABC)
static char cabc_set0[] = {0x51, 0xFf};
static char cabc_set1[] = {0x5E, 225};
static char cabc_set2[] = {0x53, 0x2C};
static char cabc_set3[] = {0x55, 0x00};//{0x55, 0x01};
static char cabc_set4[] = {0xC8, 0x22, 0x01};
#endif

// gamma setting
static char positive_gamma_curve_for_red[] = {0xD0, 0x00, 0x07,0x60,0x25,0x07,0x02,0x50,0x26,0x05}; 
static char negative_gamma_curve_for_red[] = {0xD1,  0x00, 0x07,0x60,0x25,0x07,0x02,0x50,0x26,0x05};
static char positive_gamma_curve_for_green[] = {0xD2,0x00, 0x07,0x60,0x25,0x07,0x02,0x50,0x26,0x05};
static char negative_gamma_curve_for_green[] = {0xD3,0x00, 0x07,0x60,0x25,0x07,0x02,0x50,0x26,0x05};
static char positive_gamma_curve_for_blue[] = {0xD4, 0x00, 0x07,0x60,0x25,0x07,0x02,0x50,0x26,0x05};
static char negative_gamma_curve_for_blue[] = {0xD5, 0x00, 0x07,0x60,0x25,0x07,0x02,0x50,0x26,0x05};

static char sleep_out[] = {0x11,0x00};
static char display_on[] = {0x29,0x00};
static char display_off[] = {0x28,0x00};
static char sleep_in[] = {0x10,0x00};
//static char deep_standby_mode_in[] = {0xC1, 0x01};

/* for command mode test */
//static char draw_red_line[] = {0x2C, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00};

static struct dsi_cmd_desc lgd_power_on_set[] = {
// display_mode_setting	
	{DTYPE_GEN_WRITE2, 1, 0, 0, 0, sizeof(time_out), time_out},
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_VIDEO_WVGA_PT)
	{DTYPE_GEN_WRITE2, 1, 0, 0, 0, sizeof(video_switch), video_switch}, 	
#endif
	{DTYPE_DCS_WRITE, 1, 0, 0, 0, sizeof(display_inversion), display_inversion}, 
	{DTYPE_DCS_WRITE, 1, 0, 0, 0, sizeof(tearing_effect_line_on), tearing_effect_line_on}, 
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, sizeof(interface_pixel_format), interface_pixel_format}, 
//	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(display_control0), display_control0}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(panel_characteristics_setting), panel_characteristics_setting}, 
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, sizeof(panel_drive_setting), panel_drive_setting}, 
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, sizeof(display_mode_control), display_mode_control}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(display_control1), display_control1}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(display_control2), display_control2}, 
//  {DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(display_control3), display_control3}, 
// power_setting	
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(internal_oscillator_setting), internal_oscillator_setting}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(power_control3), power_control3}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(power_control4), power_control4}, 
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, sizeof(power_control5), power_control5}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(power_control6), power_control6}, 
#if defined(LGIT_CABC)
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, sizeof(cabc_set0),cabc_set0},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, sizeof(cabc_set1),cabc_set1},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, sizeof(cabc_set2),cabc_set2},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, sizeof(cabc_set3),cabc_set3},
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(cabc_set4),cabc_set4},
#endif
// gamma_setting	
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(positive_gamma_curve_for_red), positive_gamma_curve_for_red}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(negative_gamma_curve_for_red), negative_gamma_curve_for_red}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(positive_gamma_curve_for_green),positive_gamma_curve_for_green}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(negative_gamma_curve_for_green), negative_gamma_curve_for_green}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(positive_gamma_curve_for_blue), positive_gamma_curve_for_blue}, 
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(negative_gamma_curve_for_blue), negative_gamma_curve_for_blue}, 
};

static struct dsi_cmd_desc main_lcd_sleep_in[] = {	
	{DTYPE_DCS_WRITE, 1, 0, 0, 0, sizeof(display_off), display_off}, 
	{DTYPE_DCS_WRITE, 1, 0, 0, 60, sizeof(sleep_in), sleep_in}, 
};

static struct dsi_cmd_desc main_sleep_out[] = {	
	{DTYPE_DCS_WRITE, 1, 0, 0, 0, sizeof(sleep_out), sleep_out}, 
};

static struct dsi_cmd_desc main_display_on[] = {
	{DTYPE_DCS_WRITE, 1, 0, 0, 120, sizeof(display_on), display_on}, 
};

static struct dsi_cmd_desc main_lcd_sleep_out[] = {	
	{DTYPE_DCS_WRITE, 1, 0, 0, 120, sizeof(sleep_out), sleep_out}, 
	{DTYPE_DCS_WRITE, 1, 0, 0, 0, sizeof(display_on), display_on}, 
};
/*
static struct dsi_cmd_desc main_sleep_in[] = {	
	{DTYPE_DCS_WRITE, 1, 0, 0, 50, sizeof(sleep_in), sleep_in}, 
};

static struct dsi_cmd_desc main_deep_standby_in[] = {	
	{DTYPE_DCS_WRITE, 1, 0, 0, 10, sizeof(deep_standby_mode_in), deep_standby_mode_in}, 
};
*/
void mipi_lgd_lcd_reset(void)
{	
	gpio_tlmm_config(GPIO_CFG(LCD_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
	// yong - LCD_RESET pin is same 
	gpio_set_value(LCD_RESET_N,1);
	mdelay(5);
	gpio_set_value(LCD_RESET_N,0);
	mdelay(20);    // yong - wait 20ms 
	gpio_set_value(LCD_RESET_N,1);
	mdelay(10);
}

void mipi_lgd_lcd_reset_pin_off(void)
{
	gpio_tlmm_config(GPIO_CFG(LCD_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
	// yong - LCD_RESET pin is same 
	gpio_set_value(LCD_RESET_N,1);
	mdelay(5);
	gpio_set_value(LCD_RESET_N,0);
	mdelay(20);    // yong - wait 20ms 
}

static int mipi_lgd_lcd_on(struct platform_device *pdev)
{
	struct msm_fb_data_type *mfd;
	mfd = platform_get_drvdata(pdev);
	if (!mfd)
		return -ENODEV;
	if (mfd->key != MFD_KEY)
		return -EINVAL;

	printk(KERN_INFO"%s: mipi lgd lcd on started \n", __func__);
	//mutex_lock(&mfd->dma->ov_mutex);	//block for avoid rocking 3160B merge 
	if(!is_lcd_power_on) {
		mipi_lgd_lcd_reset();	
		// device initialize	
		mipi_dsi_cmds_tx(mfd, &lgd_tx_buf, lgd_power_on_set ,ARRAY_SIZE(lgd_power_on_set));
		mipi_dsi_cmds_tx(mfd, &lgd_tx_buf, main_sleep_out , ARRAY_SIZE(main_sleep_out));
		mipi_dsi_cmds_tx(mfd, &lgd_tx_buf, main_display_on , ARRAY_SIZE(main_display_on));
		is_lcd_power_on = 1;
	}
	else{
		mipi_lgd_lcd_reset();	
		mipi_dsi_cmds_tx(mfd, &lgd_tx_buf, lgd_power_on_set ,ARRAY_SIZE(lgd_power_on_set));
		mipi_dsi_cmds_tx(mfd, &lgd_tx_buf, main_lcd_sleep_out , ARRAY_SIZE(main_lcd_sleep_out));
//		mipi_dsi_cmds_tx(mfd, &lgd_tx_buf, main_lcd_display_on , ARRAY_SIZE(main_lcd_display_on));
	}
	//mutex_unlock(&mfd->dma->ov_mutex);
	return 0;
}

static int mipi_lgd_lcd_off(struct platform_device *pdev)
{
	struct msm_fb_data_type *mfd;
	mfd = platform_get_drvdata(pdev);
	if (!mfd)
		return -ENODEV;
	if (mfd->key != MFD_KEY)
		return -EINVAL;
	
	printk(KERN_INFO"%s: mipi lgd lcd off started \n", __func__); 
	
	mipi_dsi_cmds_tx(mfd,&lgd_tx_buf, main_lcd_sleep_in, ARRAY_SIZE(main_lcd_sleep_in));
//	mipi_dsi_cmds_tx(mfd,&lgd_tx_buf, main_sleep_in, ARRAY_SIZE(main_sleep_in));	
//	mipi_dsi_cmds_tx(mfd,&lgd_tx_buf, main_deep_standby_in, ARRAY_SIZE(main_deep_standby_in));
	mipi_lgd_lcd_reset_pin_off();

	return 0;
}

static void mipi_lgd_set_backlight_board(struct msm_fb_data_type *mfd) 
{
	int level;	

	level=(int)mfd->bl_level;
#if defined(CONFIG_LGE_DISPLAY_MIPI_LGD_CMD_WVGA_PT)
/*----- To avoid block suface Backlight-on move to later than image update   -----*/
#else /* video mode */
	mipi_lgd_pdata->backlight_level(level, 0, 0);
#endif
}

static int mipi_lgd_lcd_probe(struct platform_device *pdev)
{
	if (pdev->id == 0) {
		mipi_lgd_pdata = pdev->dev.platform_data;
		return 0;
	}

	printk(KERN_INFO"%s: mipi lgd lcd probe start\n", __func__);

	msm_fb_add_device(pdev);

	return 0;
}

static struct platform_driver this_driver = {
	.probe  = mipi_lgd_lcd_probe,
	.driver = {
	.name   = "mipi_lgd"
	},
};

static struct msm_fb_panel_data lgd_panel_data = {
	.on		= mipi_lgd_lcd_on,
	.off		= mipi_lgd_lcd_off,
	.set_backlight = mipi_lgd_set_backlight_board,
};

static int ch_used[3];

int mipi_lgd_device_register(struct msm_panel_info *pinfo,
							u32 channel, u32 panel)
{
	struct platform_device *pdev = NULL;
	int ret;

	if ((channel >= 3) || ch_used[channel])
		return -ENODEV;

	ch_used[channel] = TRUE;

	pdev = platform_device_alloc("mipi_lgd", (panel << 8)|channel);
	if (!pdev)
		return -ENOMEM;

	lgd_panel_data.panel_info = *pinfo;
	ret = platform_device_add_data(pdev, &lgd_panel_data,
	sizeof(lgd_panel_data));
	if (ret) {
		printk(KERN_ERR "%s: platform_device_add_data failed!\n", __func__);
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

static int __init mipi_lgd_lcd_init(void)
{
	mipi_dsi_buf_alloc(&lgd_tx_buf, DSI_BUF_SIZE);
	mipi_dsi_buf_alloc(&lgd_rx_buf, DSI_BUF_SIZE);

	return platform_driver_register(&this_driver);
}

module_init(mipi_lgd_lcd_init);


