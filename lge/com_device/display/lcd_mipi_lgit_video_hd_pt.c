/* Copyright (c) 2009-2010, Code Aurora Forum. All rights reserved.
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
#include "lcd_mipi_lgit.h"

#define LGIT_IEF

static struct msm_panel_info pinfo;

#define DSI_BIT_CLK_433MHZ
//#define DSI_BIT_CLK_450MHZ
//#define DSI_BIT_CLK_392MHZ

static struct mipi_dsi_phy_ctrl dsi_video_mode_phy_db = {
	/* 720*1280, RGB888, 4 Lane 60 fps video mode */
#if defined(DSI_BIT_CLK_433MHZ)
	{0x03, 0x01, 0x01, 0x00},		/* regulator */
	//{0x66, 0x26, 0x1B, 0x00, 0x1E, 0x93, 0x1E, 0x8E, 0x1E, 0x03, 0x04}, 	/* timing */
	{0x66, 0x26, 0x1C, 0x00, 0x1F, 0x93, 0x1E, 0x8E, 0x1F, 0x03, 0x04}, 	/* timing */
	{0x7f, 0x00, 0x00, 0x00},		/* phy ctrl */
	{0xee, 0x03, 0x86, 0x03},		/* strength */
	{0x41, 0xB0/*0xA7*/, 0x31, 0xDA, 0x00, 0x50, 0x48, 0x63,		 /* pll control */
	 0x31, 0x0f, 0x03, 0x05, 0x14, 0x03, 0x03, 0x03,
	 0x54, 0x06, 0x10, 0x04, 0x03},	
#endif

#if defined(DSI_BIT_CLK_450MHZ)
	{0x03, 0x01, 0x01, 0x00},		/* regulator */
	{0x66, 0x26, 0x1D, 0x00, 0x20, 0x95, 0x1E, 0x8F, 0x20, 0x03, 0x04}, 	/* timing */
	{0x7f, 0x00, 0x00, 0x00},		/* phy ctrl */
	{0xee, 0x03, 0x86, 0x03},		/* strength */
	{0x41, 0xC8, 0x31, 0xDA, 0x00, 0x50, 0x48, 0x63,		 /* pll control */
	 0x31, 0x0f, 0x03, 0x05, 0x14, 0x03, 0x03, 0x03,
	 0x54, 0x06, 0x10, 0x04, 0x03}, 
#endif

#if defined(DSI_BIT_CLK_392MHZ)
	{0x03, 0x01, 0x01, 0x00},		/* regulator */
	{0x66, 0x26, 0x19, 0x00, 0x1C, 0x90, 0x1E, 0x8D, 0x1C, 0x03, 0x04}, 	/* timing */
	{0x7f, 0x00, 0x00, 0x00},		/* phy ctrl */
	{0xee, 0x03, 0x86, 0x03},		/* strength */
	{0x41, 0x87, 0x31, 0xDA, 0x00, 0x50, 0x48, 0x63, 
	 0x31, 0x0f, 0x03, 0x05, 0x14, 0x03, 0x03, 0x03,
	 0x54, 0x06, 0x10, 0x04, 0x03 }, 
#endif
};

static int __init mipi_video_lgit_wvga_pt_init(void)
{
	int ret;

#ifdef CONFIG_FB_MSM_MIPI_PANEL_DETECT
	if (msm_fb_detect_client("mipi_video_lgit_wvga"))
		return 0;
#endif

	pinfo.xres = 720;
	pinfo.yres = 1280;
	pinfo.type = MIPI_VIDEO_PANEL;
	pinfo.pdest = DISPLAY_1;
	pinfo.wait_cycle = 0;
	pinfo.bpp = 24;
	pinfo.lcdc.h_back_porch = 88;
	pinfo.lcdc.h_front_porch = 99;//12;
	pinfo.lcdc.h_pulse_width = 4;
	pinfo.lcdc.v_back_porch = 32;
	pinfo.lcdc.v_front_porch = 8;
	pinfo.lcdc.v_pulse_width = 2;
	pinfo.lcdc.border_clr = 0;	/* blk */
	pinfo.lcdc.underflow_clr = 0xff;	/* blue */
	pinfo.lcdc.hsync_skew = 0;
	pinfo.bl_max = 0x7F;
	pinfo.bl_min = 0;
	pinfo.fb_num = 2;

	pinfo.mipi.mode = DSI_VIDEO_MODE;
	pinfo.mipi.pulse_mode_hsa_he = TRUE;
/* jinho.jang 2011.03.22,  Modify code to apply IEF function */
#if defined(LGIT_IEF)
	pinfo.mipi.hfp_power_stop = FALSE;
	pinfo.mipi.hbp_power_stop = FALSE;
	pinfo.mipi.hsa_power_stop = FALSE;
#else
	pinfo.mipi.hfp_power_stop = TRUE;
	pinfo.mipi.hbp_power_stop = TRUE;
	pinfo.mipi.hsa_power_stop = TRUE;
#endif
	pinfo.mipi.eof_bllp_power_stop = TRUE;
	pinfo.mipi.bllp_power_stop = TRUE;
	pinfo.mipi.traffic_mode = DSI_NON_BURST_SYNCH_PULSE;
 	pinfo.mipi.dst_format = DSI_VIDEO_DST_FORMAT_RGB888;
	pinfo.mipi.vc = 0;
	pinfo.mipi.rgb_swap = DSI_RGB_SWAP_BGR;
	pinfo.mipi.data_lane0 = TRUE;
	pinfo.mipi.data_lane1 = TRUE;
	pinfo.mipi.data_lane2 = TRUE;
	pinfo.mipi.data_lane3 = TRUE;
#if defined(DSI_BIT_CLK_433MHZ)
	pinfo.mipi.t_clk_post = 0x22;
	pinfo.mipi.t_clk_pre = 0x35;
	pinfo.clk_rate = 433560000;
	pinfo.mipi.frame_rate = 60;
#endif /*DSI_BIT_CLK_433MHZ*/

#if defined(DSI_BIT_CLK_450MHZ)
	pinfo.mipi.t_clk_post = 0x22;
	pinfo.mipi.t_clk_pre = 0x36;
	pinfo.clk_rate = 450000000;
	pinfo.mipi.frame_rate = 70;
#endif /*DSI_BIT_CLK_450MHZ*/

#if defined(DSI_BIT_CLK_392MHZ)
	pinfo.mipi.t_clk_post = 0x22;
	pinfo.mipi.t_clk_pre = 0x35;
	pinfo.clk_rate = 400000000;
	pinfo.mipi.frame_rate = 60;
#endif	/*DSI_BIT_CLK_392MHZ*/
	pinfo.mipi.stream = 0; /* dma_p */
	pinfo.mipi.mdp_trigger = DSI_CMD_TRIGGER_SW;
	pinfo.mipi.dma_trigger = DSI_CMD_TRIGGER_SW;
	pinfo.mipi.dsi_phy_db = &dsi_video_mode_phy_db;
	ret = mipi_lgit_device_register(&pinfo, MIPI_DSI_PRIM,
						MIPI_DSI_PANEL_WVGA_PT);
	if (ret)
		printk(KERN_ERR "%s: failed to register device!\n", __func__);

	return ret;
}

module_init(mipi_video_lgit_wvga_pt_init);
