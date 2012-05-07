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
#include "lcd_mipi_sharp.h"

static struct msm_panel_info pinfo;

#define DSI_BIT_CLK_366MHZ
static struct mipi_dsi_phy_ctrl dsi_video_mode_phy_db = {
#ifdef DSI_BIT_CLK_490MHZ
	{0x03, 0x01, 0x01, 0x00},	/* regulator */
	/* timing DSIPHY_TIMING_CTRL_0 ~ 10 3 is ommited*/
	{0x66, 0x26, 0x1f, 0x00, 0x23, 0x97, 0x1E, 0x90,
	 0x23, 0x03, 0x04},
	{0x7f, 0x00, 0x00, 0x00},           /* phy ctrl */
	{0xee, 0x03, 0x86, 0x03},           /* strength 0*/
	/* pll control 1~19*/	
	{0x41, 0xe6, 0xb2, 0xf5, 0x00, 0x50, 0x48, 0x63,
	 0x31, 0x0f, 0x07,
	 0x05, 0x14, 0x03, 0x03, 0x03, 0x54, 0x06, 0x10, 0x04, 0x03 },
#elif defined(DSI_BIT_CLK_460MHZ)
	{0x03, 0x01, 0x01, 0x00},	/* regulator */
	/* timing DSIPHY_TIMING_CTRL_0 ~ 10 3 is ommited*/
	{0x66, 0x26, 0x1d, 0x00, 0x21, 0x95, 0x1E, 0x8f,
	 0x21, 0x03, 0x04},
	{0x7f, 0x00, 0x00, 0x00},           /* phy ctrl */
	{0xee, 0x03, 0x86, 0x03},           /* strength 0*/
	/* pll control 1~19*/	
	{0x41, 0xcc, 0xb2, 0xf5, 0x00, 0x50, 0x48, 0x63,
	 0x31, 0x0f, 0x07,
	 0x05, 0x14, 0x03, 0x03, 0x03, 0x54, 0x06, 0x10, 0x04, 0x03 },
#elif defined(DSI_BIT_CLK_366MHZ)
	{0x03, 0x01, 0x01, 0x00},	/* regulator */
	/* timing DSIPHY_TIMING_CTRL_0 ~ 10 3 is ommited*/
	{0x66, 0x26, 0x17, 0x00, 0x1A, 0x8E, 0x1E, 0x8C,
	 0x1A, 0x03, 0x04},
	{0x7f, 0x00, 0x00, 0x00},           /* phy ctrl */
	{0xee, 0x03, 0x86, 0x03},           /* strength 0*/
	/* pll control 1~19*/	
	{0x41, 0x6C, 0xb2, 0xf5, 0x00, 0x50, 0x48, 0x63,
	 0x31, 0x0f, 0x07,
	 0x05, 0x14, 0x03, 0x03, 0x03, 0x54, 0x06, 0x10, 0x04, 0x03 },
#else
	{0x03, 0x01, 0x01, 0x00},          /* regulator */
	/* timing DSIPHY_TIMING_CTRL_0 ~ 10 3 is ommited*/
	{0x50, 0x0f, 0x14, 0x00, 0x19, 0x23, 0x0e, 0x12, 0x16, 0x1b, 0x1c },
	{0x7f, 0x00, 0x00, 0x00},           /* phy ctrl */
	{0xee, 0x86},           /* strength 0*/
	/* pll control 1~19*/	
	{0x41, 0x8f, 0xb1, 0xda, 0x00, 0x50, 0x48, 0x63, 0x33, 0x1f, 0x0f,
	0x05, 0x14, 0x03, 0x03, 0x03, 0x54, 0x06, 0x10, 0x04},
#endif
};

static int __init mipi_video_sharp_wvga_pt_init(void)
{
	int ret;

#ifdef CONFIG_FB_MSM_MIPI_PANEL_DETECT
	if (msm_fb_detect_client("mipi_video_sharp_wvga"))
		return 0;
#endif

	pinfo.xres = 480;
	pinfo.yres = 800;
	pinfo.type = MIPI_VIDEO_PANEL;
	pinfo.pdest = DISPLAY_1;
	pinfo.wait_cycle = 0;
	pinfo.bpp = 24;
	pinfo.lcdc.h_back_porch = 64;//16;
	pinfo.lcdc.h_front_porch = 64;//16;
	pinfo.lcdc.h_pulse_width = 10;//10;
	pinfo.lcdc.v_back_porch = 8;
	pinfo.lcdc.v_front_porch = 8;
	pinfo.lcdc.v_pulse_width = 5;
	pinfo.lcdc.border_clr = 0;	/* blk */
	pinfo.lcdc.underflow_clr = 0xff;	/* blue */
	pinfo.lcdc.hsync_skew = 0;
	pinfo.bl_max = 22;
	pinfo.bl_min = 1;
	pinfo.fb_num = 2;

	pinfo.mipi.mode = DSI_VIDEO_MODE;
	pinfo.mipi.pulse_mode_hsa_he = TRUE;
	pinfo.mipi.hfp_power_stop = TRUE;
	pinfo.mipi.hbp_power_stop = TRUE;
	pinfo.mipi.hsa_power_stop = TRUE;
	pinfo.mipi.eof_bllp_power_stop = TRUE;
	pinfo.mipi.bllp_power_stop = TRUE;
	pinfo.mipi.traffic_mode = DSI_NON_BURST_SYNCH_PULSE;
 	pinfo.mipi.dst_format = DSI_VIDEO_DST_FORMAT_RGB888;
	pinfo.mipi.vc = 0;
	pinfo.mipi.rgb_swap = DSI_RGB_SWAP_BGR;
	pinfo.mipi.data_lane0 = TRUE;
	pinfo.mipi.data_lane1 = TRUE;
	pinfo.mipi.t_clk_post = 0x02;
#if defined(DSI_BIT_CLK_392MHZ)
	pinfo.mipi.t_clk_pre = 0x15;
	pinfo.clk_rate = 392000000;
#elif defined(DSI_BIT_CLK_400MHZ)
	pinfo.mipi.t_clk_pre = 0x14;
	pinfo.clk_rate = 400000000;
#elif defined(DSI_BIT_CLK_450MHZ)
	pinfo.mipi.t_clk_pre = 0x17;
	pinfo.clk_rate = 450000000;
#elif defined(DSI_BIT_CLK_460MHZ)
	pinfo.mipi.t_clk_pre = 0x17;
	pinfo.clk_rate = 460000000;
#endif
	pinfo.mipi.stream = 0; /* dma_p */
	pinfo.mipi.mdp_trigger = DSI_CMD_TRIGGER_SW;
	pinfo.mipi.dma_trigger = DSI_CMD_TRIGGER_SW;
	pinfo.mipi.dsi_phy_db = &dsi_video_mode_phy_db;
	ret = mipi_sharp_device_register(&pinfo, MIPI_DSI_PRIM,
						MIPI_DSI_PANEL_WVGA_PT);
	if (ret)
		printk(KERN_ERR "%s: failed to register device!\n", __func__);

	return ret;
}

module_init(mipi_video_sharp_wvga_pt_init);
