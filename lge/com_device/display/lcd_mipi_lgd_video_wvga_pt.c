
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
#include "lcd_mipi_lgd.h"

//#define DSI_BIT_CLK_500MHZ
//#define DSI_BIT_CLK_400MHZ
//#define DSI_BIT_CLK_300MHZ
#define DSI_BIT_CLK_333MHZ

static struct msm_panel_info pinfo;

static struct mipi_dsi_phy_ctrl dsi_video_mode_phy_db = {
		// 2 lane, RGB888
		{0x03, 0x01, 0x01, 0x00},		// regulator 
		{0x66, 0x26, 0x15, 0x00, 0x17, 0x8c, 0x1e,0x8b, 0x17, 0x03, 0x04}, 	// timing 
		{0x7f, 0x00, 0x00, 0x00},		// phy ctrl 
		{0xee, 0x03, 0x86, 0x03},		// strength 
		#if defined(DSI_BIT_CLK_300MHZ)
		{0x41, 0x2B, 0x31, 0xDA, 0x00, 0x50, 0x48, 0x63, // pll control 
		#endif
		#if defined(DSI_BIT_CLK_333MHZ)
		{0x41, 0x4C, 0x31, 0xDA, 0x00, 0x50, 0x48, 0x63, // pll control 
		#endif
		#if defined(DSI_BIT_CLK_400MHZ)
		{0x41, 0x87, 0x31, 0xDA, 0x00, 0x50, 0x48, 0x63, // pll control 
		#endif
		#if defined(DSI_BIT_CLK_500MHZ)
		{0x40, 0xf9, 0xb0, 0xda, 0x00, 0x50, 0x48, 0x63, // pll control 
		#endif		
		 0x31, 0x0f, 0x07, 0x05, 0x14, 0x03, 0x03, 0x03,
		 0x54, 0x06, 0x10, 0x04, 0x03},
};

static int __init mipi_video_lgd_wvga_pt_init(void)
{
	int ret;

#ifdef CONFIG_FB_MSM_MIPI_PANEL_DETECT
	if (msm_fb_detect_client("mipi_wvga_lgd_wvga"))
		return 0;
#endif
	pinfo.xres = 480;
	pinfo.yres = 800;
	pinfo.type = MIPI_VIDEO_PANEL;
	pinfo.pdest = DISPLAY_1;
	pinfo.wait_cycle = 0;
	pinfo.bpp = 24;
	pinfo.lcdc.h_back_porch = 64;//64;//80;//16;
	pinfo.lcdc.h_front_porch = 2;//48;//16;
	pinfo.lcdc.h_pulse_width = 1;//32;//10;
	pinfo.lcdc.v_back_porch = 15;//2;//8;
	pinfo.lcdc.v_front_porch = 5;//8;
	pinfo.lcdc.v_pulse_width = 3;//5;
	pinfo.lcdc.border_clr = 0;	/* blk */
	pinfo.lcdc.underflow_clr = 0xff;	/* blue */
	pinfo.lcdc.hsync_skew = 0;
	pinfo.bl_max = 128;
	pinfo.bl_min = 1;
	pinfo.fb_num = 1;

	pinfo.mipi.mode = DSI_VIDEO_MODE;
	pinfo.mipi.pulse_mode_hsa_he = FALSE;
	pinfo.mipi.hfp_power_stop = FALSE;
	pinfo.mipi.hbp_power_stop = FALSE;
	pinfo.mipi.hsa_power_stop = FALSE;
	pinfo.mipi.eof_bllp_power_stop = TRUE;
	pinfo.mipi.bllp_power_stop = FALSE;
	pinfo.mipi.traffic_mode = DSI_NON_BURST_SYNCH_EVENT;
	pinfo.mipi.dst_format = DSI_VIDEO_DST_FORMAT_RGB888;
	pinfo.mipi.vc = 0;
	pinfo.mipi.rgb_swap = DSI_RGB_SWAP_BGR;
	pinfo.mipi.data_lane0 = TRUE;
	pinfo.mipi.data_lane1 = TRUE;
	pinfo.mipi.data_lane2 = FALSE;
	pinfo.mipi.data_lane3 = FALSE;

	pinfo.mipi.t_clk_post = 34;//0x22;
	pinfo.mipi.t_clk_pre = 51;//0x32;//0x35
	pinfo.mipi.frame_rate = 62;
	pinfo.clk_rate = 300000000;//285
	pinfo.mipi.stream = 0; /* dma_p */
	pinfo.mipi.mdp_trigger = DSI_CMD_TRIGGER_SW;
	pinfo.mipi.dma_trigger = DSI_CMD_TRIGGER_SW;
//	pinfo.mipi.interleave_max = 1;
//	pinfo.mipi.wr_mem_continue = 0x3c;
//	pinfo.mipi.wr_mem_start = 0x2c;
	pinfo.mipi.dsi_phy_db = &dsi_video_mode_phy_db;

	ret = mipi_lgd_device_register(&pinfo, MIPI_DSI_PRIM,
						MIPI_DSI_PANEL_WVGA_PT);
	if (ret)
		printk(KERN_ERR "%s: failed to register device!\n", __func__);

	return ret;
}

module_init(mipi_video_lgd_wvga_pt_init);
