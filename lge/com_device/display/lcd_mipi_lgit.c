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
#include "lcd_mipi_lgit.h"
#include <linux/gpio.h>

#include <mach/board_lge.h>

#define LGIT_IEF
#define LGIT_CABC
#define LGIT_IEF_SWITCH

#ifdef LGIT_IEF_SWITCH
struct msm_fb_data_type *local_mfd0 = NULL;
static int is_ief_on = 1;
#endif

static struct msm_panel_common_pdata *mipi_lgit_pdata;

static struct dsi_buf lgit_tx_buf;
static struct dsi_buf lgit_rx_buf;

#define LCD_RESET_N	50

static char dsi_config    [6] = {0xE0, 0x43, 0x00, 0x80, 0x00, 0x00};
static char display_mode1 [6] = {0xB5, 0x29, 0x20, 0x40, 0x00, 0x20};
static char display_mode2 [6] = {0xB6, 0x01, 0x14, 0x0F, 0x16, 0x13};

static char p_gamma_r_setting[10] = {0xD0, 0x00, 0x30, 0x56, 0x01, 0x12, 0x04, 0x34, 0x10, 0x01};
static char n_gamma_r_setting[10] = {0xD1, 0x02, 0x51, 0x56, 0x06, 0x08, 0x00, 0x47, 0x12, 0x02};
static char p_gamma_g_setting[10] = {0xD2, 0x00, 0x30, 0x56, 0x01, 0x12, 0x04, 0x34, 0x10, 0x01};
static char n_gamma_g_setting[10] = {0xD3, 0x02, 0x51, 0x56, 0x06, 0x08, 0x00, 0x47, 0x12, 0x02};
static char p_gamma_b_setting[10] = {0xD4, 0x00, 0x30, 0x56, 0x01, 0x12, 0x04, 0x34, 0x10, 0x01};
static char n_gamma_b_setting[10] = {0xD5, 0x02, 0x51, 0x56, 0x06, 0x08, 0x00, 0x47, 0x12, 0x02};

static char p_gamma_r_setting_2P5[10] = {0xD0, 0x00, 0x11, 0x77, 0x23, 0x16, 0x06, 0x62, 0x41, 0x03};
static char n_gamma_r_setting_2P5[10] = {0xD1, 0x00, 0x14, 0x63, 0x23, 0x08, 0x06, 0x41, 0x33, 0x04};
static char p_gamma_g_setting_2P5[10] = {0xD2, 0x00, 0x11, 0x77, 0x23, 0x16, 0x06, 0x62, 0x41, 0x03};
static char n_gamma_g_setting_2P5[10] = {0xD3, 0x00, 0x14, 0x63, 0x23, 0x08, 0x06, 0x41, 0x33, 0x04};
static char p_gamma_b_setting_2P5[10] = {0xD4, 0x00, 0x11, 0x77, 0x23, 0x16, 0x06, 0x62, 0x41, 0x03};
static char n_gamma_b_setting_2P5[10] = {0xD5, 0x00, 0x14, 0x63, 0x23, 0x08, 0x06, 0x41, 0x33, 0x04};

#ifdef LGIT_IEF
static char ief_set0[2] = {0x70, 0x0F}; //{0x70, 0x07};
static char ief_set1[5] = {0x71, 0x00, 0x00, 0x01, 0x01};
static char ief_set2[3] = {0x72, 0x01, 0x0F};
static char ief_set3[4] = {0x73, 0x34, 0x52, 0x00};
static char ief_set4[4] = {0x74, 0x04, 0x01, 0x07}; //{0x74, 0x04, 0x01, 0x00};
static char ief_set5[4] = {0x75, 0x03, 0x0F, 0x07}; //{0x75, 0x03, 0x0F, 0x00};
static char ief_set6[4] = {0x76, 0x07, 0x00, 0x05}; //{0x76, 0x07, 0x00, 0x04};
static char ief_set7[9] = {0x77, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D}; //{0x77, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40};
static char ief_set8[9] = {0x78, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39}; //{0x78, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C};  //new: for I-pjt LCD tunning.;
static char ief_set9[9] = {0x79, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40};//{0x79, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40};
static char ief_setA[9] = {0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static char ief_setB[9] = {0x7B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static char ief_setC[9] = {0x7C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//camera mode
#ifdef LGIT_IEF_SWITCH
static char ief_set10[2] = {0x70, 0x0A};
static char ief_set16[4] = {0x76, 0x00, 0x00, 0x00};   
static char ief_set15[4] = {0x75, 0x00, 0x00, 0x00}; 
static char ief_set14[4] = {0x74, 0x00, 0x00, 0x00};
#endif /* LGIT_IEF_SWITCH*/
#endif

#if defined(LGIT_CABC)
static char cabc_set0[2] = {0x51, 0xFF};
static char cabc_set1[2] = {0x5E, 0xE8};
static char cabc_set2[2] = {0x53, 0x2C};
static char cabc_set3[2] = {0x55, 0x01};
static char cabc_set4[5] = {0xC8, 0x22, 0xE3, 0x01, 0x11};
#endif

static char osc_setting[3] =     {0xC0, 0x00, 0x00};
static char osc_setting_2P5[3] =     {0xC0, 0x01, 0x04}; // Enable Internal Oscillator / expected Freq 900KHz

/*shoogi.lee@lge.com 2011.03.31, Modify code to apply final vlaue*/
static char power_setting1[2] = {0xC1, 0x00};
static char power_setting2_1[2] = {0xC2, 0x02};
static char power_setting2_2[2] = {0xC2, 0x06};
static char power_setting2_3[2] = {0xC2, 0x4E};
static char power_setting_7[4] = {0xC7, 0x10, 0x00, 0x14};

static char power_setting3[10] = {0xC3, 0x00, 0x08, 0x00, 0x00, 0x00, 0x67, 0x88, 0x32, 0x00};
static char power_setting4[6] =  {0xC4, 0x22, 0x24, 0x19, 0x19, 0x41};
static char power_setting3_2P3[10] = {0xC3, 0x00, 0x09, 0x00, 0x00, 0x00, 0x66, 0x88, 0x32, 0x00};
static char power_setting4_2P3[6] =  {0xC4, 0x22, 0x24, 0x18, 0x18, 0x47};
static char power_setting3_2P5[10] = {0xC3, 0x00, 0x09, 0x10, 0x12, 0x00, 0x66, 0x20, 0x31, 0x00};
static char power_setting4_2P5[6] =  {0xC4, 0x22, 0x24, 0x18, 0x18, 0x47};

static char otp2_setting[2] =    {0XF9, 0x00};
static char otp2_setting2[2] =    {0XF9, 0x80};

static char exit_sleep[2] =  {0x11,0x00};
static char display_on[2] =  {0x29,0x00};
static char enter_sleep[2] = {0x10,0x00};
static char display_off[2] = {0x28,0x00};
static char power_setting2_4[2] = {0xC2,0x00};
static char power_setting4_1[6] = {0xC4,0x00,0x00,0x00,0x00,0x00};
static char deep_standby_1[2] = {0xC1,0x02};
static char deep_standby_2[2] = {0xC1,0x03};

/* initialize device */
static struct dsi_cmd_desc lgit_power_on_set[] = {
	// Display Initial Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(dsi_config    ),dsi_config   },
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_mode1 ),display_mode1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_mode2 ),display_mode2},

	// Gamma Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_r_setting),p_gamma_r_setting},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_r_setting),n_gamma_r_setting},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_g_setting),p_gamma_g_setting},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_g_setting),n_gamma_g_setting},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_b_setting),p_gamma_b_setting},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_b_setting),n_gamma_b_setting},

#if defined(LGIT_IEF)
	// Image Enhancement Function Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set0),ief_set0},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set1),ief_set1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set2),ief_set2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set3),ief_set3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set4),ief_set4},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set5),ief_set5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set6),ief_set6},	
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set7),ief_set7},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set8),ief_set8},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set9),ief_set9},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setA),ief_setA},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setB),ief_setB},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setC),ief_setC},
#endif

#if defined(LGIT_CABC)
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set0),cabc_set0},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set1),cabc_set1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set2),cabc_set2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set3),cabc_set3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set4),cabc_set4},
#endif

	// Power Supply Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(osc_setting   ),osc_setting   }, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting3),power_setting3}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting4),power_setting4}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(otp2_setting  ),otp2_setting  }, 
	{DTYPE_DCS_WRITE,  1, 0, 0, 0, sizeof(exit_sleep	),exit_sleep	},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting1),power_setting1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 20, sizeof(power_setting2_1),power_setting2_1}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 20, sizeof(power_setting2_2),power_setting2_2}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 100, sizeof(power_setting2_3),power_setting2_3}, 
	{DTYPE_DCS_WRITE,  1, 0, 0, 0, sizeof(exit_sleep	),exit_sleep	},
//	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(otp2_setting2  ),otp2_setting2  }, 
	{DTYPE_DCS_WRITE,  1, 0, 0, 0, sizeof(display_on	),display_on	},
};

static struct dsi_cmd_desc lgit_power_on_set_2P3[] = {
	// Display Initial Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(dsi_config    ),dsi_config   },
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_mode1 ),display_mode1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_mode2 ),display_mode2},

	// Gamma Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_r_setting_2P5),p_gamma_r_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_r_setting_2P5),n_gamma_r_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_g_setting_2P5),p_gamma_g_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_g_setting_2P5),n_gamma_g_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_b_setting_2P5),p_gamma_b_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_b_setting_2P5),n_gamma_b_setting_2P5},

#if defined(LGIT_IEF)
	// Image Enhancement Function Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set0),ief_set0},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set1),ief_set1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set2),ief_set2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set3),ief_set3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set4),ief_set4},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set5),ief_set5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set6),ief_set6},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set7),ief_set7},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set8),ief_set8},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set9),ief_set9},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setA),ief_setA},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setB),ief_setB},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setC),ief_setC},
#endif

#if defined(LGIT_CABC)
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set0),cabc_set0},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set1),cabc_set1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set2),cabc_set2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set3),cabc_set3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set4),cabc_set4},
#endif

	// Power Supply Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(osc_setting   ),osc_setting   }, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting3_2P3),power_setting3_2P3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting4_2P3),power_setting4_2P3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(otp2_setting  ),otp2_setting  }, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting1),power_setting1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(power_setting2_1),power_setting2_1}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(power_setting2_2),power_setting2_2}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(power_setting2_3),power_setting2_3}, 
	{DTYPE_DCS_WRITE,  1, 0, 0, 10, sizeof(exit_sleep	),exit_sleep	},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(otp2_setting2  ),otp2_setting2  }, 
	{DTYPE_DCS_WRITE,  1, 0, 0, 0, sizeof(display_on	),display_on	},
};


static struct dsi_cmd_desc lgit_power_on_set_2P5[] = {
	// Display Initial Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(dsi_config    ),dsi_config   },
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_mode1 ),display_mode1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_mode2 ),display_mode2},

	// Gamma Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_r_setting_2P5),p_gamma_r_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_r_setting_2P5),n_gamma_r_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_g_setting_2P5),p_gamma_g_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_g_setting_2P5),n_gamma_g_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(p_gamma_b_setting_2P5),p_gamma_b_setting_2P5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(n_gamma_b_setting_2P5),n_gamma_b_setting_2P5},

#if defined(LGIT_IEF)
	// Image Enhancement Function Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set0),ief_set0},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set1),ief_set1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set2),ief_set2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set3),ief_set3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set4),ief_set4},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set5),ief_set5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set6),ief_set6},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set7),ief_set7},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set8),ief_set8},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set9),ief_set9},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setA),ief_setA},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setB),ief_setB},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_setC),ief_setC},
#endif

#if defined(LGIT_CABC)
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set0),cabc_set0},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set1),cabc_set1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set2),cabc_set2},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set3),cabc_set3},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(cabc_set4),cabc_set4},
#endif

	// Power Supply Set
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(osc_setting_2P5   ),osc_setting_2P5   }, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting3_2P5),power_setting3_2P5}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting4_2P5),power_setting4_2P5}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting_7),power_setting_7},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(otp2_setting  ),otp2_setting  }, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(power_setting1),power_setting1},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(power_setting2_1),power_setting2_1}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(power_setting2_2),power_setting2_2}, 
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(power_setting2_3),power_setting2_3}, 
	{DTYPE_DCS_WRITE,  1, 0, 0, 10, sizeof(exit_sleep	),exit_sleep	},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 10, sizeof(otp2_setting2  ),otp2_setting2  }, 
	{DTYPE_DCS_WRITE,  1, 0, 0, 0, sizeof(display_on	),display_on	},
};

static struct dsi_cmd_desc lgit_power_off_set[] = {
  {DTYPE_DCS_WRITE, 1, 0, 0, 0, sizeof(display_off), display_off},
  {DTYPE_DCS_WRITE, 1, 0, 0, 0, sizeof(enter_sleep), enter_sleep},
  {DTYPE_DCS_WRITE, 1, 0, 0, 0, sizeof(power_setting2_4), power_setting2_4},
  {DTYPE_DCS_WRITE, 1, 0, 0, 20, sizeof(power_setting4_1), power_setting4_1},
  {DTYPE_DCS_WRITE, 1, 0, 0, 20, sizeof(deep_standby_1), deep_standby_1},
  {DTYPE_DCS_WRITE, 1, 0, 0, 20, sizeof(deep_standby_2), deep_standby_2},
};

#ifdef LGIT_IEF_SWITCH
static struct dsi_cmd_desc lgit_power_on_set_camera[] = {		
// Image Enhancement Function Set
//	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_off),display_off},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set10),ief_set10},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set16),ief_set16},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set15),ief_set15},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set14),ief_set14},
//	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_on),display_on},
};

static struct dsi_cmd_desc lgit_power_off_set_camera[] = {	
	// Image Enhancement Function Set
//	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_off),display_off},		
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set0),ief_set0},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set6),ief_set6},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set5),ief_set5},
	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(ief_set4),ief_set4},
//	{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(display_on),display_on},
};

extern int mipi_lgit_lcd_ief_off(void)
{
	if(local_mfd0->panel_power_on && is_ief_on) {	
		mutex_lock(&local_mfd0->dma->ov_mutex);
		MIPI_OUTP(MIPI_DSI_BASE + 0x38, 0x10000000); //HS mode
		mipi_dsi_cmds_tx(local_mfd0, &lgit_tx_buf, lgit_power_on_set_camera, ARRAY_SIZE(lgit_power_on_set_camera));
		is_ief_on = 0;
		printk("%s, %d\n", __func__,is_ief_on);
		MIPI_OUTP(MIPI_DSI_BASE + 0x38, 0x14000000);
		mutex_unlock(&local_mfd0->dma->ov_mutex);
	}
                                                                                         
	return 0;
} 
EXPORT_SYMBOL(mipi_lgit_lcd_ief_off);

extern int mipi_lgit_lcd_ief_on(void)
{	
	if(local_mfd0->panel_power_on && !is_ief_on) {

		mutex_lock(&local_mfd0->dma->ov_mutex);
		MIPI_OUTP(MIPI_DSI_BASE + 0x38, 0x10000000);
		mipi_dsi_cmds_tx(local_mfd0, &lgit_tx_buf, lgit_power_off_set_camera, ARRAY_SIZE(lgit_power_off_set_camera)); 
		is_ief_on = 1;
		printk("%s, %d\n", __func__,is_ief_on);
		MIPI_OUTP(MIPI_DSI_BASE + 0x38, 0x14000000);
		mutex_unlock(&local_mfd0->dma->ov_mutex);
	}
                                                              
	return 0;                                                                             
} 
EXPORT_SYMBOL(mipi_lgit_lcd_ief_on);
#endif

void mipi_lgit_lcd_reset(void)
{	
	gpio_tlmm_config(GPIO_CFG(LCD_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
	gpio_set_value(LCD_RESET_N,1);
	mdelay(5);
	gpio_set_value(LCD_RESET_N,0);
    mdelay(5);
    gpio_set_value(LCD_RESET_N,1);
    mdelay(20);
}

extern int lge_bd_rev;

static int mipi_lgit_lcd_on(struct platform_device *pdev)
{
	struct msm_fb_data_type *mfd;
	mfd = platform_get_drvdata(pdev);
	if (!mfd)
		return -ENODEV;
	if (mfd->key != MFD_KEY)
		return -EINVAL;

#ifdef LGIT_IEF_SWITCH
	if(local_mfd0 == NULL)
		local_mfd0 = mfd;
#endif

	printk(KERN_INFO"%s: mipi lgit lcd on started, lge_bd_rev = %d \n", __func__, lge_bd_rev);
	mipi_lgit_lcd_reset();
	//mipi_dsi_op_mode_config(DSI_CMD_MODE);

	//display on each panel
	//This is seperated by HW rev.
	if(lge_bd_rev < LGE_REV_E)
		mipi_dsi_cmds_tx(mfd, &lgit_tx_buf, lgit_power_on_set, ARRAY_SIZE(lgit_power_on_set));
	else {
		if(lge_bd_rev == LGE_REV_E)
			mipi_dsi_cmds_tx(mfd, &lgit_tx_buf, lgit_power_on_set_2P3, ARRAY_SIZE(lgit_power_on_set_2P3));
		else
			mipi_dsi_cmds_tx(mfd, &lgit_tx_buf, lgit_power_on_set_2P5, ARRAY_SIZE(lgit_power_on_set_2P5));
	}
	
//if camera is on
#ifdef LGIT_IEF_SWITCH
	if(!is_ief_on) // if camera is on, turn ief off
		mipi_dsi_cmds_tx(local_mfd0, &lgit_tx_buf, lgit_power_on_set_camera, ARRAY_SIZE(lgit_power_on_set_camera));
#endif

	return 0;
}

static int mipi_lgit_lcd_off(struct platform_device *pdev)
{
	struct msm_fb_data_type *mfd;
	mfd = platform_get_drvdata(pdev);
	if (!mfd)
		return -ENODEV;
	if (mfd->key != MFD_KEY)
		return -EINVAL;

	printk(KERN_INFO"%s: mipi lgit lcd off started \n", __func__);

	//mipi_dsi_op_mode_config(DSI_CMD_MODE);
	mipi_dsi_cmds_tx(mfd, &lgit_tx_buf, lgit_power_off_set, ARRAY_SIZE(lgit_power_off_set));

	gpio_tlmm_config(GPIO_CFG(LCD_RESET_N, 0, GPIO_CFG_OUTPUT, GPIO_CFG_PULL_DOWN, GPIO_CFG_2MA),GPIO_CFG_ENABLE);
	gpio_set_value(LCD_RESET_N,0);

	return 0;
}

static void mipi_lgit_set_backlight_board(struct msm_fb_data_type *mfd) 
{
	int level;	

	level=(int)mfd->bl_level;
	mipi_lgit_pdata->backlight_level(level, 0, 0);
}

static int mipi_lgit_lcd_probe(struct platform_device *pdev)
{
	if (pdev->id == 0) {
		mipi_lgit_pdata = pdev->dev.platform_data;
		return 0;
	}

	printk(KERN_INFO"%s: mipi lgit lcd probe start\n", __func__);

	msm_fb_add_device(pdev);

	return 0;
}

static struct platform_driver this_driver = {
	.probe  = mipi_lgit_lcd_probe,
	.driver = {
		.name   = "mipi_lgit",
	},
};

static struct msm_fb_panel_data lgit_panel_data = {
	.on		= mipi_lgit_lcd_on,
	.off		= mipi_lgit_lcd_off,
	.set_backlight = mipi_lgit_set_backlight_board,
};

static int ch_used[3];

int mipi_lgit_device_register(struct msm_panel_info *pinfo,
					u32 channel, u32 panel)
{
	struct platform_device *pdev = NULL;
	int ret;

	if ((channel >= 3) || ch_used[channel])
		return -ENODEV;

	ch_used[channel] = TRUE;

	pdev = platform_device_alloc("mipi_lgit", (panel << 8)|channel);
	if (!pdev)
		return -ENOMEM;

	lgit_panel_data.panel_info = *pinfo;

	ret = platform_device_add_data(pdev, &lgit_panel_data,
		sizeof(lgit_panel_data));
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

static int __init mipi_lgit_lcd_init(void)
{
	mipi_dsi_buf_alloc(&lgit_tx_buf, DSI_BUF_SIZE);
	mipi_dsi_buf_alloc(&lgit_rx_buf, DSI_BUF_SIZE);

	return platform_driver_register(&this_driver);
}

module_init(mipi_lgit_lcd_init);
