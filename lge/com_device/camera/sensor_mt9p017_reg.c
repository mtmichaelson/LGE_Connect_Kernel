/* Copyright (c) 2010, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "sensor_mt9p017.h"

struct mt9p017_i2c_reg_conf const pll_tbl[]=
{
	{0x301A, 0x0018},	 //reset_register
	{0x3064, 0xB800},	 //smia_test_2lane_mipi //2011-09-21 miracle.kim@lge.com low temperature entry issue
	{0x31AE, 0x0202},	 //dual_lane_MIPI_interface
	{0x0300, 0x0005},	 //vt_pix_clk_div
	{0x0302, 0x0001},	 //vt_sys_clk_div
	{0x0304, 0x0002},	 //pre_pll_clk_div
	{0x0306, 0x002D},	 //pll_multipler
	{0x0308, 0x000A},	 //op_pix_clk_div
	{0x030A, 0x0001}	 //op_sys_clk_div

};

struct mt9p017_i2c_reg_conf const init_tbl[] =
{
	#if 1	//new setting from Aptina : 2011.12.20
		// Sensor Rev4 Setting 2011.12.21
	{0x316A, 0x8400}, 		// Manufacturer-Specific
	{0x316C, 0x8400},      // Manufacturer-Specific
	{0x316E, 0x8400},      // Manufacturer-Specific
	{0x3EFA, 0x1A1F},      // Manufacturer-Specific
	{0x3ED2, 0xD965},      // Manufacturer-Specific
	{0x3ED8, 0x7F1B}, 		// Manufacturer-Specific
	{0x3EDA, 0xAF11},      // Manufacturer-Specific
	{0x3EE2, 0x0060},      // Manufacturer-Specific
	{0x3EF2, 0xD965},      // Manufacturer-Specific
	{0x3EF8, 0x797F},      // Manufacturer-Specific
	{0x3EFC, 0xA8EF},	// Manufacturer-Specific 
	{0x3EFE, 0x1F0F},      // Manufacturer-Specific
	{0x31E0, 0x1F01},      // Manufacturer-Specific
	{0x305E, 0x1824},      //  minimum analog gain, 2011.12.21
	{0x3E00, 0x042F},      // Manufacturer-Specific
	{0x3E02, 0xFFFF},      // Manufacturer-Specific
	{0x3E04, 0xFFFF},	// Manufacturer-Specific
	{0x3E06, 0xFFFF},      // Manufacturer-Specific
	{0x3E08, 0x8071},      // Manufacturer-Specific
	{0x3E0A, 0x7281},      // Manufacturer-Specific
	{0x3E0C, 0x4011},      // Manufacturer-Specific
	{0x3E0E, 0x8010},      // Manufacturer-Specific
	{0x3E10, 0x60A5},      // Manufacturer-Specific
	{0x3E12, 0x4080},      // Manufacturer-Specific
	{0x3E14, 0x4180},      // Manufacturer-Specific
	{0x3E16, 0x0018},      // Manufacturer-Specific
	{0x3E18, 0x46B7},      // Manufacturer-Specific
	{0x3E1A, 0x4994},      // Manufacturer-Specific
	{0x3E1C, 0x4997},      // Manufacturer-Specific
	{0x3E1E, 0x4682},      // Manufacturer-Specific
	{0x3E20, 0x0018},      // Manufacturer-Specific
	{0x3E22, 0x4241},      // Manufacturer-Specific
	{0x3E24, 0x8000},      // Manufacturer-Specific
	{0x3E26, 0x1880},      // Manufacturer-Specific
	{0x3E28, 0x4785},      // Manufacturer-Specific
	{0x3E2A, 0x4992},      // Manufacturer-Specific
	{0x3E2C, 0x4997},	// Manufacturer-Specific
	{0x3E2E, 0x4780},      // Manufacturer-Specific
	{0x3E30, 0x4D80},      // Manufacturer-Specific
	{0x3E32, 0x100C},      // Manufacturer-Specific
	{0x3E34, 0x8000},      // Manufacturer-Specific
	{0x3E36, 0x184A},      // Manufacturer-Specific
	{0x3E38, 0x8042},      // Manufacturer-Specific
	{0x3E3A, 0x001A},      // Manufacturer-Specific
	{0x3E3C, 0x9610},      // Manufacturer-Specific
	{0x3E3E, 0x0C80},      // Manufacturer-Specific
	{0x3E40, 0x4DC6},      // Manufacturer-Specific
	{0x3E42, 0x4A80},      // Manufacturer-Specific
	{0x3E44, 0x0018},      // Manufacturer-Specific
	{0x3E46, 0x8042},      // Manufacturer-Specific
	{0x3E48, 0x8041},      // Manufacturer-Specific
	{0x3E4A, 0x0018},      // Manufacturer-Specific
	{0x3E4C, 0x804B},      // Manufacturer-Specific
	{0x3E4E, 0xB74B},      // Manufacturer-Specific
	{0x3E50, 0x8010},      // Manufacturer-Specific
	{0x3E52, 0x6056},      // Manufacturer-Specific
	{0x3E54, 0x001C},	// Manufacturer-Specific
	{0x3E56, 0x8211},      // Manufacturer-Specific
	{0x3E58, 0x8056},      // Manufacturer-Specific
	{0x3E5A, 0x827C},      // Manufacturer-Specific
	{0x3E5C, 0x0970},      // Manufacturer-Specific
	{0x3E5E, 0x8082},      // Manufacturer-Specific
	{0x3E60, 0x7281},      // Manufacturer-Specific
	{0x3E62, 0x4C40},      // Manufacturer-Specific
	{0x3E64, 0x8E4D},      // Manufacturer-Specific
	{0x3E66, 0x8110},      // Manufacturer-Specific
	{0x3E68, 0x0CAF},      // Manufacturer-Specific
	{0x3E6A, 0x4D80},      // Manufacturer-Specific
	{0x3E6C, 0x100C},      // Manufacturer-Specific
	{0x3E6E, 0x8440},      // Manufacturer-Specific
	{0x3E70, 0x4C81},      // Manufacturer-Specific
	{0x3E72, 0x7C5F},      // Manufacturer-Specific
	{0x3E74, 0x7000},      // Manufacturer-Specific
	{0x3E76, 0x0000},      // Manufacturer-Specific
	{0x3E78, 0x0000},      // Manufacturer-Specific
	{0x3E7A, 0x0000},      // Manufacturer-Specific
	{0x3E7C, 0x0000},	// Manufacturer-Specific
	{0x3E7E, 0x0000},      // Manufacturer-Specific
	{0x3E80, 0x0000},      // Manufacturer-Specific
	{0x3E82, 0x0000},      // Manufacturer-Specific
	{0x3E84, 0x0000},      // Manufacturer-Specific
	{0x3E86, 0x0000},      // Manufacturer-Specific
	{0x3E88, 0x0000},      // Manufacturer-Specific
	{0x3E8A, 0x0000},      // Manufacturer-Specific
	{0x3E8C, 0x0000},      // Manufacturer-Specific
	{0x3E8E, 0x0000},      // Manufacturer-Specific
	{0x3E90, 0x0000},      // Manufacturer-Specific
	{0x3E92, 0x0000},      // Manufacturer-Specific
	{0x3E94, 0x0000},      // Manufacturer-Specific
	{0x3E96, 0x0000},      // Manufacturer-Specific
	{0x3E98, 0x0000},      // Manufacturer-Specific
	{0x3E9A, 0x0000},      // Manufacturer-Specific
	{0x3E9C, 0x0000},      // Manufacturer-Specific
	{0x3E9E, 0x0000},      // Manufacturer-Specific
	{0x3EA0, 0x0000},      // Manufacturer-Specific
	{0x3EA2, 0x0000},      // Manufacturer-Specific
	{0x3EA4, 0x0000},	// Manufacturer-Specific
	{0x3EA6, 0x0000},      // Manufacturer-Specific
	{0x3EA8, 0x0000},      // Manufacturer-Specific
	{0x3EAA, 0x0000},      // Manufacturer-Specific
	{0x3EAC, 0x0000},      // Manufacturer-Specific
	{0x3EAE, 0x0000},      // Manufacturer-Specific
	{0x3EB0, 0x0000},      // Manufacturer-Specific
	{0x3EB2, 0x0000},      // Manufacturer-Specific
	{0x3EB4, 0x0000},      // Manufacturer-Specific
	{0x3EB6, 0x0000},      // Manufacturer-Specific
	{0x3EB8, 0x0000},      // Manufacturer-Specific
	{0x3EBA, 0x0000},      // Manufacturer-Specific
	{0x3EBC, 0x0000},      // Manufacturer-Specific
	{0x3EBE, 0x0000},      // Manufacturer-Specific
	{0x3EC0, 0x0000},      // Manufacturer-Specific
	{0x3EC2, 0x0000},      // Manufacturer-Specific
	{0x3EC4, 0x0000},      // Manufacturer-Specific
	{0x3EC6, 0x0000},      // Manufacturer-Specific
	{0x3EC8, 0x0000},      // Manufacturer-Specific
	{0x3ECA, 0x0000},      // Manufacturer-Specific
	{0x3170, 0x2150},	// Manufacturer-Specific  
	{0x317A, 0x0150},      // Manufacturer-Specific
	{0x3ECC, 0x2200},      // Manufacturer-Specific
	{0x3174, 0x0000},      // Manufacturer-Specific
	{0x3176, 0X0000}, 	// Manufacturer-Specific
    {0x30D4, 0x9200},	
    {0x30B2, 0xC000},	
    {0x30BC, 0x0400},	
    {0x306E, 0xB480},	
    {0x31B0, 0x00C4},	
    {0x31B2, 0x0064},	
    {0x31B4, 0x0E77},	
    {0x31B6, 0x0D24},	
    {0x31B8, 0x020E},	
    {0x31BA, 0x0710},	
    {0x31BC, 0x2A0D},	
    {0x31BE, 0xC007},		

	//mipi set
	{0x31B0, 0x00C4}, 
	{0x31B2, 0x0064},
	{0x31B4, 0x0E77},
	{0x31B6, 0x0D24},
	{0x31B8, 0x020E},
	{0x31BA, 0x0710},
	{0x31BC, 0x2A0D},	
	{0x31BE, 0xC007}, //  continuous
	#else
	// Sensor Rev4 Setting 110411
	{0x316A, 0x8400},	 // Manufacturer-Specific             
	{0x316C, 0x8400},  // Manufacturer-Specific  
	{0x316E, 0x8400},  // Manufacturer-Specific  
	{0x3EFA, 0x1B1F},  // Manufacturer-Specific   
	{0x3ED2, 0xD965},	 // Manufacturer-Specific  
	{0x3ED8, 0x7F1B},	 // Manufacturer-Specific  
	{0x3EDA, 0xAF11},	 // Manufacturer-Specific  
	{0x3EE2, 0x0060},	 // Manufacturer-Specific  
	{0x3EF2, 0xD965},	 // Manufacturer-Specific  
	{0x3EF8, 0x797F},	 // Manufacturer-Specific  
	{0x3EFC, 0xA8EF},	                           
	{0x3EFE, 0x1F0F},	 // Manufacturer-Specific  
	{0x31E0, 0x1F01},	 // Manufacturer-Specific  
	{0x3E00, 0x0429},	 // Manufacturer-Specific  
	{0x3E02, 0xFFFF},  // Manufacturer-Specific  
	{0x3E04, 0xFFFF},  // Manufacturer-Specific  
	{0x3E06, 0xFFFF},  // Manufacturer-Specific  
	{0x3E08, 0x8071},  // Manufacturer-Specific  
	{0x3E0A, 0x7281},  // Manufacturer-Specific  
	{0x3E0C, 0x0043},  // Manufacturer-Specific  
	{0x3E0E, 0x5313},  // Manufacturer-Specific  
	{0x3E10, 0x0087},  // Manufacturer-Specific  
	{0x3E12, 0x1060},  // Manufacturer-Specific  
	{0x3E14, 0x8540},  // Manufacturer-Specific  
	{0x3E16, 0xA200},  // Manufacturer-Specific  
	{0x3E18, 0x1890},  // Manufacturer-Specific  
	{0x3E1A, 0x57A0},  // Manufacturer-Specific  
	{0x3E1C, 0x49A6},  // Manufacturer-Specific  
	{0x3E1E, 0x4988},  // Manufacturer-Specific  
	{0x3E20, 0x4681},  // Manufacturer-Specific  
	{0x3E22, 0x4200},  // Manufacturer-Specific  
	{0x3E24, 0x828B},  // Manufacturer-Specific  
	{0x3E26, 0x499C},  // Manufacturer-Specific  
	{0x3E28, 0x498E},  // Manufacturer-Specific  
	{0x3E2A, 0x4788},  // Manufacturer-Specific  
	{0x3E2C, 0x4D80},  // Manufacturer-Specific  
	{0x3E2E, 0x100C},  // Manufacturer-Specific  
	{0x3E30, 0x0406},  // Manufacturer-Specific  
	{0x3E32, 0x9110},  // Manufacturer-Specific  
	{0x3E34, 0x0C8C},  // Manufacturer-Specific  
	{0x3E36, 0x4DB9},  // Manufacturer-Specific  
	{0x3E38, 0x4A42},  // Manufacturer-Specific  
	{0x3E3A, 0x8341},  // Manufacturer-Specific  
	{0x3E3C, 0x814B},  // Manufacturer-Specific  
	{0x3E3E, 0xB24B},  // Manufacturer-Specific  
	{0x3E40, 0x8056},  // Manufacturer-Specific  
	{0x3E42, 0x8000},  // Manufacturer-Specific  
	{0x3E44, 0x1C81},  // Manufacturer-Specific  
	{0x3E46, 0x10E0},  // Manufacturer-Specific  
	{0x3E48, 0x8013},  // Manufacturer-Specific  
	{0x3E4A, 0x001C},  // Manufacturer-Specific  
	{0x3E4C, 0x0082},  // Manufacturer-Specific  
	{0x3E4E, 0x7C09},  // Manufacturer-Specific  
	{0x3E50, 0x7000},  // Manufacturer-Specific  
	{0x3E52, 0x8082},  // Manufacturer-Specific  
	{0x3E54, 0x7281},  // Manufacturer-Specific  
	{0x3E56, 0x4C40},  // Manufacturer-Specific  
	{0x3E58, 0x8E4D},  // Manufacturer-Specific  
	{0x3E5A, 0x8110},  // Manufacturer-Specific  
	{0x3E5C, 0x0CAF},  // Manufacturer-Specific  
	{0x3E5E, 0x4D80},  // Manufacturer-Specific  
	{0x3E60, 0x100C},  // Manufacturer-Specific  
	{0x3E62, 0x8440},  // Manufacturer-Specific  
	{0x3E64, 0x4C81},  // Manufacturer-Specific  
	{0x3E66, 0x7C53},  // Manufacturer-Specific  
	{0x3E68, 0x7000},  // Manufacturer-Specific  
	{0x3E6A, 0x0000},  // Manufacturer-Specific  
	{0x3E6C, 0x0000},  // Manufacturer-Specific  
	{0x3E6E, 0x0000},  // Manufacturer-Specific  
	{0x3E70, 0x0000},  // Manufacturer-Specific  
	{0x3E72, 0x0000},  // Manufacturer-Specific  
	{0x3E74, 0x0000},  // Manufacturer-Specific  
	{0x3E76, 0x0000},  // Manufacturer-Specific  
	{0x3E78, 0x0000},  // Manufacturer-Specific  
	{0x3E7A, 0x0000},  // Manufacturer-Specific  
	{0x3E7C, 0x0000},  // Manufacturer-Specific  
	{0x3E7E, 0x0000},  // Manufacturer-Specific  
	{0x3E80, 0x0000},  // Manufacturer-Specific  
	{0x3E82, 0x0000},  // Manufacturer-Specific  
	{0x3E84, 0x0000},  // Manufacturer-Specific  
	{0x3E86, 0x0000},  // Manufacturer-Specific  
	{0x3E88, 0x0000},  // Manufacturer-Specific  
	{0x3E8A, 0x0000},  // Manufacturer-Specific  
	{0x3E8C, 0x0000},  // Manufacturer-Specific  
	{0x3E8E, 0x0000},  // Manufacturer-Specific  
	{0x3E90, 0x0000},  // Manufacturer-Specific  
	{0x3E92, 0x0000},  // Manufacturer-Specific  
	{0x3E94, 0x0000},  // Manufacturer-Specific  
	{0x3E96, 0x0000},  // Manufacturer-Specific  
	{0x3E98, 0x0000},  // Manufacturer-Specific  
	{0x3E9A, 0x0000},  // Manufacturer-Specific  
	{0x3E9C, 0x0000},  // Manufacturer-Specific  
	{0x3E9E, 0x0000},  // Manufacturer-Specific  
	{0x3EA0, 0x0000},  // Manufacturer-Specific  
	{0x3EA2, 0x0000},  // Manufacturer-Specific  
	{0x3EA4, 0x0000},  // Manufacturer-Specific  
	{0x3EA6, 0x0000},  // Manufacturer-Specific  
	{0x3EA8, 0x0000},  // Manufacturer-Specific  
	{0x3EAA, 0x0000},  // Manufacturer-Specific  
	{0x3EAC, 0x0000},  // Manufacturer-Specific  
	{0x3EAE, 0x0000},  // Manufacturer-Specific  
	{0x3EB0, 0x0000},  // Manufacturer-Specific  
	{0x3EB2, 0x0000},  // Manufacturer-Specific  
	{0x3EB4, 0x0000},  // Manufacturer-Specific  
	{0x3EB6, 0x0000},  // Manufacturer-Specific  
	{0x3EB8, 0x0000},  // Manufacturer-Specific  
	{0x3EBA, 0x0000},  // Manufacturer-Specific  
	{0x3EBC, 0x0000},  // Manufacturer-Specific  
	{0x3EBE, 0x0000},  // Manufacturer-Specific  
	{0x3EC0, 0x0000},  // Manufacturer-Specific  
	{0x3EC2, 0x0000},  // Manufacturer-Specific  
	{0x3EC4, 0x0000},  // Manufacturer-Specific  
	{0x3EC6, 0x0000},  // Manufacturer-Specific  
	{0x3EC8, 0x0000},
	{0x3ECA, 0x0000},
	{0x3170, 0x2150},
	{0x317A, 0x0150},
	{0x3ECC, 0x2200},
	{0x3174, 0x0000},
	{0x3176, 0X0000},

	//mipi set
	{0x31B0, 0x00C4}, //changed from 0x0083
	{0x31B2, 0x0064},
	{0x31B4, 0x0E77},
	{0x31B6, 0x0D24},
	{0x31B8, 0x020E},
	{0x31BA, 0x0710},
	{0x31BC, 0x2A0D},
	#endif
}; 
/* Preview	register settings	*/

/* read out mode register : 15-vert_flip, 14-horiz_mirror, 
					      11-x_bin_en, 10-xy_bin_en, 
					      8~6-x_odd_inc, 5~0-y_odd_inc */

struct mt9p017_i2c_reg_conf const mode_preview_temp_tbl[]=
{
	{0x3004, 0x0000},	 //x_addr_start
	{0x3008, 0x0A25},	 //x_addr_end
	{0x3002, 0x0000},	 //y_start_addr
	{0x3006, 0x07A5},	 //y_addr_end
	{0x3040, 0xC4C3},	 //read_mode
	{0x034C, 0x0514},	 //x_output_size
	{0x034E, 0x03D4},	 //y_output_size
	{0x300C, 0x0D4C},	 //line_length_pck
	{0x300A, 0x0420},	 //frame_length_lines
	{0x3012, 0x041F},	 //coarse_integration_time
	{0x3014, 0x0A04},	 //fine_integration_time
	{0x3010, 0x0184}	 //fine_correction
};

struct mt9p017_i2c_reg_conf const mode_preview_tbl[]=
{
	{0x3004, 0x0000},	 //x_addr_start
	{0x3008, 0x0A25},	 //x_addr_end
	{0x3002, 0x0000},	 //y_start_addr
	{0x3006, 0x07A5},	 //y_addr_end
	{0x3040, 0x04C3},	 //read_mode
	{0x034C, 0x0514},	 //x_output_size
	{0x034E, 0x03D4},	 //y_output_size
	{0x300C, 0x0D4C},	 //line_length_pck
	{0x300A, 0x0420},	 //frame_length_lines
	{0x3012, 0x041F},	 //coarse_integration_time
	{0x3014, 0x0A04},	 //fine_integration_time
	{0x3010, 0x0184}	 //fine_correction
};

/* 2400*1350 -21fps */
struct mt9p017_i2c_reg_conf const mode_preview_1080_temp_tbl[]=
{
	{0x3004, 0x0150},	   //x_addr_start								  
	{0x3008, 0x08DF},	  //x_addr_end										 
	{0x3002, 0x01B0},	  //y_start_addr									 
	{0x3006, 0x05F7},	   //y_addr_end 									  
	{0x3040, 0xC041},	  //read_mode - vertical flip, horizontal mirror	 
	{0x034C, 0x0790},	  //x_output_size	 //1920+16									  
	{0x034E, 0x0448},	   //y_output_size	  //1080+16 								 
	{0x300C, 0x0BFD},	  //line_length_pck 								 
	{0x300A, 0x0495},	  //frame_length_lines								 
	{0x3012, 0x0494},	   //coarse_integration_time						  
	{0x3014, 0x02CE},	  //0x12BE				//fine_integration_time 						   
	{0x3010, 0x00A0}	  //fine_correction
};

struct mt9p017_i2c_reg_conf const mode_preview_1080_tbl[]=
{
	{0x3004, 0x0150},	   //x_addr_start								  
	{0x3008, 0x08DF},	  //x_addr_end										 
	{0x3002, 0x01B0},	  //y_start_addr									 
	{0x3006, 0x05F7},	   //y_addr_end 									  
	{0x3040, 0x0041},	  //read_mode - vertical flip, horizontal mirror	 
	{0x034C, 0x0790},	  //x_output_size	 //1920+16									  
	{0x034E, 0x0448},	   //y_output_size	  //1080+16 								 
	{0x300C, 0x0BFD},	  //line_length_pck 								 
	{0x300A, 0x0495},	  //frame_length_lines								 
	{0x3012, 0x0494},	   //coarse_integration_time						  
	{0x3014, 0x02CE},	  //0x12BE				//fine_integration_time 						   
	{0x3010, 0x00A0}	  //fine_correction
};

/* Snapshot register settings */
struct mt9p017_i2c_reg_conf const mode_snapshot_temp_tbl[]=
{
	{0x3004, 0x0000},	 //x_addr_start
	{0x3008, 0x0A2F},	 //x_addr_end  //2607
	{0x3002, 0x0000},	 //y_start_addr
	{0x3006, 0x07A7},	 //y_addr_end //1959
	{0x3040, 0xC041},	 //read_mode miracle.kim@lge.com 11.06.07 // no mirror, no flip, x_odd_inc = 1, y_odd_inc = 1
	{0x034C, 0x0A30},	 //x_output_size //2608
	{0x034E, 0x07A8},	 //y_output_size //1960
	{0x300C, 0x14A0},	 //line_length_pck //5280
	{0x300A, 0x07F8},	 //frame_length_lines //2040
//	{0x3012, 0x07F7},	 //coarse_integration_time //2039
	{0x3014, 0x12BE},	 //fine_integration_time //4798
	{0x3010, 0x00A0},	 //fine_correction //160
};

struct mt9p017_i2c_reg_conf const mode_snapshot_tbl[]=
{
	{0x3004, 0x0000},	 //x_addr_start
	{0x3008, 0x0A2F},	 //x_addr_end  //2607
	{0x3002, 0x0000},	 //y_start_addr
	{0x3006, 0x07A7},	 //y_addr_end //1959
	{0x3040, 0x0041},	 //read_mode miracle.kim@lge.com 11.06.07 // no mirror, no flip, x_odd_inc = 1, y_odd_inc = 1
	{0x034C, 0x0A30},	 //x_output_size //2608
	{0x034E, 0x07A8},	 //y_output_size //1960
	{0x300C, 0x14A0},	 //line_length_pck //5280
	{0x300A, 0x07F8},	 //frame_length_lines //2040
//	{0x3012, 0x07F7},	 //coarse_integration_time //2039
	{0x3014, 0x12BE},	 //fine_integration_time //4798
	{0x3010, 0x00A0},	 //fine_correction //160
};

struct mt9p017_i2c_reg_conf const lensrolloff_tbl[] = {
                {0x3600, 0x7F2F},             //  P_GR_P0Q0                                                                                                                                                                                                                                 
                {0x3602, 0x03AE},             //  P_GR_P0Q1                                                                                                                                                                                                                                 
                {0x3604, 0x3C50},             //  P_GR_P0Q2                                                                                                                                                                                                                                 
                {0x3606, 0xD52D},            //  P_GR_P0Q3                                                                                                                                                                                                                                 
                {0x3608, 0x8391},            //  P_GR_P0Q4                                                                                                                                                                                                                                 
                {0x360A, 0x0050},            //  P_RD_P0Q0                                                                                                                                                                                                                                  
                {0x360C, 0xEF0C},            //  P_RD_P0Q1                                                                                                                                                                                                                                  
                {0x360E, 0x2C10},             //  P_RD_P0Q2                                                                                                                                                                                                                                  
                {0x3610, 0x362D},             //  P_RD_P0Q3                                                                                                                                                                                                                                  
                {0x3612, 0xEB90},            //  P_RD_P0Q4                                                                                                                                                                                                                                  
                {0x3614, 0x02D0},             //  P_BL_P0Q0                                                                                                                                                                                                                                   
                {0x3616, 0x352E},            //  P_BL_P0Q1                                                                                                                                                                                                                                   
                {0x3618, 0x538F},             //  P_BL_P0Q2                                                                                                                                                                                                                                   
                {0x361A, 0xE3AE},            //  P_BL_P0Q3                                                                                                                                                                                                                                   
                {0x361C, 0xA610},             //  P_BL_P0Q4                                                                                                                                                                                                                                   
                {0x361E, 0x0070},             //  P_GB_P0Q0                                                                                                                                                                                                                                 
                {0x3620, 0x8B6D},             //  P_GB_P0Q1                                                                                                                                                                                                                                 
                {0x3622, 0x5C30},             //  P_GB_P0Q2                                                                                                                                                                                                                                 
                {0x3624, 0x1169},             //  P_GB_P0Q3                                                                                                                                                                                                                                 
                {0x3626, 0x9DF1},             //  P_GB_P0Q4                                                                                                                                                                                                                                 
                {0x3640, 0xB04C},            //  P_GR_P1Q0                                                                                                                                                                                                                                 
                {0x3642, 0xDA0D},           //  P_GR_P1Q1                                                                                                                                                                                                                                 
                {0x3644, 0xABCF},             //  P_GR_P1Q2                                                                                                                                                                                                                                 
                {0x3646, 0x4CAD},           //  P_GR_P1Q3                                                                                                                                                                                                                                 
                {0x3648, 0x50F0},             //  P_GR_P1Q4                                                                                                                                                                                                                                 
                {0x364A, 0x860C},           //  P_RD_P1Q0                                                                                                                                                                                                                                  
                {0x364C, 0x31CD},            //  P_RD_P1Q1                                                                                                                                                                                                                                  
                {0x364E, 0x16EE},             //  P_RD_P1Q2                                                                                                                                                                                                                                  
                {0x3650, 0x9AAE},            //  P_RD_P1Q3                                                                                                                                                                                                                                  
                {0x3652, 0xAB4E},             //  P_RD_P1Q4                                                                                                                                                                                                                                  
                {0x3654, 0x0B8D},            //  P_BL_P1Q0                                                                                                                                                                                                                                   
                {0x3656, 0x0BCE},            //  P_BL_P1Q1                                                                                                                                                                                                                                   
                {0x3658, 0x35AE},             //  P_BL_P1Q2                                                                                                                                                                                                                                   
                {0x365A, 0xD72E},           //  P_BL_P1Q3                                                                                                                                                                                                                                   
                {0x365C, 0xC7AF},            //  P_BL_P1Q4                                                                                                                                                                                                                                   
                {0x365E, 0x738B},            //  P_GB_P1Q0                                                                                                                                                                                                                                 
                {0x3660, 0x8E6E},             //  P_GB_P1Q1                                                                                                                                                                                                                                 
                {0x3662, 0x7FEF},             //  P_GB_P1Q2                                                                                                                                                                                                                                 
                {0x3664, 0x36CE},             //  P_GB_P1Q3                                                                                                                                                                                                                                 
                {0x3666, 0xF530},            //  P_GB_P1Q4                                                                                                                                                                                                                                 
                {0x3680, 0x2A50},             //  P_GR_P2Q0                                                                                                                                                                                                                                 
                {0x3682, 0x66ED},             //  P_GR_P2Q1                                                                                                                                                                                                                                 
                {0x3684, 0xE98D},             //  P_GR_P2Q2                                                                                                                                                                                                                                 
                {0x3686, 0xC4CE},             //  P_GR_P2Q3                                                                                                                                                                                                                                 
                {0x3688, 0x8AB3},            //  P_GR_P2Q4                                                                                                                                                                                                                                 
                {0x368A, 0x3550},            //  P_RD_P2Q0                                                                                                                                                                                                                                  
                {0x368C, 0xA80E},            //  P_RD_P2Q1                                                                                                                                                                                                                                  
                {0x368E, 0xC5CE},             //  P_RD_P2Q2                                                                                                                                                                                                                                  
                {0x3690, 0x16CC},             //  P_RD_P2Q3                                                                                                                                                                                                                                  
                {0x3692, 0xFD32},            //  P_RD_P2Q4                                                                                                                                                                                                                                  
                {0x3694, 0x0F30},             //  P_BL_P2Q0                                                                                                                                                                                                                                   
                {0x3696, 0x00ED},            //  P_BL_P2Q1                                                                                                                                                                                                                                   
                {0x3698, 0xD98E},            //  P_BL_P2Q2                                                                                                                                                                                                                                   
                {0x369A, 0x79CE},            //  P_BL_P2Q3                                                                                                                                                                                                                                   
                {0x369C, 0xB732},           //  P_BL_P2Q4                                                                                                                                                                                                                                   
                {0x369E, 0x31B0},             //  P_GB_P2Q0                                                                                                                                                                                                                                 
                {0x36A0, 0xF80E},            //  P_GB_P2Q1                                                                                                                                                                                                                                 
                {0x36A2, 0xA830},            //  P_GB_P2Q2                                                                                                                                                                                                                                 
                {0x36A4, 0x6FAF},            //  P_GB_P2Q3                                                                                                                                                                                                                                 
                {0x36A6, 0xBFB2},            //  P_GB_P2Q4                                                                                                                                                                                                                                 
                {0x36C0, 0x550E},            //  P_GR_P3Q0                                                                                                                                                                                                                                 
                {0x36C2, 0x24AE},            //  P_GR_P3Q1                                                                                                                                                                                                                                 
                {0x36C4, 0x30CF},            //  P_GR_P3Q2                                                                                                                                                                                                                                 
                {0x36C6, 0xE06D},            //  P_GR_P3Q3                                                                                                                                                                                                                                 
                {0x36C8, 0xD6F0},            //  P_GR_P3Q4                                                                                                                                                                                                                                 
                {0x36CA, 0x1D8F},            //  P_RD_P3Q0                                                                                                                                                                                                                                  
                {0x36CC, 0x820D},            //  P_RD_P3Q1                                                                                                                                                                                                                                  
                {0x36CE, 0x88B1},            //  P_RD_P3Q2                                                                                                                                                                                                                                  
                {0x36D0, 0x574E},            //  P_RD_P3Q3                                                                                                                                                                                                                                  
                {0x36D2, 0x58D1},            //  P_RD_P3Q4                                                                                                                                                                                                                                  
                {0x36D4, 0xBD6D},            //  P_BL_P3Q0                                                                                                                                                                                                                                   
                {0x36D6, 0xBD4E},           //  P_BL_P3Q1                                                                                                                                                                                                                                   
                {0x36D8, 0xD2AE},           //  P_BL_P3Q2                                                                                                                                                                                                                                   
                {0x36DA, 0x4AEF},           //  P_BL_P3Q3                                                                                                                                                                                                                                   
                {0x36DC, 0x0351},            //  P_BL_P3Q4                                                                                                                                                                                                                                   
                {0x36DE, 0x4ACD},            //  P_GB_P3Q0                                                                                                                                                                                                                                 
                {0x36E0, 0x7A6D},             //  P_GB_P3Q1                                                                                                                                                                                                                                 
                {0x36E2, 0xEF50},             //  P_GB_P3Q2                                                                                                                                                                                                                                 
                {0x36E4, 0xBD6B},             //  P_GB_P3Q3                                                                                                                                                                                                                                 
                {0x36E6, 0x5931},             //  P_GB_P3Q4                                                                                                                                                                                                                                 
                {0x3700, 0xBD70},            //  P_GR_P4Q0                                                                                                                                                                                                                                 
                {0x3702, 0xFD8F},             //  P_GR_P4Q1                                                                                                                                                                                                                                 
                {0x3704, 0x9834},             //  P_GR_P4Q2                                                                                                                                                                                                                                 
                {0x3706, 0x0ED0},            //  P_GR_P4Q3                                                                                                                                                                                                                                 
                {0x3708, 0x6A75},            //  P_GR_P4Q4                                                                                                                                                                                                                                 
                {0x370A, 0x9FB0},            //  P_RD_P4Q0                                                                                                                                                                                                                                  
                {0x370C, 0x7CC5},            //  P_RD_P4Q1                                                                                                                                                                                                                                  
                {0x370E, 0x8914},            //  P_RD_P4Q2                                                                                                                                                                                                                                  
                {0x3710, 0x6530},             //  P_RD_P4Q3                                                                                                                                                                                                                                  
                {0x3712, 0x5DF5},            //  P_RD_P4Q4                                                                                                                                                                                                                                  
                {0x3714, 0x9150},            //  P_BL_P4Q0                                                                                                                                                                                                                                   
                {0x3716, 0xE86F},            //  P_BL_P4Q1                                                                                                                                                                                                                                   
                {0x3718, 0xF473},            //  P_BL_P4Q2                                                                                                                                                                                                                                   
                {0x371A, 0x342D},            //  P_BL_P4Q3                                                                                                                                                                                                                                   
                {0x371C, 0x50D5},             //  P_BL_P4Q4                                                                                                                                                                                                                                   
                {0x371E, 0xBBB0},            //  P_GB_P4Q0                                                                                                                                                                                                                                 
                {0x3720, 0x1D6F},             //  P_GB_P4Q1                                                                                                                                                                                                                                 
                {0x3722, 0x8114},             //  P_GB_P4Q2                                                                                                                                                                                                                                 
                {0x3724, 0x97CD},             //  P_GB_P4Q3                                                                                                                                                                                                                                 
                {0x3726, 0x47F5},             //  P_GB_P4Q4                                                                                                                                                                                                                                 
                {0x3782, 0x0508},             //  POLY_ORIGIN_C                                                                                                                                                                                                                        
                {0x3784, 0x03B4},             //  POLY_ORIGIN_R                                                                                                                                                                                                                        
                {0x37C0, 0x388A},             //  P_GR_Q5                                                                                                                                                                                                                                      
                {0x37C2, 0x258A},             //  P_RD_Q5                                                                                                                                                                                                                       
                {0x37C4, 0x6CEA},             //  P_BL_Q5                                                                                                                                                                                                                        
                {0x37C6, 0x1A2B},            //  P_GB_Q5            
                {0x3780, 0x0000}              //  Poly_sc_enable                
//                {0x3780, 0x8000}              //  Poly_sc_enable
};


struct mt9p017_reg mt9p017_regs = {
	.pll_tbl = &pll_tbl[0],
	.plltbl_size = ARRAY_SIZE(pll_tbl),

	.init_tbl = &init_tbl[0],
	.inittbl_size = ARRAY_SIZE(init_tbl),

	.prev_tbl = &mode_preview_tbl[0],
	.prevtbl_size = ARRAY_SIZE(mode_preview_tbl),

	.prev_1080_tbl = &mode_preview_1080_tbl[0],
	.prevtbl_1080_size = ARRAY_SIZE(mode_preview_1080_tbl),

	.snap_tbl = &mode_snapshot_tbl[0],
	.snaptbl_size = ARRAY_SIZE(mode_snapshot_tbl),

	.prev_temp_tbl = &mode_preview_temp_tbl[0],
	.prevtbl_temp_size = ARRAY_SIZE(mode_preview_tbl),

	.prev_1080_temp_tbl = &mode_preview_1080_temp_tbl[0],
	.prevtbl_1080_temp_size = ARRAY_SIZE(mode_preview_1080_tbl),

	.snap_temp_tbl = &mode_snapshot_temp_tbl[0],
	.snaptbl_temp_size = ARRAY_SIZE(mode_snapshot_tbl),

	.lensroff_tbl = &lensrolloff_tbl[0],
	.lensroff_size = ARRAY_SIZE(lensrolloff_tbl),
};



