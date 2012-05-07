/* Copyright (c) 2009, Code Aurora Forum. All rights reserved.
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

#ifndef MT9M114_H
#define MT9M114_H

#include <linux/types.h>
#include <mach/camera.h>

enum mt9m114_wb_type{
	CAMERA_WB_MIN_MINUS_1,
	CAMERA_WB_AUTO = 1,  /* This list must match aeecamera.h */
	CAMERA_WB_CUSTOM,
	CAMERA_WB_INCANDESCENT =3,
	CAMERA_WB_FLUORESCENT=4,
	CAMERA_WB_DAYLIGHT=5,
	CAMERA_WB_CLOUDY_DAYLIGHT=6,
	CAMERA_WB_TWILIGHT,
	CAMERA_WB_SHADE,
	CAMERA_WB_MAX_PLUS_1
};

/* Enum Type for different ISO Mode supported */
enum mt9m114_iso_value {
	CAMERA_ISO_AUTO = 0,
	CAMERA_ISO_100 =2,
	CAMERA_ISO_200,
	CAMERA_ISO_400,
	CAMERA_ISO_MAX
};

enum mt9m114_antibanding_type {
	CAMERA_ANTIBANDING_OFF =0,
	CAMERA_ANTIBANDING_60HZ =1,
	CAMERA_ANTIBANDING_50HZ =2,
	CAMERA_MAX_ANTIBANDING,
};

extern struct mt9m114_reg mt9m114_regs;

enum mt9m114_width {
	BYTE_LEN,
	WORD_LEN,
};

struct mt9m114_i2c_reg_conf {
	unsigned short waddr;
	unsigned short wdata;
};

struct mt9m114_reg {

	struct mt9m114_i2c_reg_conf const *init_tbl;
	uint16_t inittbl_size;
	// Preview
	struct mt9m114_i2c_reg_conf const *prev_tbl;
	uint16_t prevtbl_size;
	// Snapshot
	struct mt9m114_i2c_reg_conf const *snap_tbl;
	uint16_t snaptbl_size;
	// Effect
	struct mt9m114_i2c_reg_conf const *effect_default_tbl;
	uint16_t effect_default_tbl_size;
	struct mt9m114_i2c_reg_conf const *effect_mono_tbl;
	uint16_t effect_mono_tbl_size;
	struct mt9m114_i2c_reg_conf const *effect_sepia_tbl;
	uint16_t effect_sepia_tbl_size;
	struct mt9m114_i2c_reg_conf const *effect_aqua_tbl;
	uint16_t effect_aqua_tbl_size;
	struct mt9m114_i2c_reg_conf const *effect_negative_tbl;
	uint16_t effect_negative_tbl_size;
	struct mt9m114_i2c_reg_conf const *effect_solarization_tbl;
	uint16_t effect_solarization_tbl_size;
	// White balance
	struct mt9m114_i2c_reg_conf const *wb_default_tbl;
	uint16_t wb_default_tbl_size;
	struct mt9m114_i2c_reg_conf const *wb_sunny_tbl;
	uint16_t wb_sunny_tbl_size;
	struct mt9m114_i2c_reg_conf const *wb_cloudy_tbl;
	uint16_t wb_cloudy_tbl_size;
	struct mt9m114_i2c_reg_conf const *wb_fluorescent_tbl;
	uint16_t wb_fluorescent_tbl_size;
	struct mt9m114_i2c_reg_conf const *wb_incandescent_tbl;
	uint16_t wb_incandescent_tbl_size;
	// ISO
	struct mt9m114_i2c_reg_conf const *iso_default_tbl;
	uint16_t iso_default_tbl_size;
	struct mt9m114_i2c_reg_conf const *iso_100_tbl;
	uint16_t iso_100_tbl_size;
	struct mt9m114_i2c_reg_conf const *iso_200_tbl;
	uint16_t iso_200_tbl_size;
	struct mt9m114_i2c_reg_conf const *iso_400_tbl;
	uint16_t iso_400_tbl_size;
	// Change-config
	struct mt9m114_i2c_reg_conf const *change_config_tbl;
	uint16_t change_config_tbl_size;
	
};


#endif /* MT9M114_H */
