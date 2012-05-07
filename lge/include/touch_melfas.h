/* include/linux/lge_touch_core.h
 *
 * Copyright (C) 2011 LGE.
 *
 * Writer: yehan.ahn@lge.com, 	hyesung.shin@lge.com
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
 */

#ifndef LGE_TOUCH_MELFAS_H
#define LGE_TOUCH_MELFAS_H

enum {
	TOUCH_NONE = 0,
	TOUCH_SCREEN,
	TOUCH_KEY
};

struct melfas_ts_data {
	u8	is_probed;
	struct regulator*	regulator_vdd;
	struct regulator*	regulator_vio;
	struct i2c_client*	client;
	struct touch_platform_data*		pdata;
	struct touch_fw_info*	fw_info;
};
#endif
