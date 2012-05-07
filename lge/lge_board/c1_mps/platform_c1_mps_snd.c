/* lge/lge_board/i_atnt/board_i_atnt_snd.c
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

#define CONFIG_LGE_AUDIO_NO_NCP_MODE
#define CONFIG_LGE_AUDIO_USE_AUXMIC_FOR_SPEAKER_MODE
#define VIBRATOR_TEST
#define EW0804_CHECK_WM_QTR

#include <mach/msm_iomap.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/err.h>
#include <mach/board_lge.h>
#include <mach/msm_iomap.h>
#include <asm/io.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/mfd/pmic8058.h>
#include <linux/pmic8058-othc.h>
#include <linux/mfd/pmic8901.h>
#include <asm/mach-types.h>
#include <asm/uaccess.h>

#include <linux/mfd/msm-adie-codec.h>
#include <linux/regulator/pmic8058-regulator.h>
#include <linux/regulator/pmic8901-regulator.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/machine.h>

#include <mach/qdsp6v2/audio_dev_ctl.h>
#include <mach/qdsp6v2/apr_audio.h>
#include <mach/mpp.h>
#include <asm/mach-types.h>
#include <asm/uaccess.h>

#include "snddev_icodec.h"
#include "snddev_ecodec.h"
#include "timpani_profile_8x60_c1_mps.h"
#include "snddev_hdmi.h"
#include "snddev_mi2s.h"



#ifdef VIBRATOR_TEST				//ew0804.kim add vibrator test in wm9093_tuning
#define GPIO_LIN_MOTOR_PWM  		29

#define GPIO_LIN_MOTOR_EN		    158
#define VIBE_IC_VOLTAGE		        3000000

#define MSM_PDM_BASE_REG		           		0x18800040
#define GP_MN_CLK_MDIV_REG		                0xC
#define GP_MN_CLK_NDIV_REG		                0x10
#define GP_MN_CLK_DUTY_REG		                0x14

#define GP_MN_M_DEFAULT			        2
#define GP_MN_N_DEFAULT			        1304
#define GP_MN_D_DEFAULT		            	(GP_MN_N_DEFAULT >> 1) 
#define PWM_MAX_DUTY GP_MN_N_DEFAULT - GP_MN_M_DEFAULT
#define PWM_MIN_DUTY GP_MN_M_DEFAULT
#define PWM_MAX_HALF_DUTY		((GP_MN_D_DEFAULT >> 1) - 8) /* 127 - 8 = 119  minimum operating spec. should be checked */

#define GPMN_M_MASK				0x01FF
#define GPMN_N_MASK				0x1FFF
#define GPMN_D_MASK				0x1FFF


#define REG_WRITEL(value, reg)	        writel(value, (MSM_PDM_BASE+reg))
#define REG_READL(reg)	        readl((MSM_PDM_BASE+reg))
#endif


#ifdef CONFIG_LGE_HEADSET_DETECTION_FSA8008
#include "fsa8008.h"
#endif

#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
#include <linux/i2c.h>
#include "devices_c1_mps.h"
#include "wm9093.h"

//#define LGE_AUDIO_COMMENT_OUT_FOR_REFERENCE

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, Acoustic Calibration 
#include <linux/fs.h>
#include <linux/fcntl.h> 
#include <linux/string.h>
#include <linux/ctype.h>

#define	DEBUG_AMP_CTL	1

#define WM9093_AUDIO_TUNING 1


#if DEBUG_AMP_CTL
#define D(fmt, args...) printk(fmt, ##args)
#else
#define D(fmt, args...) do {} while(0)
#endif

enum {
    SPK_IN2_VOL,
    SPK_BOOST,
    SPK_OUT_VOL,
    HPH_IN1_VOL,
    HPH_OUT_VOL,
    TTY_IN1_VOL,
    TTY_OUT_VOL,
    HPH_SPK_IN1_VOL,
    HPH_SPK_BOOST,
    HPH_SPK_OUT_SPK_VOL,
    HPH_SPK_OUT_HPH_VOL,
    P_SPK_IN2_VOL,
    P_SPK_BOOST,
    P_SPK_OUT_VOL,
    P_HPH_IN1_VOL,
    P_HPH_OUT_VOL,
    WM9093_CAL_DB_MAX
};

char* wm9093_cfg_item[WM9093_CAL_DB_MAX] = 
{
    "SPK_IN2_VOL(addr 0x1A):0x%04X",
    "SPK_BOOST(addr 0x25):0x%04X",
    "SPK_OUT_VOL(addr 0x26):0x%04X",
    "HPH_IN1_VOL(addr 0x18):0x%04X",
    "HPH_OUT_VOL(addr 0x1C):0x%04X",
    "TTY_IN1_VOL(addr 0x18):0x%04X",
    "TTY_OUT_VOL(addr 0x1C):0x%04X",
    "HPH_SPK_IN1_VOL(addr 0x18):0x%04X",
    "HPH_SPK_BOOST(addr 0x25):0x%04X",
    "HPH_SPK_OUT_SPK_VOL(addr 0x26):0x%04X",
    "HPH_SPK_OUT_HPH_VOL(addr 0x1C):0x%04X",
    "P_SPK_IN2_VOL(addr 0x1A):0x%04X",
    "P_SPK_BOOST(addr 0x25):0x%04X",
    "P_SPK_OUT_VOL(addr 0x26):0x%04X",
    "P_HPH_IN1_VOL(addr 0x18):0x%04X",
    "P_HPH_OUT_VOL(addr 0x1C):0x%04X"
};



enum {
    RCV_RX1_L_GAIN,
    RCV_GAIN,
    RCV_FE_GAIN,
    RCV_TX1_GAIN,
    SPK_RX1_L_GAIN,
    SPK_RX1_R_GAIN,
    SPK_L_GAIN,
    SPK_R_GAIN,
    SPK_FE_GAIN,
    SPK_TX1_GAIN,
    HPH_RX1_L_GAIN,
    HPH_RX1_R_GAIN,
    HPH_L_GAIN,
    HPH_R_GAIN,
    HPH_FE_GAIN,
    HPH_TX1_GAIN,
    TTY_RX1_L_GAIN,
    TTY_RX1_R_GAIN,
    TTY_L_GAIN,
    TTY_R_GAIN,    
    TTY_FE_GAIN,
    TTY_TX1_GAIN,
    HAC_RX1_L_GAIN,
    HAC_GAIN,
    P_SPK_RX1_L_GAIN,
    P_SPK_RX1_R_GAIN,
    P_SPK_L_GAIN,
    P_SPK_R_GAIN,
    P_HPH_RX1_L_GAIN,
    P_HPH_RX1_R_GAIN,
    P_HPH_L_GAIN,
    P_HPH_R_GAIN,
    RECORD_FE_GAIN,
    RECORD_TX1_GAIN,
    D_MAIN_FE1_GAIN,
    D_MAIN_TX1_L_GAIN,
    D_SUB_FE2_GAIN,
    D_SUB_TX1_R_GAIN,
    QTR8615L_CAL_DB_MAX
};

char* qtr8615l_cfg_item[QTR8615L_CAL_DB_MAX] = 
{
    "RCV_RX1_L_GAIN(0x84):0x%02X",
    "RCV_GAIN(0x39):0x%02X",
    "RCV_FE_GAIN(0x0D):0x%02X",
    "RCV_TX1_GAIN(0x86):0x%02X",
    "SPK_RX1_L_GAIN(0x84):0x%02X",
    "SPK_RX1_R_GAIN(0x85):0x%02X",
    "SPK_L_GAIN(0xE0):0x%02X",
    "SPK_R_GAIN(0xE1):0x%02X",
    "SPK_FE_GAIN(0x0D):0x%02X",
    "SPK_TX1_GAIN(0x86):0x%02X",
    "HPH_RX1_L_GAIN(0x84):0x%02X",
    "HPH_RX1_R_GAIN(0x85):0x%02X",
    "HPH_L_GAIN(0xE2):0x%02X",
    "HPH_R_GAIN(0xE3):0x%02X",
    "HPH_FE_GAIN(0x0D):0x%02X",
    "HPH_TX1_GAIN(0x86):0x%02X",
    "TTY_RX1_L_GAIN(0x84):0x%02X",
    "TTY_RX1_R_GAIN(0x85):0x%02X",
    "TTY_L_GAIN(0xE2):0x%02X",
    "TTY_R_GAIN(0xE3):0x%02X",    
    "TTY_FE_GAIN(0x0D):0x%02X",
    "TTY_TX1_GAIN(0x86):0x%02X",
    "HAC_RX1_L_GAIN(0x84):0x%02X",
    "HAC_GAIN(0x39):0x%02X",
    "P_SPK_RX1_L_GAIN(0x84):0x%02X",
    "P_SPK_RX1_R_GAIN(0x85):0x%02X",
    "P_SPK_L_GAIN(0xE0):0x%02X",
    "P_SPK_R_GAIN(0xE1):0x%02X",
    "P_HPH_RX1_L_GAIN(0x84):0x%02X",
    "P_HPH_RX1_R_GAIN(0x85):0x%02X",
    "P_HPH_L_GAIN(0xE2):0x%02X",
    "P_HPH_R_GAIN(0xE3):0x%02X",
    "RECORD_FE1_GAIN(0x0D):0x%02X",
    "RECORD_TX1_L_GAIN(0x86):0x%02X",
    "D_MAIN_FE1_GAIN(0x0D):0x%02X",
    "D_MAIN_TX1_L_GAIN(0x86):0x%02X",
    "D_SUB_FE2_GAIN(0x0E):0x%02X",    
    "D_SUB_TX1_R_GAIN(0x87):0x%02X"
};

typedef struct {
    struct adie_codec_action_unit *adie_codec_action_ptr;   
    u8 cal_idx;
    u8 val;
} adie_codec_action_Cmd;

const char* LGE_WM9093_CALIBRATION_TOOL = "wm9093_codec";
const char* LGE_QTR8615L_CALIBRATION_TOOL = "qtr8615l";
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, Acoustic Calibration 

static int wm9093TuningFlag = 0;

/* QTR Line ==> WM9093 IN2 ==> SPK */
wmCodecCmd seq_lin_to_spkout[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x6030},
    {0x17, 0x0001}, // IN2_CLAMP 0bit 0 : clamp de-activate 1: clamp activated  
    {0x1A, 0x0101}, // IN2A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x1B, 0x0101}, // IN2B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)
    {0x36, 0x0005},
    {0x03, 0x0008},
    {0x22, 0x0000}, // 0dB
    {0x03, 0x0108},  
    {0x25, 0x0170},//{0x25, 0x0140}, // 12dB(178}, 9dB(170}, 7.5dB(168}, 6dB(160}, 4.5dB(158}, 3dB(150}, 1.5dB(148}, 0dB(140)
    {0x26, 0x013F}, // refer page 26  //0x013e
    {0x17, 0x0000},  
    {0x01, 0x100B}
};

/* QTR Line ==> WM9093 IN2 ==> SPK */
wmCodecCmd seq_lin_to_spkout_playback[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x6030},
    {0x17, 0x0001}, // IN2_CLAMP 0bit 0 : clamp de-activate 1: clamp activated  
    {0x1A, 0x0101}, // IN2A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x1B, 0x0101}, // IN2B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)
    {0x36, 0x0005},
    {0x03, 0x0008},
    {0x22, 0x0000}, // 0dB
    {0x03, 0x0108},  
    {0x25, 0x0170}, // 12dB(178}, 9dB(170}, 7.5dB(168}, 6dB(160}, 4.5dB(158}, 3dB(150}, 1.5dB(148}, 0dB(140)
    {0x26, 0x013F}, // refer page 26  // 0x013e
    {0x17, 0x0000},  
    {0x01, 0x100B}
};


/* QTR HPH ==> WM9093 IN1 ==> EAR */
wmCodecCmd seq_lin_to_headset[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x60C0},
    {0x16, 0x0001}, // IN1_CLAMP 0bit 0 : clamp de-activate 1: clamp activated
    {0x18, 0x0100}, // IN1A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x19, 0x0100}, // IN1B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x2D, 0x0040},
    {0x2E, 0x0010},
    {0x03, 0x0030},
    {0x2F, 0x0000},
    {0x30, 0x0000},
    {0x1C, 0x0139}, //refer to page 26
    {0x1D, 0x0139}, //refer to page 26  
    {0x16, 0x0000},
    {0x46, 0x0100},
    {0x49, 0x0100}
};

/* QTR HPH ==> WM9093 IN1 ==> EAR */
wmCodecCmd seq_lin_to_headset_playback[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x60C0},
    {0x16, 0x0001}, // IN1_CLAMP 0bit 0 : clamp de-activate 1: clamp activated
    {0x18, 0x0100}, // IN1A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x19, 0x0100}, // IN1B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x2D, 0x0040},
    {0x2E, 0x0010},
    {0x03, 0x0030},
    {0x2F, 0x0000},
    {0x30, 0x0000},
    {0x1C, 0x0137}, //refer to page 26
    {0x1D, 0x0137}, //refer to page 26  
    {0x16, 0x0000},
    {0x46, 0x0100},
    {0x49, 0x0100}
};

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t simultaneously Ringing Headset and SPK
/* QTR HPH ==> WM9093 IN1 ==> EAR and SPK */
wmCodecCmd seq_lin_to_headset_spkout[] = 
{
    {0x39, 0x000D},
    {0x01, 0x130B}, // Enable Speaker output, Headphone output
    {0x02, 0x60C0},	
    {0x16, 0x0001},	
    {0x18, 0x0100}, // IN1A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x19, 0x0100}, // IN1B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x36, 0x0050},
    {0x22, 0x0000}, // 0dB
    {0x25, 0x0170}, // 12dB(178}, 9dB(170}, 7.5dB(168}, 6dB(160}, 4.5dB(158}, 3dB(150}, 1.5dB(148}, 0dB(140)
    {0x26, 0x0139}, // refer to page 26  //0x013E
    {0x2D, 0x0040},
    {0x2E, 0x0010},	
    {0x03, 0x0138},
    {0x2F, 0x0000},	
    {0x30, 0x0000},	
    {0x1C, 0x0119}, //refer to page 26  //0x0137
    {0x1D, 0x0119}, //refer to page 26  //0x0137
    {0x16, 0x0000},	
    {0x46, 0x0100},	
    {0x49, 0x0100}
};
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t simultaneously Ringing Headset and SPK

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t TTY
/* QTR HPH ==> WM9093 IN1 ==> EAR */
wmCodecCmd seq_lin_to_headset_tty[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x60C0},
    {0x16, 0x0001}, // IN1_CLAMP 0bit 0 : clamp de-activate 1: clamp activated
    {0x18, 0x0102}, // IN1A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x19, 0x0102}, // IN1B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x2D, 0x0040},
    {0x2E, 0x0010},
    {0x03, 0x0030},
    {0x2F, 0x0000},
    {0x30, 0x0000},
    {0x1C, 0x012F}, //refer to page 26
    {0x1D, 0x012F}, //refer to page 26  
    {0x16, 0x0000},
    {0x46, 0x0100},
    {0x49, 0x0100}
};
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t TTY

static wmCodecCmd seq_power_down[] = 
{
	{0x46, 0x0100},
	{0x49, 0x0110},
	{0x00, 0x0000},
	{0x02, 0x6000},
	{0x39, 0x0000}
};

/* QTR Line ==> WM9093 IN2 ==> SPK */
wmCodecCmd seq_tuning_lin_to_spkout[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x6030},
    {0x17, 0x0001}, // IN2_CLAMP 0bit 0 : clamp de-activate 1: clamp activated  
    {0x1A, 0x0101}, // IN2A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x1B, 0x0101}, // IN2B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)
    {0x36, 0x0005},
    {0x03, 0x0008},
    {0x22, 0x0000}, // 0dB
    {0x03, 0x0108},  
    {0x25, 0x0170},//{0x25, 0x0140}, // 12dB(178}, 9dB(170}, 7.5dB(168}, 6dB(160}, 4.5dB(158}, 3dB(150}, 1.5dB(148}, 0dB(140)
    {0x26, 0x013F}, // refer page 26  
    {0x17, 0x0000},  
    {0x01, 0x100B}
};

/* QTR Line ==> WM9093 IN2 ==> SPK */
wmCodecCmd seq_tuning_lin_to_spkout_playback[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x6030},
    {0x17, 0x0001}, // IN2_CLAMP 0bit 0 : clamp de-activate 1: clamp activated  
    {0x1A, 0x0101}, // IN2A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x1B, 0x0101}, // IN2B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)
    {0x36, 0x0005},
    {0x03, 0x0008},
    {0x22, 0x0000}, // 0dB
    {0x03, 0x0108},  
    {0x25, 0x0170}, // 12dB(178}, 9dB(170}, 7.5dB(168}, 6dB(160}, 4.5dB(158}, 3dB(150}, 1.5dB(148}, 0dB(140)
    {0x26, 0x013F}, // refer page 26  
    {0x17, 0x0000},  
    {0x01, 0x100B}
};


/* QTR HPH ==> WM9093 IN1 ==> EAR */
wmCodecCmd seq_tuning_lin_to_headset[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x60C0},
    {0x16, 0x0001}, // IN1_CLAMP 0bit 0 : clamp de-activate 1: clamp activated
    {0x18, 0x0100}, // IN1A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x19, 0x0100}, // IN1B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x2D, 0x0040},
    {0x2E, 0x0010},
    {0x03, 0x0030},
    {0x2F, 0x0000},
    {0x30, 0x0000},
    {0x1C, 0x0139}, //refer to page 26
    {0x1D, 0x0139}, //refer to page 26  
    {0x16, 0x0000},
    {0x46, 0x0100},
    {0x49, 0x0100}
};

/* QTR HPH ==> WM9093 IN1 ==> EAR */
wmCodecCmd seq_tuning_lin_to_headset_playback[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x60C0},
    {0x16, 0x0001}, // IN1_CLAMP 0bit 0 : clamp de-activate 1: clamp activated
    {0x18, 0x0100}, // IN1A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x19, 0x0100}, // IN1B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x2D, 0x0040},
    {0x2E, 0x0010},
    {0x03, 0x0030},
    {0x2F, 0x0000},
    {0x30, 0x0000},
    {0x1C, 0x0137}, //refer to page 26
    {0x1D, 0x0137}, //refer to page 26  
    {0x16, 0x0000},
    {0x46, 0x0100},
    {0x49, 0x0100}
};

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t simultaneously Ringing Headset and SPK
/* QTR HPH ==> WM9093 IN1 ==> EAR and SPK */
wmCodecCmd seq_tuning_lin_to_headset_spkout[] = 
{
    {0x39, 0x000D},
    {0x01, 0x130B}, // Enable Speaker output, Headphone output
    {0x02, 0x60C0},	
    {0x16, 0x0001},	
    {0x18, 0x0100}, // IN1A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x19, 0x0100}, // IN1B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x36, 0x0050},
    {0x22, 0x0000}, // 0dB
    {0x25, 0x0140}, // 12dB(178}, 9dB(170}, 7.5dB(168}, 6dB(160}, 4.5dB(158}, 3dB(150}, 1.5dB(148}, 0dB(140)
    {0x26, 0x013F}, // refer to page 26  
    {0x2D, 0x0040},
    {0x2E, 0x0010},	
    {0x03, 0x0138},
    {0x2F, 0x0000},	
    {0x30, 0x0000},	
    {0x1C, 0x0125}, //refer to page 26
    {0x1D, 0x0125}, //refer to page 26    
    {0x16, 0x0000},	
    {0x46, 0x0100},	
    {0x49, 0x0100}
};
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t simultaneously Ringing Headset and SPK

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t TTY
/* QTR HPH ==> WM9093 IN1 ==> EAR */
wmCodecCmd seq_tuning_lin_to_headset_tty[] = 
{
    {0x39, 0x000D},
    {0x01, 0x000B},
    {0x02, 0x60C0},
    {0x16, 0x0001}, // IN1_CLAMP 0bit 0 : clamp de-activate 1: clamp activated
    {0x18, 0x0102}, // IN1A -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x19, 0x0102}, // IN1B -6dB(00}, -3.5dB(01}, 0dB(02}, 3.5dB(03}, 6dB(04}, 12dB(05}, 18dB(06}, 18dB(07)  
    {0x2D, 0x0040},
    {0x2E, 0x0010},
    {0x03, 0x0030},
    {0x2F, 0x0000},
    {0x30, 0x0000},
    {0x1C, 0x012F}, //refer to page 26
    {0x1D, 0x012F}, //refer to page 26  
    {0x16, 0x0000},
    {0x46, 0x0100},
    {0x49, 0x0100}
};

struct wm9093_platform_data lge_audio_wm9093_platform = {
	.speaker_on = {
		.amp_function = seq_lin_to_spkout,
		.amp_tuning_function = seq_tuning_lin_to_spkout,	
		.amp_function_size = ARRAY_SIZE(seq_lin_to_spkout),
	},
		
	.hph_on = {
		.amp_function = seq_lin_to_headset,
		.amp_tuning_function = seq_tuning_lin_to_headset,				
		.amp_function_size = ARRAY_SIZE(seq_lin_to_headset),
	},

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t
    .hph_spk_on = { // at&t simultaneously Ringing Headset and SPK
        .amp_function = seq_lin_to_headset_spkout,
		.amp_tuning_function = seq_tuning_lin_to_headset_spkout,			
        .amp_function_size = ARRAY_SIZE(seq_lin_to_headset_spkout),
    },

    .tty_on = { // TTY
        .amp_function = seq_lin_to_headset_tty,
		.amp_tuning_function = seq_tuning_lin_to_headset_tty,			
        .amp_function_size = ARRAY_SIZE(seq_lin_to_headset_tty),
    },

    .speaker_playback_on = { // playback
        .amp_function = seq_lin_to_spkout_playback,
		.amp_tuning_function = seq_tuning_lin_to_spkout_playback,			
        .amp_function_size = ARRAY_SIZE(seq_lin_to_spkout_playback),
    },

    .hph_playback_on = { // playback
        .amp_function = seq_lin_to_headset_playback,
		.amp_tuning_function = seq_tuning_lin_to_headset_playback,			
        .amp_function_size = ARRAY_SIZE(seq_lin_to_headset_playback),
    },
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t
	.power_down = {
		.amp_function = seq_power_down,
		.amp_tuning_function = seq_power_down,	
		.amp_function_size = ARRAY_SIZE(seq_power_down),
	},
	.set_amp_path = NULL,
	.wm9093_cmd_register = NULL,
	.wm9093_reg_dump = NULL
	
};

#define WM9093_I2C_SLAVE_ADDR   0xDC

static struct i2c_board_info lge_i2c_wm9093_info[] = {
        {
                I2C_BOARD_INFO("wm9093", WM9093_I2C_SLAVE_ADDR>>1),
				.platform_data = &lge_audio_wm9093_platform
        },
};
#endif

#ifdef CONFIG_DEBUG_FS
static struct dentry *debugfs_hsed_config;
//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t Acoustic Calibration  
static struct dentry *debugfs_wm9093_cal_tool_config;
static struct dentry *debugfs_wmread;
static struct dentry *debugfs_wmwrite;
static struct dentry *debugfs_wmtuning;
static struct dentry *debugfs_dump;

static struct dentry *debugfs_qtr8616l_cal_tool_config;
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t Acoustic Calibration  
static unsigned char read_data;

static void snddev_hsed_config_modify_setting(int type);
static void snddev_hsed_config_restore_setting(void);
#endif

static struct resource msm_cdcclk_ctl_resources[] = {
	{
		.name   = "msm_snddev_tx_mclk",
		.start  = 108,
		.end    = 108,
		.flags  = IORESOURCE_IO,
	},
	{
		.name   = "msm_snddev_rx_mclk",
		.start  = 109,
		.end    = 109,
		.flags  = IORESOURCE_IO,
	},
};

static struct platform_device msm_cdcclk_ctl_device = {
	.name   = "msm_cdcclk_ctl",
	.num_resources  = ARRAY_SIZE(msm_cdcclk_ctl_resources),
	.resource       = msm_cdcclk_ctl_resources,
};

static struct resource msm_aux_pcm_resources[] = {

	{
		.name   = "aux_pcm_dout",
		.start  = 111,
		.end    = 111,
		.flags  = IORESOURCE_IO,
	},
	{
		.name   = "aux_pcm_din",
		.start  = 112,
		.end    = 112,
		.flags  = IORESOURCE_IO,
	},
	{
		.name   = "aux_pcm_syncout",
		.start  = 113,
		.end    = 113,
		.flags  = IORESOURCE_IO,
	},
	{
		.name   = "aux_pcm_clkin_a",
		.start  = 114,
		.end    = 114,
		.flags  = IORESOURCE_IO,
	},
};

static struct platform_device msm_aux_pcm_device = {
	.name   = "msm_aux_pcm",
	.num_resources  = ARRAY_SIZE(msm_aux_pcm_resources),
	.resource       = msm_aux_pcm_resources,
};

static struct resource msm_mi2s_gpio_resources[] = {

	{
		.name   = "mi2s_ws",
		.start  = 101,
		.end    = 101,
		.flags  = IORESOURCE_IO,
	},
	{
		.name   = "mi2s_sclk",
		.start  = 102,
		.end    = 102,
		.flags  = IORESOURCE_IO,
	},
	{
		.name   = "mi2s_mclk",
		.start  = 103,
		.end    = 103,
		.flags  = IORESOURCE_IO,
	},
	{
		.name   = "fm_mi2s_sd",
		.start  = 107,
		.end    = 107,
		.flags  = IORESOURCE_IO,
	},
};

static struct platform_device msm_mi2s_device = {
	.name		= "msm_mi2s",
	.num_resources	= ARRAY_SIZE(msm_mi2s_gpio_resources),
	.resource	= msm_mi2s_gpio_resources,
};

#ifdef LGE_AUDIO_COMMENT_OUT_FOR_REFERENCE
static struct regulator *s3;
static struct regulator *mvs;

static int msm_snddev_enable_dmic_power(void)
{
	int ret;

	s3 = regulator_get(NULL, "8058_s3");
	if (IS_ERR(s3)) {
		ret = -EBUSY;
		goto fail_get_s3;
	}

	ret = regulator_set_voltage(s3, 1800000, 1800000);
	if (ret) {
		pr_err("%s: error setting voltage\n", __func__);
		goto fail_s3;
	}

	ret = regulator_enable(s3);
	if (ret) {
		pr_err("%s: error enabling regulator\n", __func__);
		goto fail_s3;
	}

	mvs = regulator_get(NULL, "8901_mvs0");
	if (IS_ERR(mvs))
		goto fail_mvs0_get;

	ret = regulator_enable(mvs);
	if (ret) {
		pr_err("%s: error setting regulator\n", __func__);
		goto fail_mvs0_enable;
	}
	return ret;

fail_mvs0_enable:
	regulator_put(mvs);
	mvs = NULL;
fail_mvs0_get:
	regulator_disable(s3);
fail_s3:
	regulator_put(s3);
	s3 = NULL;
fail_get_s3:
	return ret;
}

static void msm_snddev_disable_dmic_power(void)
{
	int ret;

	if (mvs) {
		ret = regulator_disable(mvs);
		if (ret < 0)
			pr_err("%s: error disabling vreg mvs\n", __func__);
		regulator_put(mvs);
		mvs = NULL;
	}

	if (s3) {
		ret = regulator_disable(s3);
		if (ret < 0)
			pr_err("%s: error disabling regulator s3\n", __func__);
		regulator_put(s3);
		s3 = NULL;
	}
}

static struct regulator *l11;

static int msm_snddev_enable_qt_dmic_power(void)
{
	int ret;

	l11 = regulator_get(NULL, "8058_l11");
	if (IS_ERR(l11))
		return -EBUSY;

	ret = regulator_set_voltage(l11, 1500000, 1500000);
	if (ret) {
		pr_err("%s: error setting regulator\n", __func__);
		goto fail_l11;
	}
	ret = regulator_enable(l11);
	if (ret) {
		pr_err("%s: error enabling regulator\n", __func__);
		goto fail_l11;
	}
	return 0;

fail_l11:
	regulator_put(l11);
	l11 = NULL;
	return ret;
}


static void msm_snddev_disable_qt_dmic_power(void)
{
	int ret;

	if (l11) {
		ret = regulator_disable(l11);
		if (ret < 0)
			pr_err("%s: error disabling regulator l11\n", __func__);
		regulator_put(l11);
		l11 = NULL;
	}
}
#endif

static int msm_snddev_poweramp_on_spk(void)
{
	pr_debug("%s\n", __func__);
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_SPEAKER_RX);
#endif

	return 0;
}

static void msm_snddev_poweramp_off_spk(void)
{
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_AMP_OFF);
	else
		printk("%s _amp_path NULL\n", __func__);
#endif

	pr_debug("%s\n", __func__);
 }

static int msm_snddev_poweramp_on_spk_playback(void)
{
	pr_debug("%s\n", __func__);

#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_SPEAKER_PLAYBACK_RX);
#endif

	return 0;
}

static int msm_snddev_poweramp_on_hph(void)
{
	pr_debug("%s\n", __func__);

#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_HEADSET_ST_RX);
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */

	return 0;
}

static void msm_snddev_poweramp_off_hph(void)
{
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_AMP_OFF);
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */

	pr_debug("%s\n", __func__);
}

static int msm_snddev_poweramp_on_hph_playback(void)
{
	pr_debug("%s\n", __func__);

#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_HEADSET_ST_PLAYBACK_RX);
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */

	return 0;
}

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t simultaneously Ringing Headset and SPK
static int msm_snddev_poweramp_on_hph_spk(void)
{
	pr_debug("%s\n", __func__);

#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_HEADSET_ST_RX_SPEAKER_RX);
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */

	return 0;
}

static void msm_snddev_poweramp_off_hph_spk(void)
{
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_AMP_OFF);
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */

	pr_debug("%s\n", __func__);
}
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t simultaneously Ringing Headset and SPK

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t TTY 
static int msm_snddev_poweramp_on_tty(void)
{
	pr_debug("%s\n", __func__);

#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_TTY_RX);
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */

	return 0;
}

static void msm_snddev_poweramp_off_tty(void)
{
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	if (lge_audio_wm9093_platform.set_amp_path)
		lge_audio_wm9093_platform.set_amp_path(ICODEC_AMP_OFF);
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */

	pr_debug("%s\n", __func__);
}
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t TTY 

/* Regulator 8058_l10 supplies regulator 8058_ncp. */
#ifndef CONFIG_LGE_AUDIO_NO_NCP_MODE
static struct regulator *snddev_reg_ncp;
#endif
static struct regulator *snddev_reg_l10;

static int msm_snddev_voltage_on(void)
{
	int rc=0;
	pr_debug("%s\n", __func__);
#if 0
	snddev_reg_l10 = regulator_get(NULL, "8058_l10");
	if (IS_ERR(snddev_reg_l10)) {
		pr_err("%s: regulator_get(%s) failed (%ld)\n", __func__,
			"l10", PTR_ERR(snddev_reg_l10));
		return -EBUSY;
	}

	rc = regulator_set_voltage(snddev_reg_l10, 2600000, 2600000);
	if (rc < 0)
		pr_err("%s: regulator_set_voltage(l10) failed (%d)\n",
			__func__, rc);

	rc = regulator_enable(snddev_reg_l10);
	if (rc < 0)
		pr_err("%s: regulator_enable(l10) failed (%d)\n", __func__, rc);
#endif
#ifndef CONFIG_LGE_AUDIO_NO_NCP_MODE
	snddev_reg_ncp = regulator_get(NULL, "8058_ncp");
	if (IS_ERR(snddev_reg_ncp)) {
		pr_err("%s: regulator_get(%s) failed (%ld)\n", __func__,
			"ncp", PTR_ERR(snddev_reg_ncp));
		return -EBUSY;
	}

	rc = regulator_set_voltage(snddev_reg_ncp, 1800000, 1800000);
	if (rc < 0) {
		pr_err("%s: regulator_set_voltage(ncp) failed (%d)\n",
			__func__, rc);
		goto regulator_fail;
	}

	rc = regulator_enable(snddev_reg_ncp);
	if (rc < 0) {
		pr_err("%s: regulator_enable(ncp) failed (%d)\n", __func__, rc);
		goto regulator_fail;
	}

	return rc;

regulator_fail:
	regulator_put(snddev_reg_ncp);
	snddev_reg_ncp = NULL;
	return rc;
#else
	return rc;
#endif
}

static void msm_snddev_voltage_off(void)
{
	int rc = 0;
	rc = 0;
	pr_debug("%s\n", __func__);

#ifndef CONFIG_LGE_AUDIO_NO_NCP_MODE
	if (!snddev_reg_ncp)
		goto done;

	rc = regulator_disable(snddev_reg_ncp);
	if (rc < 0)
		pr_err("%s: regulator_disable(ncp) failed (%d)\n",
			__func__, rc);

	regulator_put(snddev_reg_ncp);

	snddev_reg_ncp = NULL;

done:
#endif
#if 0
	if (!snddev_reg_l10)
		return;

	rc = regulator_disable(snddev_reg_l10);
	if (rc < 0)
		pr_err("%s: regulator_disable(l10) failed (%d)\n",
			__func__, rc);

	regulator_put(snddev_reg_l10);
#endif
	snddev_reg_l10 = NULL;
}

static int msm_snddev_enable_amic_power(void)
{
/* sungwoo.cho@lge.com 2011. 01. 26 */
#ifdef CONFIG_LGE_AUDIO
	int ret;

#ifdef CONFIG_PMIC8058_OTHC
	ret = pm8058_micbias_enable(OTHC_MICBIAS_MAIN, OTHC_SIGNAL_ALWAYS_ON);

	if (ret)
		pr_err("%s: Enabling OTHC_MICBIAS_MAIN(%d) power failed\n", __func__, OTHC_MICBIAS_MAIN);
#endif
#if 0
	ret = gpio_request(GPIO_CAMCORDER_MIC_EN, "CAMCORDER_MIC_EN");
	if (ret) {
		pr_err("%s: camcorder mic en %d request failed\n",
			__func__, GPIO_CAMCORDER_MIC_EN);
		return 0;
	}
	gpio_direction_output(GPIO_CAMCORDER_MIC_EN, 1);
#endif	
#endif
	return 0;
/* sungwoo.cho@lge.com 2011. 01. 26 */
}

static void msm_snddev_disable_amic_power(void)
{
/* sungwoo.cho@lge.com 2011. 01. 26 */
#ifdef CONFIG_LGE_AUDIO
#if 0
	gpio_set_value(GPIO_CAMCORDER_MIC_EN, 0);
	gpio_free(GPIO_CAMCORDER_MIC_EN);
#endif
#ifdef CONFIG_PMIC8058_OTHC
	{
		int ret;

		ret = pm8058_micbias_enable(OTHC_MICBIAS_MAIN, OTHC_SIGNAL_OFF);

		if (ret)
			pr_err("%s: Disabling OTHC_MICBIAS_MAIN(%d) power failed\n", __func__, OTHC_MICBIAS_MAIN);
	}
#endif
#endif
/* sungwoo.cho@lge.com 2011. 01. 26 */
}

static int msm_snddev_enable_adualmic_power(void)
{
	
#if defined(CONFIG_LGE_AUDIO)&&defined(CONFIG_PMIC8058_OTHC)
	int ret;
	ret = pm8058_micbias_enable(OTHC_MICBIAS_MAIN, OTHC_SIGNAL_ALWAYS_ON);
	if (ret)
		pr_err("%s: Enabling OTHC_MICBIAS_MAIN(%d) power failed\n", __func__, OTHC_MICBIAS_MAIN);
	ret = pm8058_micbias_enable(OTHC_MICBIAS_SUB, OTHC_SIGNAL_ALWAYS_ON);
	if (ret)
		pr_err("%s: Enabling OTHC_MICBIAS_SUB(%d) power failed\n", __func__, OTHC_MICBIAS_SUB);

#endif
	return 0;

}

static void msm_snddev_disable_adualmic_power(void)
{
#if defined(CONFIG_LGE_AUDIO)&&defined(CONFIG_PMIC8058_OTHC)
	int ret;

	ret = pm8058_micbias_enable(OTHC_MICBIAS_MAIN, OTHC_SIGNAL_OFF);
	if (ret)
		pr_err("%s: Disabling OTHC_MICBIAS_MAIN(%d) power failed\n", __func__, OTHC_MICBIAS_MAIN);
	ret = pm8058_micbias_enable(OTHC_MICBIAS_SUB, OTHC_SIGNAL_OFF);
	if (ret)
		pr_err("%s: Enabling OTHC_MICBIAS_SUB(%d) power failed\n", __func__, OTHC_MICBIAS_SUB);

#endif
}

#ifdef LGE_AUDIO_COMMENT_OUT_FOR_REFERENCE
static int msm_snddev_enable_dmic_sec_power(void)
{
	int ret;

	ret = msm_snddev_enable_dmic_power();
	if (ret) {
		pr_err("%s: Error: Enabling dmic power failed\n", __func__);
		return ret;
	}
#ifdef CONFIG_PMIC8058_OTHC
	ret = pm8058_micbias_enable(OTHC_MICBIAS_2, OTHC_SIGNAL_ALWAYS_ON);
	if (ret) {
		pr_err("%s: Error: Enabling micbias failed\n", __func__);
		msm_snddev_disable_dmic_power();
		return ret;
	}
#endif
	return 0;
}

static void msm_snddev_disable_dmic_sec_power(void)
{
	msm_snddev_disable_dmic_power();

#ifdef CONFIG_PMIC8058_OTHC
	pm8058_micbias_enable(OTHC_MICBIAS_2, OTHC_SIGNAL_OFF);
#endif
}
#endif

static struct adie_codec_action_unit iearpiece_48KHz_osr256_actions[] =
	HANDSET_RX_MONO_8000_OSR_256;

static struct adie_codec_hwsetting_entry iearpiece_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = iearpiece_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(iearpiece_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile iearpiece_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = iearpiece_settings,
	.setting_sz = ARRAY_SIZE(iearpiece_settings),
};

static struct snddev_icodec_data snddev_iearpiece_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "handset_rx",
	.copp_id = 0,
	.profile = &iearpiece_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
};

static struct platform_device msm_iearpiece_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_iearpiece_data },
};

static struct adie_codec_action_unit imic_48KHz_osr256_actions[] =
	HANDSET_TX_PRI_MONO_OSR_256;

static struct adie_codec_hwsetting_entry imic_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = imic_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(imic_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile imic_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = imic_settings,
	.setting_sz = ARRAY_SIZE(imic_settings),
};

static struct snddev_icodec_data snddev_imic_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_tx",
	.copp_id = 1,
	.profile = &imic_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
};

static struct platform_device msm_imic_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_imic_data },
};

static struct adie_codec_action_unit ihs_stereo_48KHz_osr256_actions[] =
#ifdef CONFIG_LGE_AUDIO_NO_NCP_MODE
	HEADSET_RX_STEREO_AB_LEG;
#else
	HEADSET_AB_CPLS_48000_OSR_256;
#endif

static struct adie_codec_hwsetting_entry ihs_stereo_rx_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = ihs_stereo_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(ihs_stereo_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile ihs_stereo_rx_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = ihs_stereo_rx_settings,
	.setting_sz = ARRAY_SIZE(ihs_stereo_rx_settings),
};

static struct snddev_icodec_data snddev_ihs_stereo_rx_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "headset_stereo_rx",
	.copp_id = 0,
	.profile = &ihs_stereo_rx_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
/* LGE_CHANGE 2011. 01. 20 sungwoo.cho, dongsung.shin start */
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	.pamp_on = msm_snddev_poweramp_on_hph,
	.pamp_off = msm_snddev_poweramp_off_hph,
#endif	
/* LGE_CHANGE 2011. 01. 20 sungwoo.cho, dongsung.shin end */
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
};

static struct platform_device msm_headset_stereo_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_ihs_stereo_rx_data },
};


/* define the value for Earjack Loopback, RX */
static struct adie_codec_action_unit ihs_stereo_acs_48KHz_osr256_actions[] =
#ifdef CONFIG_LGE_AUDIO_NO_NCP_MODE
	HEADSET_RX_STEREO_AB_LEG;
#else
	HEADSET_AB_CPLS_48000_OSR_256;
#endif
static struct adie_codec_hwsetting_entry ihs_stereo_acs_rx_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = ihs_stereo_acs_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(ihs_stereo_acs_48KHz_osr256_actions),
	}
};
static struct adie_codec_dev_profile ihs_stereo_acs_rx_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = ihs_stereo_acs_rx_settings,
	.setting_sz = ARRAY_SIZE(ihs_stereo_acs_rx_settings),
};
static struct snddev_icodec_data snddev_ihs_stereo_acs_rx_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "headset_acs_rx",
	.copp_id = 0,
	.profile = &ihs_stereo_acs_rx_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
/* LGE_CHANGE 2011. 01. 20 sungwoo.cho, dongsung.shin start */
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	.pamp_on = msm_snddev_poweramp_on_hph,
	.pamp_off = msm_snddev_poweramp_off_hph,
#endif	
/* LGE_CHANGE 2011. 01. 20 sungwoo.cho, dongsung.shin end */
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
};
static struct platform_device msm_headset_stereo_acs_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_ihs_stereo_acs_rx_data },
};


static struct adie_codec_action_unit ihs_stereo_playback_48KHz_osr256_actions[] =
#ifdef CONFIG_LGE_AUDIO_NO_NCP_MODE
	HEADSET_RX_STEREO_PLAYBACK_AB_LEG;
#else
	HEADSET_AB_CPLS_48000_OSR_256;
#endif

static struct adie_codec_hwsetting_entry ihs_stereo_playback_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = ihs_stereo_playback_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(ihs_stereo_playback_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile ihs_stereo_rx_playback_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = ihs_stereo_playback_settings,
	.setting_sz = ARRAY_SIZE(ihs_stereo_playback_settings),
};

static struct snddev_icodec_data snddev_ihs_stereo_rx_playbackdata = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "headset_stereo_rx_playback",
	.copp_id = 0,
	.profile = &ihs_stereo_rx_playback_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_poweramp_on_hph_playback,
	.pamp_off = msm_snddev_poweramp_off_hph,
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
};

static struct platform_device msm_headset_stereo_playback_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_ihs_stereo_rx_playbackdata },
};

#ifdef LGE_AUDIO_COMMENT_OUT_FOR_REFERENCE
static struct adie_codec_action_unit headset_anc_48KHz_osr256_actions[] =
	ANC_HEADSET_CPLS_AMIC1_AUXL_RX1_48000_OSR_256;

static struct adie_codec_hwsetting_entry headset_anc_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = headset_anc_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(headset_anc_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile headset_anc_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = headset_anc_settings,
	.setting_sz = ARRAY_SIZE(headset_anc_settings),
};

static struct snddev_icodec_data snddev_anc_headset_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE | SNDDEV_CAP_ANC),
	.name = "anc_headset_stereo_rx",
	.copp_id = PRIMARY_I2S_RX,
	.profile = &headset_anc_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
};

static struct platform_device msm_anc_headset_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_anc_headset_data },
};
#endif

static struct adie_codec_action_unit ispkr_stereo_48KHz_osr256_actions[] =
	SPEAKER_RX_STEREO_48000_OSR_256;

static struct adie_codec_hwsetting_entry ispkr_stereo_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = ispkr_stereo_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(ispkr_stereo_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile ispkr_stereo_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = ispkr_stereo_settings,
	.setting_sz = ARRAY_SIZE(ispkr_stereo_settings),
};

static struct snddev_icodec_data snddev_ispkr_stereo_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "speaker_stereo_rx",
	.copp_id = 0,
	.profile = &ispkr_stereo_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_poweramp_on_spk,
	.pamp_off = msm_snddev_poweramp_off_spk,
/* sungwoo.cho@lge.com 2011. 01. 26 */
#if 0//def CONFIG_LGE_AUDIO_AMP_WM9093
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
#endif
/* sungwoo.cho@lge.com 2011. 01. 26 */
};

static struct platform_device msm_ispkr_stereo_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_ispkr_stereo_data },
};

static struct adie_codec_action_unit ispkr_stereo_playback_48KHz_osr256_actions[] =
	SPEAKER_RX_STEREO_PLAYBACK_48000_OSR_256;

static struct adie_codec_hwsetting_entry ispkr_stereo_playback_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = ispkr_stereo_playback_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(ispkr_stereo_playback_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile ispkr_stereo_playback_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = ispkr_stereo_playback_settings,
	.setting_sz = ARRAY_SIZE(ispkr_stereo_playback_settings),
};

static struct snddev_icodec_data snddev_ispkr_stereo_playback_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "speaker_stereo_rx_playback",
	.copp_id = 0,
	.profile = &ispkr_stereo_playback_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_poweramp_on_spk_playback,
	.pamp_off = msm_snddev_poweramp_off_spk,
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
};

static struct platform_device msm_ispkr_stereo_playback_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_ispkr_stereo_playback_data },
};
#ifdef CONFIG_LGE_AUDIO

static int msm_snddev_enable_dualmic_power(void)
{
	int ret;

	ret = pm8058_micbias_enable(OTHC_MICBIAS_SUB, OTHC_SIGNAL_ALWAYS_ON);

	if (ret)
		pr_err("%s: Enabling OTHC_MICBIAS_SUB(%d) power failed\n", __func__, OTHC_MICBIAS_SUB);

	ret = pm8058_micbias_enable(OTHC_MICBIAS_MAIN, OTHC_SIGNAL_ALWAYS_ON);

	if (ret)
		pr_err("%s: Enabling OTHC_MICBIAS_MAIN(%d) power failed\n", __func__, OTHC_MICBIAS_MAIN);

	return ret;
}

static void msm_snddev_disable_dualmic_power(void)
{
	int ret;

	ret = pm8058_micbias_enable(OTHC_MICBIAS_SUB, OTHC_SIGNAL_OFF);

	if (ret)
		pr_err("%s: Disabling OTHC_MICBIAS_SUB(%d) power failed\n", __func__, OTHC_MICBIAS_SUB);

	ret = pm8058_micbias_enable(OTHC_MICBIAS_MAIN, OTHC_SIGNAL_OFF);

	if (ret)
		pr_err("%s: Disabling OTHC_MICBIAS_MAIN(%d) power failed\n", __func__, OTHC_MICBIAS_MAIN);
}

#ifdef CONFIG_LGE_AUDIO_USE_AUXMIC_FOR_SPEAKER_MODE
static int msm_snddev_enable_submic_power(void)
{
	int ret;

	ret = pm8058_micbias_enable(OTHC_MICBIAS_SUB, OTHC_SIGNAL_ALWAYS_ON);

	if (ret)
		pr_err("%s: Enabling OTHC_MICBIAS_SUB(%d) power failed\n", __func__, OTHC_MICBIAS_SUB);

	return ret;
}

static void msm_snddev_disable_submic_power(void)
{
	int ret;

	ret = pm8058_micbias_enable(OTHC_MICBIAS_SUB, OTHC_SIGNAL_OFF);

	if (ret)
		pr_err("%s: Disabling OTHC_MICBIAS_SUB(%d) power failed\n", __func__, OTHC_MICBIAS_SUB);
}

static struct adie_codec_action_unit submic_48KHz_osr256_actions[] =
//	AMIC_SEC_MONO_OSR_256;
	AUXIN_MONO_OSR_256;

static struct adie_codec_hwsetting_entry submic_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = submic_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(submic_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile submic_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = submic_settings,
	.setting_sz = ARRAY_SIZE(submic_settings),
};
#endif

static struct snddev_icodec_data snddev_ispkr_mic_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "speaker_mono_tx",
	.copp_id = 1,
#ifdef CONFIG_LGE_AUDIO_USE_AUXMIC_FOR_SPEAKER_MODE
	.profile = &submic_profile,
#else
	.profile = &imic_profile,
#endif
	.channel_mode = 1,
	.default_sample_rate = 48000,
#ifdef CONFIG_LGE_AUDIO_USE_AUXMIC_FOR_SPEAKER_MODE
	.pamp_on = msm_snddev_enable_submic_power,
	.pamp_off = msm_snddev_disable_submic_power,
#else
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
#endif
};

#else

static struct adie_codec_action_unit ispkr_mic_48KHz_osr256_actions[] =
	SPEAKER_TX_PRI_MONO_OSR_256;

static struct adie_codec_hwsetting_entry ispkr_mic_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = ispkr_mic_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(ispkr_mic_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile ispkr_mic_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = ispkr_mic_settings,
	.setting_sz = ARRAY_SIZE(ispkr_mic_settings),
};

static struct snddev_icodec_data snddev_ispkr_mic_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "speaker_mono_tx",
	.copp_id = 1,
	.profile = &ispkr_mic_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
};

#endif

static struct platform_device msm_ispkr_mic_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_ispkr_mic_data },
};

static struct adie_codec_action_unit dual_mic_endfire_8KHz_osr256_actions[] =
	AMIC_DUAL_8000_OSR_256;

static struct adie_codec_hwsetting_entry dual_mic_endfire_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = dual_mic_endfire_8KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(dual_mic_endfire_8KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile dual_mic_endfire_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = dual_mic_endfire_settings,
	.setting_sz = ARRAY_SIZE(dual_mic_endfire_settings),
};

static struct snddev_icodec_data snddev_dual_mic_endfire_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_dual_mic_endfire_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &dual_mic_endfire_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
#ifdef CONFIG_LGE_AUDIO
	.pamp_on = msm_snddev_enable_adualmic_power,
	.pamp_off = msm_snddev_disable_adualmic_power,
#else
	.pamp_on = msm_snddev_enable_dmic_power,
	.pamp_off = msm_snddev_disable_dmic_power,
#endif	
};

static struct platform_device msm_hs_dual_mic_endfire_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_dual_mic_endfire_data },
};

#ifdef LGE_AUDIO_COMMENT_OUT_FOR_REFERENCE
static struct adie_codec_action_unit iearpiece_ffa_48KHz_osr256_actions[] =
	EAR_PRI_MONO_8000_OSR_256;

static struct adie_codec_hwsetting_entry iearpiece_ffa_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = iearpiece_ffa_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(iearpiece_ffa_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile iearpiece_ffa_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = iearpiece_ffa_settings,
	.setting_sz = ARRAY_SIZE(iearpiece_ffa_settings),
};

static struct snddev_icodec_data snddev_iearpiece_ffa_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "handset_rx",
	.copp_id = 0,
	.profile = &iearpiece_ffa_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
};

static struct platform_device msm_iearpiece_ffa_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_iearpiece_ffa_data },
};

static struct snddev_icodec_data snddev_imic_ffa_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &idmic_mono_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_dmic_power,
	.pamp_off = msm_snddev_disable_dmic_power,
};

static struct platform_device msm_imic_ffa_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_imic_ffa_data },
};

static struct snddev_icodec_data snddev_qt_dual_dmic_d0_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "speaker_mono_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &idmic_mono_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_qt_dmic_power,
	.pamp_off = msm_snddev_disable_qt_dmic_power,
};

static struct platform_device msm_qt_dual_dmic_d0_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_qt_dual_dmic_d0_data },
};

static struct snddev_icodec_data snddev_dual_mic_spkr_endfire_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "speaker_dual_mic_endfire_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &dual_mic_endfire_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_dmic_power,
	.pamp_off = msm_snddev_disable_dmic_power,
};

static struct platform_device msm_spkr_dual_mic_endfire_device = {
	.name = "snddev_icodec",
	.id = 15,
	.dev = { .platform_data = &snddev_dual_mic_spkr_endfire_data },
};

static struct adie_codec_action_unit dual_mic_broadside_8osr256_actions[] =
	HS_DMIC2_STEREO_OSR_256;

static struct adie_codec_hwsetting_entry dual_mic_broadside_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = dual_mic_broadside_8osr256_actions,
		.action_sz = ARRAY_SIZE(dual_mic_broadside_8osr256_actions),
	}
};

static struct adie_codec_dev_profile dual_mic_broadside_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = dual_mic_broadside_settings,
	.setting_sz = ARRAY_SIZE(dual_mic_broadside_settings),
};

static struct snddev_icodec_data snddev_hs_dual_mic_broadside_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_dual_mic_broadside_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &dual_mic_broadside_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_dmic_sec_power,
	.pamp_off = msm_snddev_disable_dmic_sec_power,
};

static struct platform_device msm_hs_dual_mic_broadside_device = {
	.name = "snddev_icodec",
	.id = 21,
	.dev = { .platform_data = &snddev_hs_dual_mic_broadside_data },
};

static struct snddev_icodec_data snddev_spkr_dual_mic_broadside_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "speaker_dual_mic_broadside_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &dual_mic_broadside_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_dmic_sec_power,
	.pamp_off = msm_snddev_disable_dmic_sec_power,
};

static struct platform_device msm_spkr_dual_mic_broadside_device = {
	.name = "snddev_icodec",
	.id = 18,
	.dev = { .platform_data = &snddev_spkr_dual_mic_broadside_data },
};

#endif

static struct snddev_hdmi_data snddev_hdmi_stereo_rx_data = {
	.capability = SNDDEV_CAP_RX ,
	.name = "hdmi_stereo_rx",
	.copp_id = HDMI_RX,
	.channel_mode = 0,
	.default_sample_rate = 48000,
};

static struct platform_device msm_snddev_hdmi_stereo_rx_device = {
	.name = "snddev_hdmi",
	.dev = { .platform_data = &snddev_hdmi_stereo_rx_data },
};

static struct snddev_mi2s_data snddev_mi2s_fm_tx_data = {
	.capability = SNDDEV_CAP_TX ,
	.name = "fmradio_stereo_tx",
	.copp_id = MI2S_TX,
	.channel_mode = 2, /* stereo */
	.sd_lines = MI2S_SD3, /* sd3 */
	.sample_rate = 48000,
};

static struct platform_device msm_mi2s_fm_tx_device = {
	.name = "snddev_mi2s",
	.dev = { .platform_data = &snddev_mi2s_fm_tx_data },
};

static struct snddev_mi2s_data snddev_mi2s_fm_rx_data = {
	.capability = SNDDEV_CAP_RX ,
	.name = "fmradio_stereo_rx",
	.copp_id = MI2S_RX,
	.channel_mode = 2, /* stereo */
	.sd_lines = MI2S_SD3, /* sd3 */
	.sample_rate = 48000,
};

static struct platform_device msm_mi2s_fm_rx_device = {
	.name = "snddev_mi2s",
	.id = 1,
	.dev = { .platform_data = &snddev_mi2s_fm_rx_data },
};

static struct adie_codec_action_unit iheadset_mic_tx_osr256_actions[] =
	HEADSET_TX_MONO_PRI_OSR_256;

static struct adie_codec_hwsetting_entry iheadset_mic_tx_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = iheadset_mic_tx_osr256_actions,
		.action_sz = ARRAY_SIZE(iheadset_mic_tx_osr256_actions),
	}
};

static struct adie_codec_dev_profile iheadset_mic_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = iheadset_mic_tx_settings,
	.setting_sz = ARRAY_SIZE(iheadset_mic_tx_settings),
};

static struct snddev_icodec_data snddev_headset_mic_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "headset_mono_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &iheadset_mic_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
};

static struct platform_device msm_headset_mic_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_headset_mic_data },
};

/* define the value for Earjack Loopback, TX */
static struct adie_codec_action_unit iheadset_mic_acs_tx_osr256_actions[] =
	HEADSET_TX_MONO_PRI_OSR_256;
static struct adie_codec_hwsetting_entry iheadset_mic_acs_tx_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = iheadset_mic_acs_tx_osr256_actions,
		.action_sz = ARRAY_SIZE(iheadset_mic_acs_tx_osr256_actions),
	}
};
static struct adie_codec_dev_profile iheadset_mic_acs_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = iheadset_mic_acs_tx_settings,
	.setting_sz = ARRAY_SIZE(iheadset_mic_acs_tx_settings),
};
static struct snddev_icodec_data snddev_headset_mic_acs_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "headset_acs_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &iheadset_mic_acs_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
};
static struct platform_device msm_headset_mic_acs_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_headset_mic_acs_data },
};



static struct adie_codec_action_unit
	ihs_stereo_speaker_stereo_rx_48KHz_osr256_actions[] =
#ifdef CONFIG_LGE_AUDIO_NO_NCP_MODE
    HPH_SPEAKER_RX_STEREO_AB_LEG;
#else
	SPEAKER_HPH_AB_CPL_PRI_STEREO_48000_OSR_256;
#endif /* CONFIG_LGE_AUDIO_NO_NCP_MODE */

static struct adie_codec_hwsetting_entry
	ihs_stereo_speaker_stereo_rx_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = ihs_stereo_speaker_stereo_rx_48KHz_osr256_actions,
		.action_sz =
		ARRAY_SIZE(ihs_stereo_speaker_stereo_rx_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile ihs_stereo_speaker_stereo_rx_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = ihs_stereo_speaker_stereo_rx_settings,
	.setting_sz = ARRAY_SIZE(ihs_stereo_speaker_stereo_rx_settings),
};

static struct snddev_icodec_data snddev_ihs_stereo_speaker_stereo_rx_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "headset_stereo_speaker_stereo_rx",
	.copp_id = 0,
	.profile = &ihs_stereo_speaker_stereo_rx_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_poweramp_on_hph_spk,
	.pamp_off = msm_snddev_poweramp_off_hph_spk,
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
};

static struct platform_device msm_ihs_stereo_speaker_stereo_rx_device = {
	.name = "snddev_icodec",
	.id = 22,
	.dev = { .platform_data = &snddev_ihs_stereo_speaker_stereo_rx_data },
};

/* define the value for BT_SCO */

static struct snddev_ecodec_data snddev_bt_sco_earpiece_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "bt_sco_rx",
	.copp_id = PCM_RX,
	.channel_mode = 1,
};

static struct snddev_ecodec_data snddev_bt_sco_mic_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "bt_sco_tx",
	.copp_id = PCM_TX,
	.channel_mode = 1,
};

struct platform_device msm_bt_sco_earpiece_device = {
	.name = "msm_snddev_ecodec",
	.dev = { .platform_data = &snddev_bt_sco_earpiece_data },
};

struct platform_device msm_bt_sco_mic_device = {
	.name = "msm_snddev_ecodec",
	.dev = { .platform_data = &snddev_bt_sco_mic_data },
};


/* define the value for BT_SCO BTTM(AT command BT Test Mode) */
//BTTM_RX BTTM_TX

static struct snddev_ecodec_data snddev_bt_sco_bttm_earpiece_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "bt_sco_bttm_rx",
	.copp_id = PCM_RX,
	.channel_mode = 1,
};

static struct snddev_ecodec_data snddev_bt_sco_bttm_mic_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "bt_sco_bttm_tx",
	.copp_id = PCM_TX,
	.channel_mode = 1,
};

struct platform_device msm_bt_sco_bttm_earpiece_device = {
	.name = "msm_snddev_ecodec",
	.dev = { .platform_data = &snddev_bt_sco_bttm_earpiece_data },
};

struct platform_device msm_bt_sco_bttm_mic_device = {
	.name = "msm_snddev_ecodec",
	.dev = { .platform_data = &snddev_bt_sco_bttm_mic_data },
};

static struct adie_codec_action_unit itty_mic_tx_osr256_actions[] =
	TTY_HEADSET_TX_MONO_OSR_256;

static struct adie_codec_hwsetting_entry itty_mono_tx_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = itty_mic_tx_osr256_actions,
		.action_sz = ARRAY_SIZE(itty_mic_tx_osr256_actions),
	},
};

static struct adie_codec_dev_profile itty_mono_tx_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = itty_mono_tx_settings,
	.setting_sz = ARRAY_SIZE(itty_mono_tx_settings),
};

static struct snddev_icodec_data snddev_itty_mono_tx_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE | SNDDEV_CAP_TTY),
	.name = "tty_headset_mono_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &itty_mono_tx_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
};

static struct platform_device msm_itty_mono_tx_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_itty_mono_tx_data },
};

static struct adie_codec_action_unit itty_stereo_48KHz_osr256_actions[] =
	TTY_HEADSET_RX_STEREO_AB_LEG;

static struct adie_codec_hwsetting_entry itty_mono_rx_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = itty_stereo_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(itty_stereo_48KHz_osr256_actions),
	},
};

static struct adie_codec_dev_profile itty_mono_rx_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = itty_mono_rx_settings,
	.setting_sz = ARRAY_SIZE(itty_mono_rx_settings),
};

static struct snddev_icodec_data snddev_itty_mono_rx_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE | SNDDEV_CAP_TTY),
	.name = "tty_headset_mono_rx",
	.copp_id = PRIMARY_I2S_RX,
	.profile = &itty_mono_rx_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_poweramp_on_tty,
	.pamp_off = msm_snddev_poweramp_off_tty,	
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
};

static struct platform_device msm_itty_mono_rx_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_itty_mono_rx_data },
};

static struct adie_codec_action_unit linein_pri_actions[] =
	LINEIN_PRI_STEREO_OSR_256;

static struct adie_codec_hwsetting_entry linein_pri_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = linein_pri_actions,
		.action_sz = ARRAY_SIZE(linein_pri_actions),
	},
};

static struct adie_codec_dev_profile linein_pri_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = linein_pri_settings,
	.setting_sz = ARRAY_SIZE(linein_pri_settings),
};

static struct snddev_icodec_data snddev_linein_pri_data = {
	.capability = SNDDEV_CAP_TX,
	.name = "linein_pri_tx",
	.copp_id = PRIMARY_I2S_TX,
	.profile = &linein_pri_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
};

static struct platform_device msm_linein_pri_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_linein_pri_data },
};

static struct adie_codec_action_unit auxpga_lb_lo_actions[] =
	LB_AUXPGA_LO_STEREO;

static struct adie_codec_hwsetting_entry auxpga_lb_lo_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = auxpga_lb_lo_actions,
		.action_sz = ARRAY_SIZE(auxpga_lb_lo_actions),
	},
};

static struct adie_codec_dev_profile auxpga_lb_lo_profile = {
	.path_type = ADIE_CODEC_LB,
	.settings = auxpga_lb_lo_settings,
	.setting_sz = ARRAY_SIZE(auxpga_lb_lo_settings),
};

static struct snddev_icodec_data snddev_auxpga_lb_lo_data = {
	.capability = SNDDEV_CAP_LB,
	.name = "speaker_stereo_lb",
	.copp_id = PRIMARY_I2S_RX,
	.profile = &auxpga_lb_lo_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_poweramp_on_spk,
	.pamp_off = msm_snddev_poweramp_off_spk,
	.dev_vol_type = SNDDEV_DEV_VOL_ANALOG,
};

static struct platform_device msm_auxpga_lb_lo_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_auxpga_lb_lo_data },
};

static struct adie_codec_action_unit auxpga_lb_hs_actions[] =
	LB_AUXPGA_HPH_AB_CPLS_STEREO;

static struct adie_codec_hwsetting_entry auxpga_lb_hs_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = auxpga_lb_hs_actions,
		.action_sz = ARRAY_SIZE(auxpga_lb_hs_actions),
	},
};

static struct adie_codec_dev_profile auxpga_lb_hs_profile = {
	.path_type = ADIE_CODEC_LB,
	.settings = auxpga_lb_hs_settings,
	.setting_sz = ARRAY_SIZE(auxpga_lb_hs_settings),
};

static struct snddev_icodec_data snddev_auxpga_lb_hs_data = {
	.capability = SNDDEV_CAP_LB,
	.name = "hs_stereo_lb",
	.copp_id = PRIMARY_I2S_RX,
	.profile = &auxpga_lb_hs_profile,
	.channel_mode = 2,
	.default_sample_rate = 48000,
	.voltage_on = msm_snddev_voltage_on,
	.voltage_off = msm_snddev_voltage_off,
	.dev_vol_type = SNDDEV_DEV_VOL_ANALOG,
};

static struct platform_device msm_auxpga_lb_hs_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_auxpga_lb_hs_data },
};

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t Hearing AID
static struct adie_codec_action_unit iearpiece_hac_48KHz_osr256_actions[] =
	HANDSET_RX_MONO_8000_OSR_256_HAC;

static struct adie_codec_hwsetting_entry iearpiece_hac_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = iearpiece_hac_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(iearpiece_hac_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile iearpiece_hac_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = iearpiece_hac_settings,
	.setting_sz = ARRAY_SIZE(iearpiece_hac_settings),
};

static struct snddev_icodec_data snddev_iearpiece_hac_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "handset_rx_hac",
	.copp_id = 0,
	.profile = &iearpiece_hac_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
};

static struct platform_device msm_iearpiece_hac_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_iearpiece_hac_data },
};
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t Hearing AID

static struct adie_codec_action_unit dual_nc_48KHz_osr256_actions[] =
	AMIC_DUAL_OSR_256; ///////////////
		
static struct adie_codec_hwsetting_entry dual_nc_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = dual_nc_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(dual_nc_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile dual_nc_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = dual_nc_settings,
	.setting_sz = ARRAY_SIZE(dual_nc_settings),
};

static struct snddev_icodec_data snddev_dual_nc_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_dual_nc_tx",
	.copp_id = 1,
	.profile = &dual_nc_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_dualmic_power,
	.pamp_off = msm_snddev_disable_dualmic_power,
};

static struct adie_codec_action_unit mic1_nc_48KHz_osr256_actions[] =
	AMIC_PRI_MONO_OSR_256; ///////////////
		
static struct adie_codec_hwsetting_entry mic1_nc_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = mic1_nc_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(mic1_nc_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile mic1_nc_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = mic1_nc_settings,
	.setting_sz = ARRAY_SIZE(mic1_nc_settings),
};

static struct snddev_icodec_data snddev_mic1_nc_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_mic1_nc_tx",
	.copp_id = 1,
	.profile = &mic1_nc_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
};


static struct adie_codec_action_unit mic2_nc_48KHz_osr256_actions[] =
	AMIC_SEC_MONO_OSR_256; ///////////////
	
static struct adie_codec_hwsetting_entry mic2_nc_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = mic2_nc_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(mic2_nc_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile mic2_nc_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = mic2_nc_settings,
	.setting_sz = ARRAY_SIZE(mic2_nc_settings),
};

static struct snddev_icodec_data snddev_mic2_nc_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_mic2_nc_tx",
	.copp_id = 1,
	.profile = &mic2_nc_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_submic_power,
	.pamp_off = msm_snddev_disable_submic_power,
};

static struct adie_codec_action_unit mic1_acs_48KHz_osr256_actions[] =
	AMIC_PRI_MONO_OSR_256_ACS; ///////////////
		
static struct adie_codec_hwsetting_entry mic1_acs_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = mic1_acs_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(mic1_acs_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile mic1_acs_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = mic1_acs_settings,
	.setting_sz = ARRAY_SIZE(mic1_acs_settings),
};


static struct snddev_icodec_data snddev_mic1_acs_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_mic1_acs_tx",
	.copp_id = 1,
	.profile = &mic1_acs_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
};


static struct platform_device msm_dual_nc_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_dual_nc_data },
};
static struct platform_device msm_mic1_nc_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_mic1_nc_data },
};
static struct platform_device msm_mic2_nc_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_mic2_nc_data },
};
static struct adie_codec_action_unit imic_record_48KHz_osr256_actions[] =
	HANDSET_RECORD_TX_PRI_MONO_OSR_256;

static struct adie_codec_hwsetting_entry imic_record_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = imic_record_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(imic_record_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile imic_record_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = imic_record_settings,
	.setting_sz = ARRAY_SIZE(imic_record_settings),
};

static struct snddev_icodec_data snddev_imic_record_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_record_tx",
	.copp_id = 1,
	.profile = &imic_record_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
};

static struct platform_device msm_imic_record_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_imic_record_data },
};

static struct platform_device msm_mic1_acs_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_mic1_acs_data },
};

#ifdef CONFIG_LGE_AUDIO
static struct adie_codec_action_unit submic_lb_48KHz_osr256_actions[] =
	SUB_MIC_LB_MONO_OSR_256;

static struct adie_codec_hwsetting_entry submic_lb_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = submic_lb_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(submic_lb_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile submic_lb_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = submic_lb_settings,
	.setting_sz = ARRAY_SIZE(submic_lb_settings),
};


static struct snddev_icodec_data snddev_ispkr_mic_lb_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "speaker_lb_mono_tx",
	.copp_id = 1,
	.profile = &submic_lb_profile,

	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_submic_power,
	.pamp_off = msm_snddev_disable_submic_power,
};


static struct platform_device msm_mic2_lb_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_ispkr_mic_lb_data },
};
#endif

static struct adie_codec_action_unit imic_vr_48KHz_osr256_actions[] =
	HANDSET_RECORD_TX_PRI_MONO_OSR_256_VR;

static struct adie_codec_hwsetting_entry imic_vr_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = imic_vr_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(imic_vr_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile imic_vr_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = imic_vr_settings,
	.setting_sz = ARRAY_SIZE(imic_vr_settings),
};

static struct snddev_icodec_data snddev_imic_vr_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_vr_tx",
	.copp_id = 1,
	.profile = &imic_vr_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
};

static struct platform_device msm_imic_vr_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_imic_vr_data },
};

//ACS_RX
static struct adie_codec_action_unit iearpiece_acs_48KHz_osr256_actions[] =
	HANDSET_ACS_RX_MONO_8000_OSR_256;
static struct adie_codec_hwsetting_entry iearpiece_acs_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = iearpiece_acs_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(iearpiece_acs_48KHz_osr256_actions),
	}
};
static struct adie_codec_dev_profile iearpiece_acs_profile = {
	.path_type = ADIE_CODEC_RX,
	.settings = iearpiece_acs_settings,
	.setting_sz = ARRAY_SIZE(iearpiece_acs_settings),
};

static struct snddev_icodec_data snddev_acs_iearpiece_data = {
	.capability = (SNDDEV_CAP_RX | SNDDEV_CAP_VOICE),
	.name = "handset_acs_rx",
	.copp_id = 0,
	.profile = &iearpiece_acs_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
};

static struct platform_device msm_iearpiece_acs_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_acs_iearpiece_data },
};


static struct adie_codec_action_unit imic_lgvm_record_48KHz_osr256_actions[] =
	HANDSET_RECORD_TX_PRI_MONO_OSR_256;

static struct adie_codec_hwsetting_entry imic_lgvm_record_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = imic_lgvm_record_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(imic_lgvm_record_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile imic_lgvm_record_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = imic_lgvm_record_settings,
	.setting_sz = ARRAY_SIZE(imic_lgvm_record_settings),
};

static struct snddev_icodec_data snddev_imic_lgvm_record_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_lgvm_tx",
	.copp_id = 1,
	.profile = &imic_lgvm_record_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_amic_power,
	.pamp_off = msm_snddev_disable_amic_power,
};

static struct platform_device msm_imic_lgvm_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_imic_lgvm_record_data },
};

static struct adie_codec_action_unit imic_lgcam_record_48KHz_osr256_actions[] =
	AUXIN_LGCAM_MONO_OSR_256;

static struct adie_codec_hwsetting_entry imic_lgcam_record_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions = imic_lgcam_record_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE(imic_lgcam_record_48KHz_osr256_actions),
	}
};

static struct adie_codec_dev_profile imic_lgcam_record_profile = {
	.path_type = ADIE_CODEC_TX,
	.settings = imic_lgcam_record_settings,
	.setting_sz = ARRAY_SIZE(imic_lgcam_record_settings),
};

static struct snddev_icodec_data snddev_imic_lgcam_record_data = {
	.capability = (SNDDEV_CAP_TX | SNDDEV_CAP_VOICE),
	.name = "handset_lgcam_tx",
	.copp_id = 1,
	.profile = &imic_lgcam_record_profile,
	.channel_mode = 1,
	.default_sample_rate = 48000,
	.pamp_on = msm_snddev_enable_submic_power,
	.pamp_off = msm_snddev_disable_submic_power,
};

static struct platform_device msm_imic_lgcam_device = {
	.name = "snddev_icodec",
	.dev = { .platform_data = &snddev_imic_lgcam_record_data },
};

adie_codec_action_Cmd qtr8615l_cal_db[QTR8615L_CAL_DB_MAX] = {
    {iearpiece_48KHz_osr256_actions,                17}, // RCV_RX1_L_GAIN
    {iearpiece_48KHz_osr256_actions,                13}, // RCV_GAIN
    {imic_48KHz_osr256_actions,                      9}, // RCV_FE_GAIN,
    {imic_48KHz_osr256_actions,                     22}, // RCV_TX1_GAIN
    {ispkr_stereo_48KHz_osr256_actions,              6}, // SPK_RX1_L_GAIN
    {ispkr_stereo_48KHz_osr256_actions,              7}, // SPK_RX1_R_GAIN
    {ispkr_stereo_48KHz_osr256_actions,             27}, // SPK_L_GAIN
    {ispkr_stereo_48KHz_osr256_actions,             28}, // SPK_R_GAIN
#ifdef CONFIG_LGE_AUDIO_USE_AUXMIC_FOR_SPEAKER_MODE
    {submic_48KHz_osr256_actions,				 15}, // SPK_FE_GAIN 0x0D
    {submic_48KHz_osr256_actions,				21}, // SPK_TX1_GAIN 0x86
#else
    {ispkr_mic_48KHz_osr256_actions,                 9}, // SPK_FE_GAIN
    {ispkr_mic_48KHz_osr256_actions,                22}, // SPK_TX1_GAIN
#endif
    {ihs_stereo_48KHz_osr256_actions,                6}, // HPH_RX1_L_GAIN
    {ihs_stereo_48KHz_osr256_actions,                7}, // HPH_RX1_R_GAIN
    {ihs_stereo_48KHz_osr256_actions,               25}, // HPH_L_GAIN
    {ihs_stereo_48KHz_osr256_actions,               26}, // HPH_R_GAIN
    {iheadset_mic_tx_osr256_actions,                15}, // HPH_FE_GAIN
    {iheadset_mic_tx_osr256_actions,                21}, // HPH_TX1_GAIN
    {itty_stereo_48KHz_osr256_actions,               6}, // TTY_RX1_L_GAIN
    {itty_stereo_48KHz_osr256_actions,               7}, // TTY_RX1_R_GAIN
    {itty_stereo_48KHz_osr256_actions,              25}, // TTY_L_GAIN
    {itty_stereo_48KHz_osr256_actions,              26}, // TTY_R_GAIN
    {itty_mic_tx_osr256_actions,                    15}, // TTY_FE_GAIN
    {itty_mic_tx_osr256_actions,                    21}, // TTY_TX1_GAIN
    {iearpiece_hac_48KHz_osr256_actions,            17}, // HAC_RX1_L_GAIN
    {iearpiece_hac_48KHz_osr256_actions,            13}, // HAC_GAIN
    {ispkr_stereo_playback_48KHz_osr256_actions,     6}, // P_SPK_RX1_L_GAIN
    {ispkr_stereo_playback_48KHz_osr256_actions,     7}, // P_SPK_RX1_R_GAIN
    {ispkr_stereo_playback_48KHz_osr256_actions,    27}, // P_SPK_L_GAIN
    {ispkr_stereo_playback_48KHz_osr256_actions,    28}, // P_SPK_R_GAIN
    {ihs_stereo_playback_48KHz_osr256_actions,       6}, // P_HPH_RX1_L_GAIN
    {ihs_stereo_playback_48KHz_osr256_actions,       7}, // P_HPH_RX1_R_GAIN
    {ihs_stereo_playback_48KHz_osr256_actions,      25}, // P_HPH_L_GAIN
    {ihs_stereo_playback_48KHz_osr256_actions,      26}, // P_HPH_R_GAIN
    {imic_record_48KHz_osr256_actions,               9}, // RECORD_FE_GAIN,
    {imic_record_48KHz_osr256_actions,              22}, // RECORD_TX1_GAIN    
    {dual_mic_endfire_8KHz_osr256_actions,              15}, // D_MAIN_FE1_GAIN 0x0D
    {dual_mic_endfire_8KHz_osr256_actions,              24}, // D_MAIN_TX1_L_GAIN 0x86
    {dual_mic_endfire_8KHz_osr256_actions,              16}, // D_SUB_FE2_GAIN 0x0E
    {dual_mic_endfire_8KHz_osr256_actions,              25}, // D_SUB_TX1_R_GAIN 0x87
};

#ifdef CONFIG_DEBUG_FS
static struct adie_codec_action_unit
	ihs_stereo_rx_class_d_legacy_48KHz_osr256_actions[] =
	HPH_PRI_D_LEG_STEREO;

static struct adie_codec_hwsetting_entry
	ihs_stereo_rx_class_d_legacy_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions =
		ihs_stereo_rx_class_d_legacy_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE
		(ihs_stereo_rx_class_d_legacy_48KHz_osr256_actions),
	}
};

static struct adie_codec_action_unit
	ihs_stereo_rx_class_ab_legacy_48KHz_osr256_actions[] =
	HPH_PRI_AB_LEG_STEREO;

static struct adie_codec_hwsetting_entry
	ihs_stereo_rx_class_ab_legacy_settings[] = {
	{
		.freq_plan = 48000,
		.osr = 256,
		.actions =
		ihs_stereo_rx_class_ab_legacy_48KHz_osr256_actions,
		.action_sz = ARRAY_SIZE
		(ihs_stereo_rx_class_ab_legacy_48KHz_osr256_actions),
	}
};

static void snddev_hsed_config_modify_setting(int type)
{
	struct platform_device *device;
	struct snddev_icodec_data *icodec_data;

	device = &msm_headset_stereo_device;
	icodec_data = (struct snddev_icodec_data *)device->dev.platform_data;

	if (icodec_data) {
		if (type == 1) {
			icodec_data->voltage_on = NULL;
			icodec_data->voltage_off = NULL;
			icodec_data->profile->settings =
				ihs_stereo_rx_class_d_legacy_settings;
			icodec_data->profile->setting_sz =
			ARRAY_SIZE(ihs_stereo_rx_class_d_legacy_settings);
		} else if (type == 2) {
			icodec_data->voltage_on = NULL;
			icodec_data->voltage_off = NULL;
			icodec_data->profile->settings =
				ihs_stereo_rx_class_ab_legacy_settings;
			icodec_data->profile->setting_sz =
			ARRAY_SIZE(ihs_stereo_rx_class_ab_legacy_settings);
		}
	}
}

static void snddev_hsed_config_restore_setting(void)
{
	struct platform_device *device;
	struct snddev_icodec_data *icodec_data;

	device = &msm_headset_stereo_device;
	icodec_data = (struct snddev_icodec_data *)device->dev.platform_data;

	if (icodec_data) {
		icodec_data->voltage_on = msm_snddev_voltage_on;
		icodec_data->voltage_off = msm_snddev_voltage_off;
		icodec_data->profile->settings = ihs_stereo_rx_settings;
		icodec_data->profile->setting_sz =
			ARRAY_SIZE(ihs_stereo_rx_settings);
	}
}

static ssize_t snddev_hsed_config_debug_write(struct file *filp,
	const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	char *lb_str = filp->private_data;
	char cmd;

	if (get_user(cmd, ubuf))
		return -EFAULT;

	if (!strcmp(lb_str, "msm_hsed_config")) {
		switch (cmd) {
		case '0':
			snddev_hsed_config_restore_setting();
			break;

		case '1':
			snddev_hsed_config_modify_setting(1);
			break;

		case '2':
			snddev_hsed_config_modify_setting(2);
			break;

		default:
			break;
		}
	}
	return cnt;
}

static int snddev_hsed_config_debug_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static const struct file_operations snddev_hsed_config_debug_fops = {
	.open = snddev_hsed_config_debug_open,
	.write = snddev_hsed_config_debug_write
};

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t Acoustic Calibration  
char *strtok_r(char *s, const char *delim, char **last)
{
    char *spanp;
    int c, sc;
    char *tok;


    if (s == NULL && (s = *last) == NULL)
        return (NULL);

    /*
    * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
    */
    cont:
    c = *s++;
    for (spanp = (char *)delim; (sc = *spanp++) != 0;) {
        if (c == sc) goto cont;
    }

    if (c == 0) {		/* no non-delimiter characters */
        *last = NULL;
        return (NULL);
    }
    tok = s - 1;

    /*
    * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
    * Note that delim must have one NUL; we stop if we see that, too.
    */
    for (;;) {
        c = *s++;
        spanp = (char *)delim;
        do {
            if ((sc = *spanp++) == c) {
                if (c == 0)
                    s = NULL;
                else
                    s[-1] = 0;

                *last = s;
                return (tok);
            }
        } while (sc != 0);
    }
    /* NOTREACHED */
}

char *strtok(char *s, const char *delim)
{
    static char *last;

    return strtok_r(s, delim, &last);
}

u16 strtol(const char *nptr, char **endptr, int base)
{
    const char *s;
    long acc, cutoff;
    int c;
    int neg, any, cutlim;

    /*
    * Skip white space and pick up leading +/- sign if any.
    * If base is 0, allow 0x for hex and 0 for octal, else
    * assume decimal; if base is already 16, allow 0x.
    */
    s = nptr;
    do {
        c = (unsigned char) *s++;
    } while (isspace(c));
    
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else {
        neg = 0;
        if (c == '+')
        c = *s++;
    }
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
    * Compute the cutoff value between legal numbers and illegal
    * numbers.  That is the largest legal value, divided by the
    * base.  An input number that is greater than this value, if
    * followed by a legal input character, is too big.  One that
    * is equal to this value may be valid or not; the limit
    * between valid and invalid numbers is then based on the last
    * digit.  For instance, if the range for longs is
    * [-2147483648..2147483647] and the input base is 10,
    * cutoff will be set to 214748364 and cutlim to either
    * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
    * a value > 214748364, or equal but the next digit is > 7 (or 8),
    * the number is too big, and we will return a range error.
    *
    * Set any if any `digits' consumed; make it negative to indicate
    * overflow.
    */
    cutoff = neg ? LONG_MIN : LONG_MAX;
    cutlim = cutoff % base;
    cutoff /= base;
    if (neg) {
        if (cutlim > 0) {
            cutlim -= base;
            cutoff += 1;
        }
        cutlim = -cutlim;
    }
    for (acc = 0, any = 0;; c = (u16) *s++) {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;

        if (c >= base)
            break;

        if (any < 0)
            continue;

        if (neg) {
            if (acc < cutoff || (acc == cutoff && c > cutlim)) {
                any = -1;
                acc = LONG_MIN;
            } else {
                any = 1;
                acc *= base;
                acc -= c;
            }
        } else {
            if (acc > cutoff || (acc == cutoff && c > cutlim)) {
                any = -1;
                acc = LONG_MAX;
            } else {
                any = 1;
                acc *= base;
                acc += c;
            }
        }
    }
    if (endptr != 0)
        *endptr = (char *) (any ? s - 1 : nptr);

    return (u16)acc;
}

int StrUpr( char *str ) 
{ 
    int loop = 0; 
    while( str[loop] != '\0' ) 
    {
        str[loop] = (char) toupper( str[loop] );
        loop++;
    }
    return loop; 
}

static int get_wm9093_str_to_index( char *inputstr)
{
	int return_val = 0;
	static struct regulator *reg = NULL;
	unsigned int M_VAL = GP_MN_M_DEFAULT;
	unsigned int N_VAL = GP_MN_N_DEFAULT;
	unsigned int D_VAL = GP_MN_D_DEFAULT;

	void __iomem *vib_base_ptr = 0;
	printk("[vibrator] %s is called \n", __func__);
	vib_base_ptr = ioremap_nocache(MSM_PDM_BASE_REG,0x20 );

	writel((M_VAL & GPMN_M_MASK), vib_base_ptr + GP_MN_CLK_MDIV_REG );
	writel((~( N_VAL - M_VAL )&GPMN_N_MASK), vib_base_ptr + GP_MN_CLK_NDIV_REG);
	
	
	StrUpr( inputstr );
	if(strcmp(inputstr, "SPK_IN_VOL") == 0)
		return_val = SPK_IN2_VOL;
	else if(strcmp(inputstr, "SPK_BOOST") == 0)
		return_val = SPK_BOOST;
	else if(strcmp(inputstr, "SPK_OUT_VOL") == 0)
		return_val = SPK_OUT_VOL;
	else if(strcmp(inputstr, "HPH_IN_VOL") == 0)
		return_val = HPH_IN1_VOL;
	else if(strcmp(inputstr, "HPH_OUT_VOL") == 0)
		return_val = HPH_OUT_VOL;
	else if(strcmp(inputstr, "TTY_IN1_VOL") == 0)
		return_val = TTY_IN1_VOL;
	else if(strcmp(inputstr, "TTY_OUT_VOL") == 0)
		return_val = TTY_OUT_VOL;
	else if(strcmp(inputstr, "HPH_SPK_IN_VOL") == 0)
		return_val = HPH_SPK_IN1_VOL;
	else if(strcmp(inputstr, "HPH_SPK_BOOST") == 0)
		return_val = HPH_SPK_BOOST;
	else if(strcmp(inputstr, "HPH_SPK_OUT_SPK_VOL") == 0)
		return_val = HPH_SPK_OUT_SPK_VOL;
	else if(strcmp(inputstr, "HPH_SPK_OUT_HPH_VOL") == 0)
		return_val = HPH_SPK_OUT_HPH_VOL;
	else if(strcmp(inputstr, "P_SPK_IN2_VOL") == 0)
		return_val = P_SPK_IN2_VOL;
	else if(strcmp(inputstr, "P_SPK_BOOST") == 0)
		return_val = P_SPK_BOOST;
	else if(strcmp(inputstr, "P_SPK_OUT_VOL") == 0)
		return_val = P_SPK_OUT_VOL;
	else if(strcmp(inputstr, "P_HPH_IN1_VOL") == 0)
		return_val = P_HPH_IN1_VOL;
	else if(strcmp(inputstr, "P_HPH_OUT_VOL") == 0)
		return_val = P_HPH_OUT_VOL;
#ifdef VIBRATOR_TEST
	else if(strcmp(inputstr, "VIBRATOR_ON") == 0)
	{
		D(KERN_INFO "================Eunwoo Vibrator On\n"); 		
		return_val = -1;
		reg = regulator_get(NULL, "8901_l1");
		regulator_set_voltage(reg, 3000000, 3000000);
		regulator_enable(reg);
#if 0		
		D_VAL = ((PWM_MAX_HALF_DUTY*128) >> 7)+ GP1_D_DEFAULT;

		REG_WRITEL(
				(((M_VAL & 0xffU) <<16U) + /* M_VAL[23:16] */
				 ((~(D_VAL<<1)) & 0xffU)),  /* D_VAL[7:0] */
				GP1_MD_REG);
		REG_WRITEL( 
				((((~(N_VAL-M_VAL))& 0xffU) <<16U) + /* N_VAL[23:16] */
				 (1U<<11U) +  /* CLK_ROOT_ENA[11]  : Enable(1) */
				 (0U<<10U) +  /* CLK_INV[10]       : Disable(0) */
				 (1U<<9U) +	 /* CLK_BRANCH_ENA[9] : Enable(1) */
				 (1U<<8U) +   /* NMCNTR_EN[8]      : Enable(1) */
				 (0U<<7U) +   /* MNCNTR_RST[7]     : Not Active(0) */
				 (2U<<5U) +   /* MNCNTR_MODE[6:5]  : Dual-edge mode(2) */
				 (3U<<3U) +   /* PRE_DIV_SEL[4:3]  : Div-4 (3) */
				 (0U<<0U)),   /* SRC_SEL[2:0]      : pxo (0)  */
				GP1_NS_REG);
#else
#ifdef CONFIG_LGE_LGT_AUDIO //ew0804.kim vibrator test mode
		D_VAL = ((GP_MN_N_DEFAULT*128) >> 8)+ GP_MN_D_DEFAULT;
#else
		D_VAL = ((GP_MN_D_DEFAULT*128) >> 7)+ GP_MN_D_DEFAULT;
#endif
		if (D_VAL > PWM_MAX_DUTY ) D_VAL = PWM_MAX_DUTY;
		if (D_VAL < PWM_MIN_DUTY ) D_VAL = PWM_MIN_DUTY;

		printk(KERN_INFO "LGE: %s D_VAL = 0x%X %d\n", __func__,D_VAL,D_VAL);

		writel(D_VAL & GPMN_D_MASK, vib_base_ptr + GP_MN_CLK_DUTY_REG);
#endif

		gpio_set_value_cansleep(158, 1);
	}
	else if(strcmp(inputstr, "VIBRATOR_OFF") == 0)
	{
		reg = regulator_get(NULL, "8901_l1");
		regulator_disable(reg);
		regulator_put(reg);
#if 0
		REG_WRITEL( 
				(((M_VAL & 0xffU) <<16U) + /* M_VAL[23:16] */
				 ((~(D_VAL<<1)) & 0xffU)),  /* D_VAL[7:0] */
				GP1_MD_REG);
		REG_WRITEL( 
				((((~(N_VAL-M_VAL))& 0xffU) <<16U) + /* N_VAL[23:16] */
				 (0U<<11U) +  /* CLK_ROOT_ENA[11]  : Disable(0) */
				 (0U<<10U) +  /* CLK_INV[10] 	  : Disable(0) */
				 (0U<<9U) +	 /* CLK_BRANCH_ENA[9] : Disable(0) */
				 (0U<<8U) +   /* NMCNTR_EN[8]      : Disable(0) */
				 (0U<<7U) +   /* MNCNTR_RST[7]     : Not Active(0) */
				 (2U<<5U) +   /* MNCNTR_MODE[6:5]  : Dual-edge mode(2) */
				 (3U<<3U) +   /* PRE_DIV_SEL[4:3]  : Div-4 (3) */
				 (0U<<0U)),   /* SRC_SEL[2:0]      : pxo (0)  */
				GP1_NS_REG);	
#else
		writel(GP_MN_D_DEFAULT & GPMN_D_MASK, vib_base_ptr + GP_MN_CLK_DUTY_REG);
#endif
		D(KERN_INFO "================Eunwoo Vibrator Off\n"); 		
		gpio_set_value_cansleep(158, 0);
		return_val = -1;
	}
#endif
	else	
		return_val = -1;
	
		D(KERN_INFO "WM9093 CONFIG[Line %d] str = %s retun val = %d \n", __LINE__ , inputstr, return_val ); 			

	iounmap(vib_base_ptr);
	return return_val;

}

void set_wm9093_cal_db(int writeflag, int AMPParamIndex, u16 cal_db)
{
//	pr_info("%s [%d 0x%04X]\n", __func__, AMPParamIndex, cal_db);    

	wmCodecCmd wmCmd;
    switch(AMPParamIndex) {
        case SPK_IN2_VOL :
            seq_tuning_lin_to_spkout[4].wmdata = seq_tuning_lin_to_spkout[5].wmdata= cal_db;
//			D(KERN_INFO "WM9093 Tuning SET reg = 0x%X, data = 0x%X\n",seq_tuning_lin_to_spkout[4].wmaddress,seq_tuning_lin_to_spkout[4].wmdata);
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_spkout[4].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
				
				wmCmd.wmaddress = seq_tuning_lin_to_spkout[5].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);

			}
            break;

        case SPK_BOOST :
            seq_tuning_lin_to_spkout[10].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_spkout[10].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;    

        case SPK_OUT_VOL :
            seq_tuning_lin_to_spkout[11].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_spkout[11].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
			
            break;    

        case HPH_IN1_VOL :
            seq_tuning_lin_to_headset[4].wmdata = seq_tuning_lin_to_headset[5].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset[4].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			
				wmCmd.wmaddress = seq_tuning_lin_to_headset[5].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;

        case HPH_OUT_VOL :
            seq_tuning_lin_to_headset[11].wmdata = seq_tuning_lin_to_headset[12].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset[11].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			
			wmCmd.wmaddress = seq_tuning_lin_to_headset[12].wmaddress;
			wmCmd.wmdata = cal_db;
			lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;

        case TTY_IN1_VOL :
            seq_tuning_lin_to_headset_tty[4].wmdata = seq_tuning_lin_to_headset_tty[5].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset_tty[4].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			
				wmCmd.wmaddress = seq_tuning_lin_to_headset_tty[5].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;

        case TTY_OUT_VOL :
            seq_tuning_lin_to_headset_tty[11].wmdata = seq_tuning_lin_to_headset_tty[12].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset_tty[11].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			
			wmCmd.wmaddress = seq_tuning_lin_to_headset_tty[12].wmaddress;
			wmCmd.wmdata = cal_db;
			lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;


        case HPH_SPK_IN1_VOL :
            seq_tuning_lin_to_headset_spkout[4].wmdata = seq_tuning_lin_to_headset_spkout[5].wmdata = cal_db;
			if(writeflag)
			{

				wmCmd.wmaddress = seq_tuning_lin_to_headset_spkout[4].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			
				wmCmd.wmaddress = seq_tuning_lin_to_headset_spkout[5].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;

        case HPH_SPK_BOOST :
            seq_tuning_lin_to_headset_spkout[8].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset_spkout[8].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;

        case HPH_SPK_OUT_SPK_VOL :
            seq_tuning_lin_to_headset_spkout[9].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset_spkout[9].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}			
            break;

        case HPH_SPK_OUT_HPH_VOL :
            seq_tuning_lin_to_headset_spkout[15].wmdata = seq_tuning_lin_to_headset_spkout[16].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset_spkout[15].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			
			wmCmd.wmaddress = seq_tuning_lin_to_headset_spkout[16].wmaddress;
			wmCmd.wmdata = cal_db;
			lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}			
            break;
        case P_SPK_IN2_VOL :
            seq_tuning_lin_to_spkout_playback[4].wmdata = seq_tuning_lin_to_spkout_playback[5].wmdata= cal_db;
//			D(KERN_INFO "WM9093 Tuning SET reg = 0x%X, data = 0x%X\n",seq_tuning_lin_to_spkout[4].wmaddress,seq_tuning_lin_to_spkout[4].wmdata);
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_spkout_playback[4].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
				
				wmCmd.wmaddress = seq_tuning_lin_to_spkout_playback[5].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);

			}
            break;

        case P_SPK_BOOST :
            seq_tuning_lin_to_spkout_playback[10].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_spkout_playback[10].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;    

        case P_SPK_OUT_VOL :
            seq_tuning_lin_to_spkout_playback[11].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_spkout_playback[11].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
			
            break;    

        case P_HPH_IN1_VOL :
            seq_tuning_lin_to_headset_playback[4].wmdata = seq_tuning_lin_to_headset_playback[5].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset_playback[4].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			
				wmCmd.wmaddress = seq_tuning_lin_to_headset_playback[5].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}
            break;

        case P_HPH_OUT_VOL :
            seq_tuning_lin_to_headset_playback[11].wmdata = seq_tuning_lin_to_headset_playback[12].wmdata = cal_db;
			if(writeflag)
			{
				wmCmd.wmaddress = seq_tuning_lin_to_headset_playback[11].wmaddress;
				wmCmd.wmdata = cal_db;
				lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			
			wmCmd.wmaddress = seq_tuning_lin_to_headset_playback[12].wmaddress;
			wmCmd.wmdata = cal_db;
			lge_audio_wm9093_platform.wm9093_cmd_register(wmCmd);
			}			
            break;

        default :
            break;
    }

}

int audio_subsystem_renewal(void)
{
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
    const char* AudioSubsystemPath  = "/data/wm9093_i_vzw.txt";
    const char* AudioSubsystemPath2 = "/etc/wm9093_i_vzw.txt";
#else
    const char* AMPDefaultFilename = "/etc/amp.txt";
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */
    struct file *filp;
    ssize_t read_size = 0;
    char data_array[1000];
    char *token = NULL;
    char *separator = "\n,:";
    int AMPParamIndex = 0;
    mm_segment_t fs = get_fs();

    set_fs(get_ds());

    filp = filp_open(AudioSubsystemPath, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("%s Unable to load %s.\n", __func__, AudioSubsystemPath);        
        filp = filp_open(AudioSubsystemPath2, O_RDONLY, 0);  
        if (IS_ERR(filp)) {
            pr_err("%s Unable to load %s.\n", __func__, AudioSubsystemPath2);     
            set_fs(fs);            
            return (int)-1;
            }
        else
            pr_info("%s load %s\n", __func__, AudioSubsystemPath2);
        }
    else
        pr_info("%s load %s\n", __func__, AudioSubsystemPath);

    read_size = filp->f_op->read(filp, data_array, 1000, &filp->f_pos);
    token = strtok(data_array, separator);

    while ((token = strtok(NULL, separator)) != NULL) {
        token = strtok(NULL, separator);
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
        set_wm9093_cal_db(0 , AMPParamIndex, (u16)strtol(token, NULL, 16));
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */
        AMPParamIndex++;
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
        if (AMPParamIndex == WM9093_CAL_DB_MAX)
            break;
#else
        if (AMPParamIndex == AMP_CAL_DB_MAX)
            break;
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */
    }
    
    filp_close(filp, NULL);

    set_fs(fs);

    pr_info("%s is done.\n", __func__);  

    return (int)1;
}

int get_wm9093_cal_db(char *data_array, int *data_len)
{
		int 	buff_len=0;
		char	str[1000];
		int 	cnt = 0;
		
		memset(data_array, 0, ARRAY_SIZE(str));  
		memset(str, 0, ARRAY_SIZE(str));  
	
		/* Header */
		sprintf(str, "WM9093 for %s", "VS920");
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';
	
		/* SPK_IN1_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_spkout[4].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';
	
		/* SPK_BOOST */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_spkout[10].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  
	
		/* SPK_OUT_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_spkout[11].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  
	
		/* HPH_IN1_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset[4].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  
	
		/* HPH_OUT_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset[11].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  

		/* TTY_IN1_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset_tty[4].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  
	
		/* TTY_OUT_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset_tty[11].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  

	
		/* HPH_SPK_IN1_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset_spkout[4].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';	  
	
		/* HPH_SPK_BOOST */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset_spkout[8].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';	  
	
		/* HPH_SPK_OUT_SPK_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset_spkout[9].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';	  
	
		/* HPH_SPK_OUT_HPH_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset_spkout[15].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';	  

		/* P_SPK_IN1_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_spkout_playback[4].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';
	
		/* P_SPK_BOOST */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_spkout_playback[10].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  
	
		/* P_SPK_OUT_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_spkout_playback[11].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  
	
		/* P_HPH_IN1_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset_playback[4].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';				  
	
		/* P_HPH_OUT_VOL */
		sprintf(str, wm9093_cfg_item[cnt++], seq_tuning_lin_to_headset_playback[11].wmdata);
		if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
		memcpy(&(data_array[buff_len]), str, strlen(str));
		buff_len +=  strlen(str);
		data_array[buff_len++] = '\n';			
	
	   END_OF_CODES:
	
		*data_len  = buff_len;
	
	//	pr_info("%s buff_len is %d\n", __func__, buff_len);    
	
		return *data_len;

}

int audio_subsystem_current_db(void)
{
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
    const char* AudioSubsystemPath  = "/data/wm9093_i_vzw.txt";
#else
    const char* AMPDefaultFilename = "/etc/amp.txt";
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */
    struct file *filp;
    char data_array[1000];
    int data_len = 0;    
    mm_segment_t fs = get_fs();

    set_fs(get_ds());

    filp = filp_open(AudioSubsystemPath, O_CREAT | O_WRONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("%s Unable to load %s\n", __func__, AudioSubsystemPath);
        set_fs(fs);            
        return (int)-1;        
        }
    else
        pr_info("%s load %s\n", __func__, AudioSubsystemPath);
    
    get_wm9093_cal_db(data_array, &data_len);

    if (filp->f_op->write(filp, data_array, data_len, &filp->f_pos) < 0)
        pr_err("%s write failed.\n", AudioSubsystemPath);        

    filp_close(filp, NULL);

    set_fs(fs);

    pr_info("%s is done.\n", __func__);  

    return (int)1;
}

static int get_str_and_parameters(char *buf, char *str , long int *param1, int num_of_par)
{
	char *token;
	int base, cnt;

	token = strsep(&buf, " ");
	strcpy(str, token);
	token = strsep(&buf, " ");
	for (cnt = 0; cnt < num_of_par; cnt++) {
		if (token != NULL) {
			if ((token[1] == 'x') || (token[1] == 'X'))
				base = 16;
			else
				base = 10;

			if (strict_strtoul(token, base, &param1[cnt]) != 0)
				return -EINVAL;

			token = strsep(&buf, " ");
			}
		else
			return -EINVAL;
	}
	return 0;
}

static int lge_wm9093_cal_tool_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t lge_wm9093_debug_read(struct file *file, char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char lbuf[8];

	snprintf(lbuf, sizeof(lbuf), "0x%x\n", read_data);
	return simple_read_from_buffer(ubuf, count, ppos, lbuf, strlen(lbuf));
}

static ssize_t lge_wm9093_cal_tool_write(struct file *filp,
	const char __user *ubuf, size_t cnt, loff_t *ppos)
{
		char *access_str = filp->private_data;
		char lbuf[32],strbuf[20];
		int rc;
//		int i;
//		int read_result;
		long int param[5];
	
		if (cnt > sizeof(lbuf) - 1)
			return -EINVAL;
	
		rc = copy_from_user(lbuf, ubuf, cnt);
		if (rc)
			return -EFAULT;
	
		lbuf[cnt] = '\0';
	
		if (!strcmp(access_str, "wmtuning")) {
	
#if 0		
			if (get_parameters(lbuf, param, 1) == 0) {
				
				switch (param[0]) {
				case 1:
					wm9093TuningFlag = 1;
					D(KERN_INFO " WM9093 Tuning Flag = %d", wm9093TuningFlag );
					break;
				case 0:
					wm9093TuningFlag = 0;
					D(KERN_INFO "WM9093 Tuning Flag = %d", wm9093TuningFlag );
					break;
				default:
					rc = -EINVAL;
					break;
				}
	
				memset(strbuf , 0 , sizeof strbuf);
				rc = get_str_and_parameters(lbuf, strbuf, param, 1);
			
				StrUpr( strbuf );
				if(strcmp(strbuf, "ON") == 0)
				{
					wm9093TuningFlag = param[0];
					D(KERN_INFO "WM9093 Tuning Flag = %d", wm9093TuningFlag );
				}
				else if(strcmp(strbuf, "WRITEDATA") == 0)
				{
					audio_subsystem_current_db();
				}
				else if(strcmp(strbuf, "READDATA") == 0)
				{
					audio_subsystem_renewal();
				}
							
			}
#endif		
			memset(strbuf , 0 , sizeof strbuf);
			rc = get_str_and_parameters(lbuf, strbuf, param, 1);
			
			StrUpr( strbuf );
			if(strcmp(strbuf, "ON") == 0)
			{
				wm9093TuningFlag = param[0];
				lge_audio_wm9093_platform.bTuningOnOff = wm9093TuningFlag;
				D(KERN_INFO "WM9093 Tuning Flag = %d", wm9093TuningFlag );
			}
			else if(strcmp(strbuf, "WRITEDATA") == 0)
			{
				audio_subsystem_current_db();
			}
			else if(strcmp(strbuf, "READDATA") == 0)
			{
				audio_subsystem_renewal();
			}

		} else if (!strcmp(access_str, "wmwrite")) {
			/* write */
			memset(strbuf , 0 , sizeof strbuf);
			rc = get_str_and_parameters(lbuf, strbuf, param, 1);
			D(KERN_INFO "WM9093 wmwrite : str = %s\n",strbuf);
#if 0		
			if ((param[0] <= 0xFF) && (param[1] <= 0xFFFF) &&(rc == 0)){
#else
			if ((param[0] <= 0xFFFF) &&(rc == 0)){
#endif
#if 0			
				amp_write_register(param[0],param[1]);
				D(KERN_INFO "WM9093 wmwrite : 0x%02X val 0x%04X\n", (u8)param[0], (u16)param[1]);
				amp_read_register((u8)param[0], &reg_val);
				D(KERN_INFO "WM9093 wmwrite : Read - reg 0x%02X val 0x%04X\n", (u8)param[0], reg_val);
#endif
				set_wm9093_cal_db (1, get_wm9093_str_to_index(strbuf) ,(u16) param[0]);

			}else
				rc = -EINVAL;
		} else if (!strcmp(access_str, "wmread")) {
			/* read */
#if 0		
			rc = get_parameters(lbuf, param, 1);
			if ((param[0] <= 0xFF) && (rc == 0)){
				amp_read_register((u8)param[0], &reg_val);
				D(KERN_INFO "WM9093 reg 0x%02X val 0x%04X\n", (u8)param[0], reg_val);
			}	
#endif
			memset(strbuf , 0 , sizeof strbuf);
			rc = get_str_and_parameters(lbuf, strbuf, param, 1);
			
			StrUpr( strbuf );
			if(strcmp(strbuf, "SPK") == 0)
				lge_audio_wm9093_platform.wm9093_reg_dump(ICODEC_SPEAKER_RX);
			else if(strcmp(strbuf, "HDSET") == 0)
				lge_audio_wm9093_platform.wm9093_reg_dump(ICODEC_HEADSET_ST_RX);
			else if(strcmp(strbuf, "PSPK") == 0)
				lge_audio_wm9093_platform.wm9093_reg_dump(ICODEC_SPEAKER_PLAYBACK_RX);
			else if(strcmp(strbuf, "PHDSET") == 0)
				lge_audio_wm9093_platform.wm9093_reg_dump(ICODEC_HEADSET_ST_PLAYBACK_RX);
			else if(strcmp(strbuf, "BOTH") == 0)
				lge_audio_wm9093_platform.wm9093_reg_dump(ICODEC_HEADSET_ST_RX_SPEAKER_RX);
			else
			D(KERN_INFO "WM9093 Tuning Flag = %d", wm9093TuningFlag );	

	
		} else if (!strcmp(access_str, "dump")) {
			lge_audio_wm9093_platform.wm9093_reg_dump(11);
		}
	
		if (rc == 0)
			rc = cnt;
		else
			D(KERN_ERR "%s: rc = %d\n", __func__, rc);
	
		return rc;

}

static const struct file_operations lge_wm9093_cal_tool_fops = {
	.open = lge_wm9093_cal_tool_open,
	.write = lge_wm9093_cal_tool_write,
	.read = lge_wm9093_debug_read
};

void set_qtr8615l_cal_db(int QTR8615LParamIndex, u8 cal_db)
{
    struct adie_codec_action_unit *temp;
    u8 reg, mask, val=0;

    temp    = qtr8615l_cal_db[QTR8615LParamIndex].adie_codec_action_ptr;

    ADIE_CODEC_UNPACK_ENTRY(temp[qtr8615l_cal_db[QTR8615LParamIndex].cal_idx].action,reg,mask,val);
//    pr_info("Before [reg:0x%02X mask:0x%02X val:0x%02X]\n", reg, mask, val);    

    val     = cal_db;

    temp[qtr8615l_cal_db[QTR8615LParamIndex].cal_idx].action = ADIE_CODEC_PACK_ENTRY(reg,mask,val);
//    ADIE_CODEC_UNPACK_ENTRY(temp[qtr8615l_cal_db[QTR8615LParamIndex].cal_idx].action,reg,mask,val);
//    pr_info("%s [reg:0x%02X mask:0x%02X val:0x%02X]\n", __func__,reg,mask,val);                    
}

int qtr8615l_renewal(void)
{
    const char* QTR8615LPath  = "/data/qtr8615l_i_atnt.txt";
    const char* QTR8615LPath2 = "/etc/qtr8615l_i_atnt.txt";
    struct file *filp;
    ssize_t read_size = 0;
    char data_array[1000];
    char *token = NULL;
    char *separator = "\n,:";
    int QTR8615LParamIndex = 0;
    mm_segment_t fs = get_fs();

    set_fs(get_ds());

    filp = filp_open(QTR8615LPath, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("%s Unable to load %s.\n", __func__, QTR8615LPath);        
        filp = filp_open(QTR8615LPath2, O_RDONLY, 0);  
        if (IS_ERR(filp)) {
            pr_err("%s Unable to load %s.\n", __func__, QTR8615LPath2);     
            set_fs(fs);            
            return (int)-1;
            }
        else
            pr_info("%s load %s\n", __func__, QTR8615LPath2);
        }
    else
        pr_info("%s load %s\n", __func__, QTR8615LPath);

    read_size = filp->f_op->read(filp, data_array, 1000, &filp->f_pos);
    token = strtok(data_array, separator);

    while ((token = strtok(NULL, separator)) != NULL) {
        token = strtok(NULL, separator);
        set_qtr8615l_cal_db(QTR8615LParamIndex, (u8)strtol(token, NULL, 16));
        QTR8615LParamIndex++;
        if (QTR8615LParamIndex == QTR8615L_CAL_DB_MAX)
            break;
    }
    
    filp_close(filp, NULL);

    set_fs(fs);

    pr_info("%s is done.\n", __func__);  

    return (int)1;
}

int get_qtr8615l_cal_db(char *data_array, int *data_len)
{
    int     buff_len=0;
    char    str[1000];
    int     cnt = 0;
    struct adie_codec_action_unit *temp;
    u8 reg, mask, val=0;

    memset(data_array, 0, ARRAY_SIZE(str));  
    memset(str, 0, ARRAY_SIZE(str));  

    /* Header */
    sprintf(str, "QTR8615L for %s", "P930");
    if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
    memcpy(&(data_array[buff_len]), str, strlen(str));
    buff_len +=  strlen(str);
    data_array[buff_len++] = '\n';

    for(cnt = 0; cnt < QTR8615L_CAL_DB_MAX; cnt++) {
        temp = qtr8615l_cal_db[cnt].adie_codec_action_ptr;
        ADIE_CODEC_UNPACK_ENTRY(temp[qtr8615l_cal_db[cnt].cal_idx].action,reg,mask,val);
        sprintf(str, qtr8615l_cfg_item[cnt], val);
        if(buff_len + strlen(str) + 4 >= ARRAY_SIZE(str)) goto END_OF_CODES;
        memcpy(&(data_array[buff_len]), str, strlen(str));
        buff_len +=  strlen(str);
        data_array[buff_len++] = '\n';
        }

   END_OF_CODES:

    *data_len  = buff_len;

//    pr_info("%s buff_len is %d\n", __func__, buff_len); 

    return *data_len;
}

int qtr8615l_current_db(void)
{
#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
    const char* QTR8615LPath  = "/data/qtr8615l_i_atnt.txt";
#else
    const char* QTR8615LPath = "/etc/qtr8615l.txt";
#endif /* CONFIG_LGE_AUDIO_AMP_WM9093 */
    struct file *filp;
    char data_array[1000];
    int data_len = 0;    
    mm_segment_t fs = get_fs();

    set_fs(get_ds());

    filp = filp_open(QTR8615LPath, O_CREAT | O_WRONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("%s Unable to load %s\n", __func__, QTR8615LPath);
        set_fs(fs);            
        return (int)-1;        
        }
    else
        pr_info("%s load %s\n", __func__, QTR8615LPath);
    
    get_qtr8615l_cal_db(data_array, &data_len);

    if (filp->f_op->write(filp, data_array, data_len, &filp->f_pos) < 0)
        pr_err("%s write failed.\n", QTR8615LPath);        

    filp_close(filp, NULL);

    set_fs(fs);

    pr_info("%s is done.\n", __func__);  

    return (int)1;
}

static int lge_qtr8615l_cal_tool_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t lge_qtr8615l_cal_tool_write(struct file *filp,
	const char __user *ubuf, size_t cnt, loff_t *ppos)
{
    char *lb_str = filp->private_data;
    char cmd;

    if (get_user(cmd, ubuf)) {
        pr_err("Unable to load %s.\n", __func__);  
        return -EFAULT;
    }

    if (!strcmp(lb_str, LGE_QTR8615L_CALIBRATION_TOOL)) {
        switch (cmd) {
            case 'w':   /* QTR8615L, Write current QTR8615L cal. DB to text file */
                qtr8615l_current_db();
                break;

            case 'r':   /* QTR8615L, Read QTR8615L cal. DB from text file */
                qtr8615l_renewal();
                break;
                
            default:
                break;
        }
    }
    return cnt;
}

static const struct file_operations lge_qtr8615l_cal_tool_fops = {
	.open = lge_qtr8615l_cal_tool_open,
	.write = lge_qtr8615l_cal_tool_write
};

//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t Acoustic Calibration  

#endif

#ifdef CONFIG_LGE_HEADSET_DETECTION_FSA8008
#include <linux/input.h>

void fsa8008_set_headset_mic_bias(int enable) {
	int rc;

	if (enable)
		rc = pm8058_micbias_enable(OTHC_MICBIAS_HEADSET, OTHC_SIGNAL_ALWAYS_ON);
	else
		rc = pm8058_micbias_enable(OTHC_MICBIAS_HEADSET, OTHC_SIGNAL_OFF);

	if (rc)
		pr_err("%s: Enabling amic power failed\n", __func__);
}

static struct fsa8008_platform_data fsa8008_platform_data = {
	.switch_name = "h2w",

	.keypad_name = "ffa-keypad", // "qwerty", // "hsd_headset"; // just for testing

	.key_code =  KEY_MEDIA,

	.gpio_detect = GPIO_EAR_SENSE_N,
	.gpio_mic_en = GPIO_EAR_MIC_EN,
	.gpio_jpole  = GPIO_EARPOL_DETECT,
	.gpio_key    = GPIO_EAR_KEY_INT,

	.set_headset_mic_bias = fsa8008_set_headset_mic_bias,

	.latency_for_detection = 75,
};

static struct platform_device lge_hsd_device = {
   .name = "fsa8008",
   .id   = -1,
   .dev = {
      .platform_data = &fsa8008_platform_data,
   },
};

#endif

#ifdef LGE_AUDIO_COMMENT_OUT_FOR_REFERENCE
static struct platform_device *snd_devices_ffa[] __initdata = {
	&msm_iearpiece_ffa_device,
	&msm_imic_ffa_device,
	&msm_ispkr_stereo_device,
	&msm_snddev_hdmi_stereo_rx_device,
	&msm_headset_mic_device,
	&msm_ispkr_mic_device,
	&msm_bt_sco_earpiece_device,
	&msm_bt_sco_mic_device,
	&msm_headset_stereo_device,
	&msm_itty_mono_tx_device,
	&msm_itty_mono_rx_device,
	&msm_mi2s_fm_tx_device,
	&msm_mi2s_fm_rx_device,
	&msm_hs_dual_mic_endfire_device,
	&msm_spkr_dual_mic_endfire_device,
	&msm_hs_dual_mic_broadside_device,
	&msm_spkr_dual_mic_broadside_device,
	&msm_ihs_stereo_speaker_stereo_rx_device,
	&msm_anc_headset_device,
	&msm_auxpga_lb_hs_device,
	&msm_auxpga_lb_lo_device,
	&msm_linein_pri_device,
};
#endif

static struct platform_device *snd_devices_lge_i_board[] __initdata = {
	&msm_iearpiece_device,
	&msm_imic_device,
	&msm_ispkr_stereo_device,
	&msm_snddev_hdmi_stereo_rx_device,
	&msm_headset_mic_device,
	&msm_ispkr_mic_device,
	&msm_bt_sco_earpiece_device,
	&msm_bt_sco_mic_device,
	&msm_headset_stereo_device,
	&msm_itty_mono_tx_device,
	&msm_itty_mono_rx_device,
	&msm_mi2s_fm_tx_device,
	&msm_mi2s_fm_rx_device,
	&msm_hs_dual_mic_endfire_device,	
	&msm_ihs_stereo_speaker_stereo_rx_device,
	&msm_auxpga_lb_hs_device,
	&msm_auxpga_lb_lo_device,
	&msm_linein_pri_device,
#ifdef CONFIG_LGE_HEADSET_DETECTION_FSA8008
	&lge_hsd_device,
#endif
//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t Hearing AID
    &msm_iearpiece_hac_device,
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t Hearing AID
//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-12, at&t Playback QTR8615L 
    &msm_ispkr_stereo_playback_device,
    &msm_headset_stereo_playback_device,
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-12, at&t Playback QTR8615L 
	&msm_imic_record_device,
	&msm_dual_nc_device,
	&msm_mic1_nc_device,
	&msm_mic2_nc_device, 
	&msm_mic2_lb_device,
    &msm_iearpiece_acs_device,       //ACS_RX
    &msm_mic1_acs_device,            //ACS_TX
    &msm_imic_vr_device,
    &msm_imic_lgvm_device,
    &msm_imic_lgcam_device,
	&msm_bt_sco_bttm_earpiece_device,//BTTM_RX
	&msm_bt_sco_bttm_mic_device,     //BTTM_TX
  &msm_headset_stereo_acs_device,//EAR ACS_RX
  &msm_headset_mic_acs_device,   //EAR ACS_TX
};

#ifdef LGE_AUDIO_COMMENT_OUT_FOR_REFERENCE
static struct platform_device *snd_devices_fluid[] __initdata = {
	&msm_iearpiece_device,
	&msm_imic_device,
	&msm_ispkr_stereo_device,
	&msm_snddev_hdmi_stereo_rx_device,
	&msm_headset_stereo_device,
	&msm_headset_mic_device,
	&msm_bt_sco_earpiece_device,
	&msm_bt_sco_mic_device,
	&msm_mi2s_fm_tx_device,
	&msm_mi2s_fm_rx_device,
	&msm_anc_headset_device,
	&msm_auxpga_lb_hs_device,
	&msm_auxpga_lb_lo_device,
};

static struct platform_device *snd_devices_qt[] __initdata = {
	&msm_headset_stereo_device,
	&msm_headset_mic_device,
	&msm_ispkr_stereo_device,
	&msm_qt_dual_dmic_d0_device,
	&msm_snddev_hdmi_stereo_rx_device,
};
#endif

static struct platform_device *snd_devices_common[] __initdata = {
	&msm_aux_pcm_device,
	&msm_cdcclk_ctl_device,
	&msm_mi2s_device,
};

void __init msm_snddev_init(void)
{
	int i;
	int dev_id;

#ifdef CONFIG_LGE_AUDIO_AMP_WM9093
	/* wm9093 initialization code */
	i2c_register_board_info(LGE_GSBI_BUS_ID_AUDIO_AMP_WM9093,
		lge_i2c_wm9093_info,
		ARRAY_SIZE(lge_i2c_wm9093_info));
#endif

	for (i = 0, dev_id = 0; i < ARRAY_SIZE(snd_devices_common); i++)
		snd_devices_common[i]->id = dev_id++;

	platform_add_devices(snd_devices_common,
		ARRAY_SIZE(snd_devices_common));

	for (i = 0; i < ARRAY_SIZE(snd_devices_lge_i_board); i++)
		snd_devices_lge_i_board[i]->id = dev_id++;

	platform_add_devices(snd_devices_lge_i_board, ARRAY_SIZE(snd_devices_lge_i_board));

#ifdef CONFIG_DEBUG_FS
	debugfs_hsed_config = debugfs_create_file("msm_hsed_config",
				S_IFREG | S_IRUGO, NULL,
		(void *) "msm_hsed_config", &snddev_hsed_config_debug_fops);

//LGE_UPDATE_S, dongsung.shin@lge.com, 2011-04-25, WM9093 Acoustic Calibration 
	debugfs_wm9093_cal_tool_config = debugfs_create_dir("wm9093_codec", 0);
	if (!IS_ERR(debugfs_wm9093_cal_tool_config)) {
		debugfs_wmread = debugfs_create_file("wmread",
		S_IFREG | S_IRUGO, debugfs_wm9093_cal_tool_config,
		(void *) "wmread", &lge_wm9093_cal_tool_fops);
	
		debugfs_wmwrite = debugfs_create_file("wmwrite",
		S_IFREG | S_IRUGO, debugfs_wm9093_cal_tool_config,
		(void *) "wmwrite", &lge_wm9093_cal_tool_fops);
	
		debugfs_wmtuning = debugfs_create_file("wmtuning",
		S_IFREG | S_IRUGO, debugfs_wm9093_cal_tool_config,
		(void *) "wmtuning", &lge_wm9093_cal_tool_fops);
	
		debugfs_dump = debugfs_create_file("dump",
		S_IFREG | S_IRUGO, debugfs_wm9093_cal_tool_config,
		(void *) "dump", &lge_wm9093_cal_tool_fops);
	
	}
//LGE_UPDATE_E, dongsung.shin@lge.com, 2011-04-25, WM9093 Acoustic Calibration 

//LGE_UPDATE_S, jeremy.pi@lge.com, 2011-04-09, at&t Acoustic Calibration 

    debugfs_qtr8616l_cal_tool_config = debugfs_create_file(LGE_QTR8615L_CALIBRATION_TOOL,
                S_IFREG | S_IRUGO, NULL,
                (void *) LGE_QTR8615L_CALIBRATION_TOOL, &lge_qtr8615l_cal_tool_fops);
//LGE_UPDATE_E, jeremy.pi@lge.com, 2011-04-09, at&t Acoustic Calibration 
#endif
}

