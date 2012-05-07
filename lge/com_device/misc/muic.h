/* Copyright (c) 2010,  LG Electronics Inc. All rights reserved. */
/* byongdoo.oh@lge.com create MUIC driver */

#ifndef ___MUIC_H_
#define __MUIC_H_

#define TS5USBA_DEVICE_ID 0x44
#define MUIC_INT_GPIO 14 //yongman.kwon 14 means 15th gpio.

typedef enum {
	NOT_UPON_IRQ,	
	UPON_IRQ,	
} TYPE_UPON_IRQ;

#define TS5USBA_DEVICE_ID_ADDR 0x00
#define TS5USBA_CONTROL_1_ADDR 0x01
#define TS5USBA_CONTROL_2_ADDR 0x02
#define TS5USBA_SW_CONTROL 0x03
#define TS5USBA_INT_STATUS 0x04
#define TS5USBA_CHIP_STATUS 0x05

/* start descripting device vendor ID */
#define TS5USBA_VENDOR_MASK 0xF0
#define TS5USBA_VENDOR_TI 0x10
#define TS5USBA_VENDOR_MAXIM 0x20

/* start descripting control1 register masking value */
#define TS5USBA_ID_2P2_MASK 0x40
#define TS5USBA_ID_620_MASK 0x20
#define TS5USBA_ID_200_MASK 0x10
#define TS5USBA_VLDO_MASK 0x08
#define TS5USBA_SEMREN_MASK 0x04
#define TS5USBA_ADC_EN_MASK 0x02
#define TS5USBA_DP_EN_MASK 0x01 

/* start descripting control2 register masking value */
#define TS5USBA_INT_POL_MASK 0x80
#define TS5USBA_INT_EN_MASK 0x40
#define TS5USBA_MIC_LP_MASK 0x20
#define TS5USBA_CP_AUD_MASK 0x10
#define TS5USBA_CHG_TPY_MASK 0x02
#define TS5USBA_USB_DET_DIS_MASK 0x01

/* start description SW control register */
#define TS5USBA_MIC_ON_MASK 0x40
#define TS5USBA_DP_MASK_SHIFT 0x3
#define TS5USBA_DM_MASK_SHIFT 0x0
#define TS5USBA_DP_DM_USB 0x0
#define TS5USBA_DP_DM_UART 0x1
#define TS5USBA_DP_DM_AUDIO 0x02
#define TS5USBA_DP_DM_OPEN 0x7

/* start description INT status register */
#define TS5USBA_CHGDET_MASK 0x80
#define TS5USBA_MR_COMP_MASK 0x40
#define TS5USBA_SEND_END_MASK 0x20
#define TS5USBA_VBUS_MASK 0x10
#define TS5USBA_IDNU_MASK 0x0F
#define TS5USBA_ID_GROUND_VAL 0x0
#define TS5USBA_ID_24K_VAL 0x01
#define TS5USBA_ID_56K_VAL 0x02
#define TS5USBA_ID_100K_VAL 0x03
#define TS5USBA_ID_130K_VAL 0x04
#define TS5USBA_ID_180K_VAL 0x05
#define TS5USBA_ID_240K_VAL 0x06
#define TS5USBA_ID_330K_VAL 0x07
#define TS5USBA_ID_430K_VAL 0x08
#define TS5USBA_ID_620K_VAL 0x09
#define TS5USBA_ID_910K_VAL 0x0A
#define TS5USBA_ID_OPEN_VAL 0x0B

/* start description Status register */
#define TS5USBA_DC_PORT_MASK 0x80
#define TS5USBA_CH_PORT_MASK 0x40

struct ts5usba_reg {
  uint8_t addr;
  uint8_t value;
};

typedef enum 
  {
    CHARGER_TYPE_NONE,
    DEDICATED_CHARGER,
    CHARGING_HOST,
    INVALID_CHARGER
  }charger_type;

typedef enum
  {
    FACTORY_UART,
    FACTORY_USB,
    TA_ONLY,
    USB_ONLY,
    AUDIO,
    INVALID
  }cable_id_type;
#endif
