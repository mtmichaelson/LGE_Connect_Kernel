#ifndef LG_DIAG_TESTMODE_H
#define LG_DIAG_TESTMODE_H
// LG_FW_DIAG_KERNEL_SERVICE

#include "lg_comdef.h"


/*********************** BEGIN PACK() Definition ***************************/
/*********************** BEGIN PACK() Definition ***************************/
#if defined __GNUC__
  #define PACK(x)       x __attribute__((__packed__))
  #define PACKED        __attribute__((__packed__))
#elif defined __arm
  #define PACK(x)       __packed x
  #define PACKED        __packed
#else
  #error No PACK() macro defined for this compiler
#endif
/********************** END PACK() Definition *****************************/
/********************** END PACK() Definition *****************************/


/* BEGIN: 0014654 jihoon.lee@lge.com 20110124 */
/* MOD 0014654: [TESTMODE] SYNC UP TESTMODE PACKET STRUCTURE TO KERNEL */
//#define MAX_KEY_BUFF_SIZE    200
#define MAX_KEY_BUFF_SIZE    201
/* END: 0014654 jihoon.lee@lge.com 2011024 */

typedef enum
{
  VER_SW=0,		//Binary Revision
  VER_DSP,      /* Camera DSP */
  VER_MMS,
  VER_CONTENTS,
  VER_PRL,
  VER_ERI,
  VER_BREW,
  VER_MODEL,  // 250-0-7 Test Mode Version
  VER_HW,
  REV_DSP=9,
  CONTENTS_SIZE,
  JAVA_FILE_CNT=13,
  JAVA_FILE_SIZE,
  VER_JAVA,
  BANK_ON_CNT=16,
  BANK_ON_SIZE,
  MODULE_FILE_CNT,
  MODULE_FILE_SIZE,
  MP3_DSP_OS_VER=21,
  VER_MODULE  ,
  VER_LCD_REVISION=24

} test_mode_req_version_type;

typedef enum
{
  MOTOR_OFF,
  MOTOR_ON
}test_mode_req_motor_type;

typedef enum
{
  ACOUSTIC_OFF=0,
  ACOUSTIC_ON,
  HEADSET_PATH_OPEN,
  HANDSET_PATH_OPEN,
  ACOUSTIC_LOOPBACK_ON,
  ACOUSTIC_LOOPBACK_OFF
}test_mode_req_acoustic_type;

typedef enum
{
  MP3_128KHZ_0DB,
  MP3_128KHZ_0DB_L,
  MP3_128KHZ_0DB_R,
  MP3_MULTISINE_20KHZ,
  MP3_PLAYMODE_OFF,
  MP3_SAMPLE_FILE,
  MP3_NoSignal_LR_128k
}test_mode_req_mp3_test_type;

typedef enum
{
  SPEAKER_PHONE_OFF,
  SPEAKER_PHONE_ON,
  NOMAL_Mic1,
  NC_MODE_ON,
  ONLY_MIC2_ON_NC_ON,
  ONLY_MIC1_ON_NC_ON
}test_mode_req_speaker_phone_type;

typedef enum
{
  VOL_LEV_OFF,
  VOL_LEV_MIN,
  VOL_LEV_MEDIUM,
  VOL_LEV_MAX
}test_mode_req_volume_level_type;

#if 1 //#ifndef LG_BTUI_TEST_MODE
typedef enum
{
  BT_GET_ADDR, //no use anymore
  BT_TEST_MODE_1=1,
  BT_TEST_MODE_CHECK=2,
  BT_TEST_MODE_RELEASE=5,
  BT_TEST_MODE_11=11 // 11~42
}test_mode_req_bt_type;

typedef enum
{
  BT_ADDR_WRITE=0,
  BT_ADDR_READ
}test_mode_req_bt_rw_type;

#define BT_RW_CNT 20

#endif //LG_BTUI_TEST_MODE

typedef enum
{
	CAM_TEST_MODE_OFF = 0,
	CAM_TEST_MODE_ON,
	CAM_TEST_SHOT,
	CAM_TEST_SAVE_IMAGE,
	CAM_TEST_CALL_IMAGE,
	CAM_TEST_ERASE_IMAGE,
	CAM_TEST_FLASH_ON,
	CAM_TEST_FLASH_OFF = 9,
	CAM_TEST_CAMCORDER_MODE_OFF,
	CAM_TEST_CAMCORDER_MODE_ON,
	CAM_TEST_CAMCORDER_SHOT,
	CAM_TEST_CAMCORDER_SAVE_MOVING_FILE,
	CAM_TEST_CAMCORDER_PLAY_MOVING_FILE,
	CAM_TEST_CAMCORDER_ERASE_MOVING_FILE,
	CAM_TEST_CAMCORDER_FLASH_ON,
	CAM_TEST_CAMCORDER_FLASH_OFF,
	CAM_TEST_STROBE_LIGHT_ON,
	CAM_TEST_STROBE_LIGHT_OFF,
	CAM_TEST_CAMERA_SELECT = 22,
}test_mode_req_cam_type;

typedef enum
{
  EXTERNAL_SOCKET_MEMORY_CHECK,
  EXTERNAL_FLASH_MEMORY_SIZE,
  EXTERNAL_SOCKET_ERASE,
  EXTERNAL_FLASH_MEMORY_USED_SIZE = 4,
    EXTERNAL_FLASH_MEMORY_CONTENTS_CHECK,
    EXTERNAL_FLASH_MEMORY_ERASE,
  EXTERNAL_SOCKET_ERASE_SDCARD_ONLY = 0xE,
  EXTERNAL_SOCKET_ERASE_FAT_ONLY = 0xF,
}test_mode_req_socket_memory;
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
typedef enum
{
  FIRST_BOOTING_COMPLETE_CHECK = 0,
}test_mode_req_fboot;
// END: 0011366 sehyuny.kim@lge.com 2010-11-25

/* BEGIN: 0015566 jihoon.lee@lge.com 20110207 */
/* ADD 0015566: [Kernel] charging mode check command */
#ifdef CONFIG_LGE_CHARGING_MODE_INFO
typedef enum
{
  FIRST_BOOTING_IN_CHG_MODE,
  FIRST_BOOTING_NOT_IN_CHG_MODE
}test_mode_first_booting_chg_mode_type;
#endif
/* END: 0015566 jihoon.lee@lge.com 20110207 */

typedef enum
{
  MEMORY_TOTAL_CAPA_TEST,
  MEMORY_USED_CAPA_TEST,
  MEMORY_REMAIN_CAPA_TEST
}test_mode_req_memory_capa_type;

// BEGIN : munho.lee@lge.com 2010-11-30
// ADD: 0011620: [Test_mode] Memory format test 
typedef enum
{
  MEMORY_TOTAL_SIZE_TEST = 0 ,
  MEMORY_FORMAT_MEMORY_TEST = 1,
}test_mode_req_memory_size_type;
// END : munho.lee@lge.com 2010-11-30

typedef enum
{
  FACTORY_RESET_CHECK,
  FACTORY_RESET_COMPLETE_CHECK,
  FACTORY_RESET_STATUS_CHECK,
  FACTORY_RESET_COLD_BOOT,
  FACTORY_RESET_FORCE_CHANGE_STATUS,
  FACTORY_RESET_ERASE_USERDATA = 0x0F, // for NPST dll
}test_mode_req_factory_reset_mode_type;

typedef enum{
  FACTORY_RESET_START = 0,
  FACTORY_RESET_INITIAL = 1,
  FACTORY_RESET_ARM9_END = 2,
  FACTORY_RESET_COLD_BOOT_START = 3,
  FACTORY_RESET_COLD_BOOT_END = 5,
  FACTORY_RESET_HOME_SCREEN_END = 6,
  FACTORY_RESET_NA = 7,
}test_mode_factory_reset_status_type;

// BEGIN 0011665: eundeok.bae@lge.com FTM MODE FOR ONLY KERNEL BOOTING
// [KERNEL] Added source code For Sleep Mode Test, Test Mode V8.3 [250-42] 
// LGE_CHANGE [dojip.kim@lge.com] 2010-09-28, kernel mode
typedef enum
{
  SLEEP_MODE_ON,
  SLEEP_FLIGHT_MODE_ON,
  FLIGHT_KERNEL_MODE_ON,
  FLIGHT_MODE_OFF
} test_mode_sleep_mode_type;
// END 0011665: eundeok.bae@lge.com FTM MODE FOR ONLY KERNEL BOOTING

/* LGE_FACTORY_TEST_MODE for Photo Sensor(ALC) */
typedef enum
{
	ALC_TEST_MODE_OFF=0,
	ALC_TEST_MODE_ON,
	ALC_TEST_CHECK_STATUS,
	ALC_TEST_AUTOTEST
} test_mode_req_alc_type;

typedef enum
{
  TEST_SCRIPT_ITEM_SET,
  TEST_SCRIPT_MODE_CHECK,
  CAL_DATA_BACKUP,
  CAL_DATA_RESTORE,
  CAL_DATA_ERASE,
  CAL_DATA_INFO
}test_mode_req_test_script_mode_type;

/* TEST_MODE_PID_TEST */
typedef enum
{
  PID_WRITE,
  PID_READ
}test_mode_req_pid_type;


/* TEST_MODE_SW_VERSION */
typedef enum
{
  SW_VERSION,
  SW_OUTPUT_VERSION,
  SW_COMPLETE_VERSION,
  SW_VERSION_CHECK
} test_mode_req_sw_version_type;

/* TEST_MODE_CAL_CHECK */
typedef enum
{
 CAL_CHECK,
 CAL_DATA_CHECK,
} test_mode_req_cal_check_type;

// BEGIN: 0010557  unchol.park@lge.com 2010-11-18
// 0010557 : [Testmode] added test_mode command for LTE test 
// add call function		
typedef enum
{
 MULTIMODE,
 LTEONLY,
 CDMAONLY,
} test_mode_req_lte_mdoe_seletion_type;

typedef enum
{
 CALL_CONN,
 CALL_DISCONN,
} test_mode_req_lte_call_type;

// BEGIN: 0010557  unchol.park@lge.com 2011-01-12
// 0010557 : [Testmode] added test_mode command for LTE test 
typedef enum	// [2010-06-14] modified by hoya to VD600
{
	VIRTUAL_SIM_OFF,
	VIRTUAL_SIM_ON,
	VIRTUAL_SIM_STATUS,
	CAMP_CHECK = 3,		// add for VD600
	AUTO_CAMP_REQ = 20,	// add for VD600
	DETACH = 21,			// add for VD600	
}test_mode_req_virtual_sim_type;
// END: 0010557 unchol.park@lge.com 2011-01-12
// END: 0010557 unchol.park@lge.com 2010-11-18

/* [yk.kim@lge.com] 2011-01-04, change usb driver */
typedef enum
{
	CHANGE_MODEM,
	CHANGE_MASS,
} test_mode_req_change_usb_driver_type;


// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
typedef enum
{
	DB_INTEGRITY_CHECK=0,
	FPRI_CRC_CHECK=1,
	FILE_CRC_CHECK=2,
	CODE_PARTITION_CRC_CHECK=3,
	TOTAL_CRC_CHECK=4,
    DB_DUMP_CHECK=5,
    DB_COPY_CHECK=6,    
} test_mode_req_db_check;

typedef enum 
{
	IMEI_WRITE=0, 
	IMEI_READ=1,
	IMEI2_WRITE=2,
	IMEI2_READ=3
} test_mode_req_imei_req_type;

#if 0
typedef PACKED struct {
	test_mode_req_imei_req_type req_type;
	byte imei[15];
} test_mode_req_imei_type;
// END: 0011366 sehyuny.kim@lge.com 2010-11-25
#endif 

/* BEGIN: 0014654 jihoon.lee@lge.com 20110124 */
/* MOD 0014654: [TESTMODE] SYNC UP TESTMODE PACKET STRUCTURE TO KERNEL */
typedef enum
{
	VCO_SELF_TUNNING_ITEM_SET,
	VCO_SELF_TUNNING_ITEM_READ
}test_mode_req_vco_self_tunning_type;

typedef enum 
{
// BEGIN: 0011402 hyunjong.do@lge.com 2010-11-26
// ADD: 0011402: add a function for power testmode
  BATTERY_THERM_ADC=0,	 
// END: 0011402 hyunjong.do@lge.com 2010-11-26
  BATTERY_VOLTAGE_LEVEL=1,
  BATTERY_CHARGING_COMPLETE,
  BATTERY_CHARGING_MODE_TEST,
  BATTERY_FUEL_GAUGE_RESET=5,
  BATTERY_FUEL_GAUGE_SOC=6,
#if 1//def CONFIG_LGE_BATT_SOC_FOR_NPST
  BATTERY_FUEL_GAUGE_SOC_NPST =99,
#endif
} test_mode_req_batter_bar_type;

typedef enum 
{
  MANUAL_TEST_ON,
  MANUAL_TEST_OFF,
  MANUAL_MODE_CHECK
} test_mode_req_manual_test_mode_type;

// BEGIN: 0010557  unchol.park@lge.com 2010-11-05
// 0010557 : [Testmode] added test_mode command for LTE test
#if 1//defined(LG_FW_LTE_TESTMODE)
/*TEST_MODE_TX_MAX_POWER*/
typedef enum	// [2010-06-14] modified by hoya
{
  CDMA_WCDMA_MAX_POWER_ON = 0,
  CDMA_WCDMA_MAX_POWER_OFF =1,
	LTE_TESTMODE_ON = 2,
	LTE_RF_ON = 3,
	LTE_FAKE_SYNC = 4,
	LTE_RX_SETUP = 5,
	LTE_SCHEDULE = 6,
	LTE_TX_SETUP = 7,
	LTE_TX_POWER_SETUP = 8,
	LTE_MAX_POWER_OFF = 9,
	LTE_RF_OFF = 10,
	
} test_mode_rep_max_current_check_type; 

/*TEST_MODE_CHANGE_RFCALMODE = 61*/
typedef enum
{
	LTE_OFF_AND_CDMA_ON = 0,
	LTE_ON_AND_CDMA_OFF = 1,
	RF_MODE_CHECK = 2
} test_mode_rep_change_rf_cal_mode_type;	// [2010-06-11] added by hoya // [2010-06-28] modified by choo

/*TEST_MODE_SELECT_MIMO_ANT = 62*/
typedef enum
{
	DUAL_ANT = 0,
	SECONDARY_ANT_ONLY = 1,
	PRIMARY_ANT_ONLY = 2
} test_mode_rep_select_mimo_ant_type;	// [2010-05-13] added by hoya
#endif
// END: 0010557 unchol.park@lge.com 2010-11-05

typedef enum
{
	MODE_OFF,
	MODE_ON,
	STATUS_CHECK,
	IRDA_AUTO_TEST_START,
	IRDA_AUTO_TEST_RESULT,
	EXT_CARD_AUTO_TEST,
}test_mode_req_irda_fmrt_finger_uim_type;
/* END: 0014654 jihoon.lee@lge.com 2011024 */

/* BEGIN: 0015893 jihoon.lee@lge.com 20110212 */
/* ADD 0015893: [MANUFACTURE] WDC LIFETIMER CLNR LAUNCH_KIT */
typedef enum
{
  RESET_FIRST_PRODUCTION,
  RESET_FIRST_PRODUCTION_CHECK,
  RESET_REFURBISH=2,
  RESET_REFURBISH_CHECK,
}test_mode_req_reset_production_type;
/* END: 0015893 jihoon.lee@lge.com 20110212 */

#define BT_ADDR_CNT 12

typedef enum
{
    BLUETOOTH_ADDRESS_WRITE,
    BLUETOOTH_ADDRESS_READ,
}test_mode_req_bt_addr_req_type;

typedef struct {
    test_mode_req_bt_addr_req_type req_type;
    byte bt_addr[BT_ADDR_CNT];
}test_mode_req_bt_addr_type;

#define WIFI_MAC_ADDR_CNT 12

typedef enum
{
    WIFI_MAC_ADDRESS_WRITE = 0,
    WIFI_MAC_ADDRESS_READ = 1,
}test_mode_req_wifi_addr_req_type;

typedef struct {
	//test_mode_req_wifi_addr_req_type req_type;
	byte req_type;
    byte wifi_mac_addr[WIFI_MAC_ADDR_CNT];
}test_mode_req_wifi_addr_type;
typedef enum {
   XO_FIELD_CALIBRATION,
   XO_FACTORY_CALIBRATION,
} test_mode_req_XOCalDataBackup_Type;

/* BEGIN: 0014654 jihoon.lee@lge.com 20110124 */
/* MOD 0014654: [TESTMODE] SYNC UP TESTMODE PACKET STRUCTURE TO KERNEL */
typedef enum
{
    FOTA_ID_CHECK,
	FOTA_ID_READ,
}test_mode_req_fota_id_check_type;

extern int key_lock;

typedef enum
{
	KEY_LOCK_REQ=0,
	KEY_UNLOCK_REQ=1,	
}test_mode_req_key_lock_type;

typedef enum
{
	KEY_LOCK_RSP=0,
	KEY_UNLOCK_RSP=1,
	KEY_LOCK_NOT_SUPPORT=2,
}test_mode_rsp_key_lock_type;


typedef union
{
  test_mode_req_version_type		version;
// BEGIN: 0010090 sehyuny.kim@lge.com 2010-10-21
// MOD 0010090: [FactoryReset] Enable Recovery mode FactoryReset
#if 0
	test_mode_req_imei_type	imei;  
#endif 
// END: 0010090 sehyuny.kim@lge.com 2010-10-21
#if 1 //#ifndef LG_BTUI_TEST_MODE
  test_mode_req_bt_type	bt;
  byte					bt_rw[BT_RW_CNT];
#endif //LG_BTUI_TEST_MODE
  test_mode_req_socket_memory esm;  // external socket memory
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
  test_mode_req_fboot fboot;
// END: 0011366 sehyuny.kim@lge.com 2010-11-25
  test_mode_req_memory_capa_type mem_capa;
// BEGIN : munho.lee@lge.com 2010-11-30
// ADD: 0011620: [Test_mode] Memory format test 
  test_mode_req_memory_size_type memory_format;
// END : munho.lee@lge.com 2010-11-30
  word key_data;
  test_mode_req_motor_type		  	motor;
  test_mode_req_acoustic_type 	  	acoustic;
  test_mode_req_mp3_test_type  		mp3_play;
  test_mode_req_speaker_phone_type	speaker_phone;
  test_mode_req_volume_level_type	volume_level;
  boolean key_test_start;
  test_mode_req_cam_type		 camera;
  test_mode_req_factory_reset_mode_type  factory_reset;
  test_mode_sleep_mode_type sleep_mode;
  test_mode_req_test_script_mode_type test_mode_test_scr_mode;
  test_mode_req_pid_type		pid;	// pid Write/Read
  test_mode_req_vco_self_tunning_type	vco_self_tunning;
  test_mode_req_factory_reset_mode_type test_factory_mode;
#if 1//def LG_FW_CGPS_MEASURE_CNO
  byte  CGPSTest;
#endif //LG_FW_CGPS_MEASURE_CNO
  test_mode_req_batter_bar_type batt;
  test_mode_req_manual_test_mode_type test_manual_mode; 
  test_mode_req_sw_version_type	sw_version;
  test_mode_req_cal_check_type		cal_check;
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
  test_mode_req_db_check		db_check;
// END: 0011366 sehyuny.kim@lge.com 2010-11-25  
// BEGIN: 0010557  unchol.park@lge.com 2010-11-18
// 0010557 : [Testmode] added test_mode command for LTE test 
// add call function	
  test_mode_req_lte_mdoe_seletion_type  	mode_seletion;
  test_mode_req_lte_call_type 	  	lte_call;
// BEGIN: 0010557  unchol.park@lge.com 2011-01-12
// 0010557 : [Testmode] added test_mode command for LTE test 
  test_mode_req_virtual_sim_type 	  	lte_virtual_sim;
// END: 0010557 unchol.park@lge.com 2011-01-12
#if 1// defined(LG_FW_LTE_TESTMODE)
  test_mode_rep_max_current_check_type		max_current;
  test_mode_rep_change_rf_cal_mode_type		rf_mode;
  test_mode_rep_select_mimo_ant_type		select_mimo;
#endif  
// END: 0010557 unchol.park@lge.com 2010-11-18
  /* [yk.kim@lge.com] 2011-01-04, change usb driver */
  test_mode_req_change_usb_driver_type	change_usb_driver;
// BEGIN: 0011527 sabina.park@lge.com 2010-11-29 
// ADD :0011527 [SIM] add testmode UIM/USIM/BANKON Card Test(250-13-5)
    test_mode_req_irda_fmrt_finger_uim_type ext_device_cmd;
// END: 0011527 sabina.park@lge.com 2010-11-29 

/* BEGIN: 0015893 jihoon.lee@lge.com 20110212 */
/* ADD 0015893: [MANUFACTURE] WDC LIFETIMER CLNR LAUNCH_KIT */
   test_mode_req_reset_production_type reset_production_cmd;
/* END: 0015893 jihoon.lee@lge.com 20110212 */

    test_mode_req_bt_addr_type bt_ad;
    test_mode_req_wifi_addr_type wifi_mac_ad;


//HELLG ........ is this is my job????????????? 
    int  resetproduction_sub2;
    int  irdafmrtfingerUIM_sub2;

#if 0
  test_mode_req_lcd_type			lcd;
  test_mode_req_folder_type			folder;
  test_mode_req_motor_type			motor;
  test_mode_req_acoustic_type		acoustic;
  test_mode_req_midi_struct_type	midi;
  test_mode_req_vod_type			vod;
  test_mode_req_cam_type			cam;
  test_mode_req_buzzer_type		buzzer;
  byte							efs_integrity;
  byte							factory_init;
  byte							efs_integrity_detail;
  byte							tx_power;
  byte							m_format;
  test_mode_req_phone_clear_type	phone_clear;
  test_mode_brew_type                      brew;
  test_mode_req_mp3_test_type  mp3_play;
  test_mode_req_bt_type   bt;
// LG_FW 2004.05.10 hieonn created -----------------------------------------
#ifdef LG_FW_FACTORY_MODE_KEY_DETECTION
  boolean if_key_pressed_is_started_or_not; /* to test key_pressed event */
#endif // LG_FW_FACTORY_MODE_KEY_DETECTION
#ifdef LG_FW_FACTORY_MODE  // race 2005.10.28
  test_mode_req_factory_mode_type factory_mode;
#endif /* LG_FW_FACTORY_MODE */

// LG_FW : 2006.04.07 louvethee--------------------
#ifdef LG_FW_TEST_MODE_V6_4
  test_mode_req_batter_bar_type			batt;
  test_mode_req_speaker_phone_type		speaker_phone;
  byte Volume_Level_Test;
#endif  // LG_FW_TEST_MODE_V6_4
// ----------------------------------------------------------

  test_mode_req_memory_capa_type mem_capa;

#ifdef LG_FW_TEST_MODE_V6_7
  test_mode_req_virtual_sim_type		virtual_sim;
  test_mode_req_photo_sensor_type		photo_sensor;
  test_mode_req_vco_self_tunning_type	vco_self_tunning;
  test_mode_req_ext_socket_memory_type	ext_socket_memory;
  test_mode_req_irda_fmrt_finger_uim_type ext_device_cmd;
#endif
#ifdef LG_FW_TEST_MODE_V6_8
  test_mode_req_mrd_usb_type mrd_usb;
#endif

#ifdef LG_FW_BMA020_TESTMODE
  test_mode_req_geomagnetic_sensor_type geomagnetism;
#endif //LG_FW_BMA020_SENSOR

#ifdef LG_FW_PROXI_CAL
  test_mode_req_proximity_type test_mode_test_proxi_mode;
#endif

  test_mode_req_manual_test_mode_type test_manual_mode;

// LG_FW : 2008.07.29 hoonylove004--------------------------------------------
// RF CAL backup
#ifdef LG_FW_TEST_MODE_V7_1
  test_mode_req_test_script_mode_type test_mode_test_scr_mode;
#endif /*LG_FW_TEST_MODE_V7_1*/
//----------------------------------------------------------------------------
#endif
//Added by jaeopark 110527 for XO Cal Backup
  test_mode_req_XOCalDataBackup_Type XOCalDataBackup;
    test_mode_req_fota_id_check_type fota_id_check;
	test_mode_req_key_lock_type req_key_lock;
    test_mode_req_fota_id_check_type fota;
} test_mode_req_type;
/* END: 0014654 jihoon.lee@lge.com 2011024 */

typedef struct diagpkt_header
{
  byte opaque_header;
}PACKED diagpkt_header_type;

typedef struct DIAG_TEST_MODE_F_req_tag {
	diagpkt_header_type		xx_header;
	word					sub_cmd_code;
	test_mode_req_type		test_mode_req;
} PACKED DIAG_TEST_MODE_F_req_type;

typedef enum
{
  TEST_OK_S,
  TEST_FAIL_S,
  TEST_NOT_SUPPORTED_S
} PACKED (test_mode_ret_stat_type);

typedef struct
{
    byte SVState;
    uint8 SV;
    uint16 MeasuredCNo;
} PACKED CGPSResultType;

#define FOTA_ID_LENGTH 30

/* BEGIN: 0014654 jihoon.lee@lge.com 20110124 */
/* MOD 0014654: [TESTMODE] SYNC UP TESTMODE PACKET STRUCTURE TO KERNEL */
typedef union
{
  test_mode_req_version_type		version;
  byte								str_buf[17];
  CGPSResultType TestResult[16];
  test_mode_req_motor_type		    motor;
  test_mode_req_acoustic_type 	    acoustic;
  test_mode_req_mp3_test_type 	    mp3_play;
  test_mode_req_speaker_phone_type  speaker_phone;
  test_mode_req_volume_level_type   volume_level;
  char key_pressed_buf[MAX_KEY_BUFF_SIZE];
  char  memory_check;
// BEGIN : munho.lee@lge.com 2011-01-15
// MOD: 0013541: 0014142: [Test_Mode] To remove Internal memory information in External memory test when SD-card is not exist   
  uint32    socket_memory_size;
  uint32    socket_memory_usedsize;
//  int    socket_memory_size
//  int    socket_memory_usedsize;
// END : munho.lee@lge.com 2011-01-15
  test_mode_req_cam_type		 camera;
  unsigned int mem_capa;
  char batt_voltage[5];
  byte		chg_stat;
  int manual_test;
  test_mode_req_pid_type		pid;
  test_mode_req_sw_version_type	sw_version;

// BEGIN: 0010557  unchol.park@lge.com 2010-11-05
// 0010557 : [Testmode] added test_mode command for LTE test
#if 1//defined(LG_FW_LTE_TESTMODE)
  byte	  hkadc_value;
#endif
// END: 0010557 unchol.park@lge.com 2010-11-05 
#ifdef LG_FW_LTE
  test_mode_lte_rsp_type testmode_lte_rsp;
#endif  
// BEGIN: 0011527 sabina.park@lge.com 2010-11-29 
// ADD :0011527 [SIM] add testmode UIM/USIM/BANKON Card Test(250-13-5)
#if 1//def LG_FW_UIM_TESTMODE
  byte uim_state;
#endif
// END: 0011527 sabina.park@lge.com 2010-11-29 

//HELLG ........ is this is my job????????????? 
  int uim_state2;    

/* BEGIN: 0011622 youngmok.park@lge.com 2010-11-29 */
/* ADD: 0011622: [RF] Testmode VCO Self Tunning */
  byte  vco_value;
/* END: 0011622 youngmok.park@lge.com 2010-11-29 */

  test_mode_req_cal_check_type		cal_check;

#if 1 //#ifndef LG_BTUI_TEST_MODE
  byte read_bd_addr[BT_RW_CNT];
#endif

test_mode_req_factory_reset_mode_type  factory_reset;
test_mode_req_test_script_mode_type test_mode_test_scr_mode;

#if 0
  test_mode_req_lcd_type			lcd;
  test_mode_req_folder_type			folder;
  test_mode_req_motor_type			motor;
  test_mode_req_acoustic_type		acoustic;
  test_mode_req_midi_struct_type	midi;
  test_mode_req_vod_type			vod;
  test_mode_req_cam_type			cam;
  test_mode_req_buzzer_type			buzzer;
  test_mode_rsp_efs_type   	efs;
  byte								factory_init;
  byte								tx_power;
  test_mode_rsp_efs_integrity_type	efs_integrity_detail;
  test_mode_rsp_phone_clear_type	phone_clear;
  test_mode_brew_type                brew;
  test_mode_rsp_bt_type     bt;
  byte							ext_socket_check;
  unsigned int		brew_cnt;
  unsigned long	brew_size;
  byte       batt_bar_count;

  // LG_FW : 2006.04.07 louvethee--------------------
#ifdef LG_FW_TEST_MODE_V6_4
  char       batt_voltage[5];
  byte		chg_stat;
 test_mode_req_mp3_test_type mp3_play;
#endif  // LG_FW_TEST_MODE_V6_4
// ----------------------------------------------------------
  byte       ant_bar_count;
  unsigned int mem_capa;
#ifdef LG_FW_FACTORY_MODE  // race 2005.10.28
  byte      factory_mode;
#endif

#ifdef LG_FW_TEST_MODE_V6_7
  byte photo_sensor;
  byte	    vco_table[16];
  byte		vco_value;
#endif

#ifdef LG_FW_BMA020_TESTMODE
//  char 	geomagnetic_acceleration[25];
  test_mode_rsp_geomagnetic_rsp_type  geomagnetic_value_rsp;
#endif //LG_FW_BMA020_SENSOR

#ifdef LG_FW_PROXI_CAL
  byte proximity_value;
#endif

  int manual_test;
#endif
    byte read_wifi_mac_addr[WIFI_MAC_ADDR_CNT];    
    byte fota_id_read[20];
 test_mode_req_XOCalDataBackup_Type XOCalDataBackup;
 test_mode_rsp_key_lock_type key_lock;
} PACKED test_mode_rsp_type;
/* END: 0014654 jihoon.lee@lge.com 2011024 */

typedef struct DIAG_TEST_MODE_F_rsp_tag {
	diagpkt_header_type		xx_header;
	word					sub_cmd_code;
	test_mode_ret_stat_type	ret_stat_code;
	test_mode_rsp_type		test_mode_rsp;
} PACKED DIAG_TEST_MODE_F_rsp_type;

typedef enum
{
  TEST_MODE_VERSION=0,
  TEST_MODE_LCD,
  TEST_MODE_MOTOR=3,
  TEST_MODE_ACOUSTIC,
  TEST_MODE_CAM=7,
  TEST_MODE_EFS_INTEGRITY=11,
  TEST_MODE_IRDA_FMRT_FINGER_UIM_TEST=13,
  TEST_MODE_BREW_CNT=20,
  TEST_MODE_BREW_SIZE=21,
  TEST_MODE_KEY_TEST,    //LGF_TM_KEY_PAD_TEST
  TEST_MODE_EXT_SOCKET_TEST,
#if 1 //#ifndef LG_BTUI_TEST_MODE
  TEST_MODE_BLUETOOTH_TEST,
#endif //LG_BTUI_TEST_MODE
  TEST_MODE_BATT_LEVEL_TEST,
  TEST_MODE_MP3_TEST=27,
  TEST_MODE_FM_TRANCEIVER_TEST,
  TEST_MODE_ISP_DOWNLOAD_TEST,
  //TEST_MODE_COMPASS_SENSOR_TEST=30,     // Geometric (Compass) Sensor
  TEST_MODE_ACCEL_SENSOR_TEST=31,
  TEST_MODE_ALCOHOL_SENSOR_TEST=32,
  TEST_MODE_TDMB_TEST=33,
  TEST_MODE_WIFI_TEST=33,
  TEST_MODE_TV_OUT_TEST=33,
  TEST_MODE_SDMB_TEST=33,
  TEST_MODE_MANUAL_MODE_TEST=36,   // Manual test
// BEGIN : munho.lee@lge.com 2010-11-30
// MOD: 0011620: [Test_mode] Memory format test 
#if 1
  TEST_MODE_FORMAT_MEMORY_TEST=38,
#else
  TEST_MODE_UV_SENSOR_TEST=38,
#endif
// END : munho.lee@lge.com 2010-11-30
  TEST_MODE_3D_ACCELERATOR_SENSOR_TEST=39,

  TEST_MODE_KEY_DATA_TEST = 40,  // Key Code Input
  TEST_MODE_MEMORY_CAPA_TEST,  // Memory Volume Check
  TEST_MODE_SLEEP_MODE_TEST,
  TEST_MODE_SPEAKER_PHONE_TEST,	// Speaker Phone test

  TEST_MODE_VIRTUAL_SIM_TEST = 44,
  TEST_MODE_PHOTO_SENSER_TEST,
  TEST_MODE_VCO_SELF_TUNNING_TEST,

  TEST_MODE_MRD_USB_TEST=47,
  TEST_MODE_TEST_SCRIPT_MODE = 48,

  TEST_MODE_PROXIMITY_SENSOR_TEST = 49,
  TEST_MODE_FACTORY_RESET_CHECK_TEST = 50,
  TEST_MODE_VOLUME_TEST=51,
  TEST_MODE_HANDSET_FREE_ACTIVATION_TEST,
  TEST_MODE_MOBILE_SYSTEM_CHANGE_TEST,
  TEST_MODE_STANDALONE_GPS_TEST,
  TEST_MODE_PRELOAD_INTEGRITY_TEST,
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
  TEST_MODE_FIRST_BOOT_COMPLETE_TEST = 58,
// END: 0011366 sehyuny.kim@lge.com 2010-11-25

  TEST_MODE_LED_TEST = 60,
// BEGIN: 0010557  unchol.park@lge.com 2010-11-05
// 0010557 : [Testmode] added test_mode command for LTE test		
  TEST_MODE_MAX_CURRENT_CHECK = 59,
  TEST_MODE_CHANGE_RFCALMODE = 61,
  TEST_MODE_SELECT_MIMO_ANT = 62,
  TEST_MODE_LTE_MODE_SELECTION = 63,
// BEGIN: 0010557  unchol.park@lge.com 2010-11-18
// 0010557 : [Testmode] added test_mode command for LTE test 
// add call function	
  TEST_MODE_LTE_CALL = 64,
// END: 0010557 unchol.park@lge.com 2010-11-18
// BEGIN: 0010557  unchol.park@lge.com 2011-01-24
// 0010557 : [Testmode] added test_mode command for LTE test
  TEST_MODE_GET_HKADC_VALUE = 66,
// END: 0010557 unchol.park@lge.com 2011-01-24
// END: 0010557 unchol.park@lge.com 2010-11-05

/* [yk.kim@lge.com] 2011-01-04, change usb driver */
  TEST_MODE_CHANGE_USB_DRIVER = 65,

  TEST_MODE_PID_TEST = 70,		// pid R/W
  TEST_MODE_SW_VERSION = 71,
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
	TEST_MODE_IME_TEST=72,
// END: 0011366 sehyuny.kim@lge.com 2010-11-25  
  TEST_MODE_IMPL_TEST,
  TEST_MODE_SIM_LOCK_TYPE_TEST,
  TEST_MODE_UNLOCK_CODE_TEST,
  TEST_MODE_IDDE_TEST,
  TEST_MODE_FULL_SIGNATURE_TEST,
  TEST_MODE_NT_CODE_TEST,
  TEST_MODE_SIM_ID_TEST = 79,

  TEST_MODE_CAL_CHECK= 82,
#if 1 //#ifndef LG_BTUI_TEST_MODE
    TEST_MODE_BLUETOOTH_RW=83,
#endif //LG_BTUI_TEST_MODE
  TEST_MODE_SKIP_WELCOM_TEST = 87,
#if 1    //LGE_CHANGE, [dongp.kim@lge.com], 2010-10-09, adding TEST_MODE_MAC_READ_WRITE for Wi-Fi Testmode menu 
    TEST_MODE_WIFI_MAC_RW = 88,
#endif //LG_FW_WLAN_TEST
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
TEST_MODE_DB_INTEGRITY_CHECK=91,
  TEST_MODE_NVCRC_CHECK = 92,

//BEGIN:seungkwan.jung
TEST_MODE_GYRO_SENSOR_TEST =93,
//END:seungkwan.jung

/* BEGIN: 0015893 jihoon.lee@lge.com 20110212 */
/* ADD 0015893: [MANUFACTURE] WDC LIFETIMER CLNR LAUNCH_KIT */
  TEST_MODE_RESET_PRODUCTION = 96,
/* END: 0015893 jihoon.lee@lge.com 20110212 */
    TEST_MODE_FOTA_ID_CHECK = 98,
// END: 0011366 sehyuny.kim@lge.com 2010-11-25
//BEGIN:byungyong.hwang
	TEST_MODE_KEY_LOCK =99,
//END:byungyong.hwang
//BEGIN:seungkwan.jung
TEST_MODE_ACCELERATOR_SENSOR_TEST = 100,
TEST_MODE_GYRO_SENSOR_TEST_TEST,
TEST_MODE_COMPASS_SENSOR_TEST,


//END:seungkwan.jung

//Added by jaeopark 110527 for XO Cal Backup
  TEST_MODE_XO_CAL_DATA_COPY=250,


  MAX_TEST_MODE_SUBCMD = 0xFFFF
  //TEST_MODE_CURRENT,
  //TEST_MODE_BREW_FILES,
} PACKED test_mode_sub_cmd_type;

#define TESTMODE_MSTR_TBL_SIZE   128

#define ARM9_PROCESSOR       0
#define ARM11_PROCESSOR     1

typedef void*(* testmode_func_type)(test_mode_req_type * , DIAG_TEST_MODE_F_rsp_type * );

typedef struct
{
  word cmd_code;
	testmode_func_type func_ptr;
  byte  which_procesor;             // to choose which processor will do act.
}testmode_user_table_entry_type;

/* LGE_CHANGES_S, [dongp.kim@lge.com], 2010-01-10, <LGE_FACTORY_TEST_MODE for WLAN RF Test > */
typedef struct
{
	uint16 countresult;
	uint16 wlan_status;
	uint16 g_wlan_status;
	uint16 rx_channel;
	uint16 rx_per;
	uint16 tx_channel;
	uint32 goodFrames;
	uint16 badFrames;
	uint16 rxFrames;
	uint16 wlan_data_rate;
	uint16 wlan_payload;
	uint16 wlan_data_rate_recent;
	unsigned long pktengrxducast_old;
	unsigned long pktengrxducast_new;
	unsigned long rxbadfcs_old;
	unsigned long rxbadfcs_new;
	unsigned long rxbadplcp_old;
	unsigned long rxbadplcp_new;

}wlan_status;
/* LGE_CHANGES_E, [dongp.kim@lge.com], 2010-01-10, <LGE_FACTORY_TEST_MODE for WLAN RF Test > */

typedef struct DIAG_TEST_MODE_KEY_F_rsp_tag {
  diagpkt_header_type		xx_header;
  word					sub_cmd_code;
  test_mode_ret_stat_type	ret_stat_code;
  byte key_pressed_buf[MAX_KEY_BUFF_SIZE];
} PACKED DIAG_TEST_MODE_KEY_F_rsp_type;

#endif /* LG_DIAG_TESTMODE_H */
