#include <linux/module.h>
#include <lg_diagcmd.h>
#include <linux/input.h>
#include <linux/syscalls.h>

#include <lg_fw_diag_communication.h>
#include <lg_diag_testmode.h>
/*BEGIN: 0011452 kiran.kanneganti@lge.com 2010-11-26*/
/*ADD 0011452: Noice cancellation check support for testmode*/
#include <mach/qdsp5v2/audio_def.h>
/* END: 0011452 kiran.kanneganti@lge.com 2010-11-26 */
#include <linux/delay.h>

#ifndef SKW_TEST
#include <linux/fcntl.h> 
#include <linux/fs.h>
#include <linux/uaccess.h>
#endif

#ifdef CONFIG_LGE_DLOAD_SRD
#include <userDataBackUpDiag.h>
#include <userDataBackUpTypeDef.h> 
#include <../../kernel/arch/arm/mach-msm/smd_private.h>
#include <linux/slab.h>
#endif 

#include <linux/msm-charger.h>

//for reading HW revision
//#include <../../kernel/arch/arm/mach-msm/include/mach/Board_lge.h>
#include <mach/board_lge.h>

#include <lg_backup_items.h>

// BEGIN : munho.lee@lge.com 2011-01-15
// ADD: 0013541: 0014142: [Test_Mode] To remove Internal memory information in External memory test when SD-card is not exist 
#include <linux/gpio.h>
#include <linux/mfd/pmic8058.h>
#include <mach/irqs.h>
#define SYS_GPIO_SD_DET	21  
/* SYS GPIO Number 22 */
//#include <../../kernel/arch/arm/mach-msm/board-msm8960.c> //dy.lee

// END : munho.lee@lge.com 2011-01-15
#define PM8058_GPIO_BASE NR_MSM_GPIOS
#define PM8058_GPIO_PM_TO_SYS(pm_gpio) (pm_gpio + PM8058_GPIO_BASE)
static struct diagcmd_dev *diagpdev;

extern PACK(void *) diagpkt_alloc (diagpkt_cmd_code_type code, unsigned int length);
extern PACK(void *) diagpkt_free (PACK(void *)pkt);
extern void send_to_arm9( void*	pReq, void	*pRsp);
extern testmode_user_table_entry_type testmode_mstr_tbl[TESTMODE_MSTR_TBL_SIZE];
extern int diag_event_log_start(void);
extern int diag_event_log_end(void);
extern void set_operation_mode(boolean isOnline);
extern struct input_dev* get_ats_input_dev(void);
extern unsigned int LGF_KeycodeTrans(word input);
extern void LGF_SendKey(word keycode);
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
extern int boot_info;
// END: 0011366 sehyuny.kim@lge.com 2010-11-25

extern void remote_rpc_srd_cmmand(void*pReq, void* pRsp );
extern void *smem_alloc(unsigned id, unsigned size);

extern PACK (void *)LGE_Dload_SRD (PACK (void *)req_pkt_ptr, uint16 pkg_len);
extern void diag_SRD_Init(udbp_req_type *req_pkt, udbp_rsp_type *rsp_pkt);
extern void diag_userDataBackUp_entrySet(udbp_req_type *req_pkt, udbp_rsp_type *rsp_pkt, script_process_type MODEM_MDM );
extern boolean writeBackUpNVdata( char * ram_start_address , unsigned int size);
#ifdef CONFIG_LGE_DLOAD_SRD  //kabjoo.choi
#define SIZE_OF_SHARD_RAM  0x60000  //384K

extern int lge_erase_block(int secnum, size_t size);
extern int lge_write_block(int secnum, unsigned char *buf, size_t size);
extern int lge_read_block(int secnum, unsigned char *buf, size_t size);
extern int lge_mmc_scan_partitions(void);
//yss
extern void msm_get_MEID_type(char* sMeid);
//yss
extern unsigned int srd_bytes_pos_in_emmc ;
unsigned char * load_srd_shard_base;
unsigned char * load_srd_kernel_base;
#endif 

#ifdef CONFIG_LGE_DLOAD_SRD  //kabjoo.choi
#define SIZE_OF_SHARD_RAM  0x60000  //384K
#if 0
#define MISC_PARTITION_TOT_SIZE 0x800000
#define MISC_ONE_PARTITION_MODEM_NV_SIZE  0x100000
#define MISC_TWO_PARTITION_MODEM_CAL_SIZE  0x100000
#define MISC_THREE_PARTITION_MODEM_EXTRA_SIZE  0x100000
#define MISC_FOUR_PARTITION_MODEM_PRL_SIZE  0x100000

#define MISC_FIVE_PARTITION_MDM_NV_SIZE  0x100000
#define MISC_SIX_PARTITION_MDM_CAL_SIZE  0x100000
#define MISC_SEVEN_PARTITION_MDM_EXTRA_SIZE  0x100000
#define MISC_EIGHT_PARTITION_MDM_PRL_SIZE  0x100000
#endif 
extern int lge_erase_block(int secnum, size_t size);
extern int lge_write_block(int secnum, unsigned char *buf, size_t size);
extern int lge_read_block(int secnum, unsigned char *buf, size_t size);
extern int lge_mmc_scan_partitions(void);

extern unsigned int srd_bytes_pos_in_emmc ;
unsigned char * load_srd_shard_base;
unsigned char * load_srd_kernel_base;
#endif 

/* ==========================================================================
===========================================================================*/

struct statfs_local {
 __u32 f_type;
 __u32 f_bsize;
 __u32 f_blocks;
 __u32 f_bfree;
 __u32 f_bavail;
 __u32 f_files;
 __u32 f_ffree;
 __kernel_fsid_t f_fsid;
 __u32 f_namelen;
 __u32 f_frsize;
 __u32 f_spare[5];
};

/* ==========================================================================
===========================================================================*/

extern int lge_bd_rev;

void CheckHWRev(byte *pStr)
{
        char *rev_str[] = {"evb1", "evb2", "A", "B", "C", "D",
                "E", "F", "G", "1.0", "1.1", "1.2"
                "revserved"};
        strcpy((char *)pStr ,(char *)rev_str[lge_bd_rev]);
}

PACK (void *)LGF_TestMode (
        PACK (void	*)req_pkt_ptr,	/* pointer to request packet  */
        uint16		pkt_len )		      /* length of request packet   */
{
  DIAG_TEST_MODE_F_req_type *req_ptr = (DIAG_TEST_MODE_F_req_type *) req_pkt_ptr;
  DIAG_TEST_MODE_F_rsp_type *rsp_ptr;  
  unsigned int rsp_len=0;
  testmode_func_type func_ptr= NULL;
  int nIndex = 0;

  diagpdev = diagcmd_get_dev();
  printk(KERN_DEBUG "%s, LGF_TestMode diagpdev , testmode_command : %d\n", __func__,req_ptr->sub_cmd_code); 

  // DIAG_TEST_MODE_F_rsp_type union type is greater than the actual size, decrease it in case sensitive items
  switch(req_ptr->sub_cmd_code)
  {
    case TEST_MODE_FACTORY_RESET_CHECK_TEST:
      rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type);
      break;

    case TEST_MODE_TEST_SCRIPT_MODE:
      rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type) + sizeof(test_mode_req_test_script_mode_type);
      break;

    //0017509: [DV] REMOVE UNNECESSARY RESPONSE PACKET FOR EXTERNEL SOCKET ERASE 
    case TEST_MODE_EXT_SOCKET_TEST:
      if((req_ptr->test_mode_req.esm == EXTERNAL_SOCKET_ERASE) || (req_ptr->test_mode_req.esm == EXTERNAL_SOCKET_ERASE_SDCARD_ONLY) \
      	|| (req_ptr->test_mode_req.esm == EXTERNAL_SOCKET_ERASE_FAT_ONLY))
        rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type);
            else
                rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type);
      break;

   //Added by jaeopark 110527 for XO Cal Backup
    case TEST_MODE_XO_CAL_DATA_COPY:
      rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type) + sizeof(test_mode_req_XOCalDataBackup_Type);
	break;

        case TEST_MODE_MANUAL_MODE_TEST:
            rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type) + sizeof(test_mode_req_manual_test_mode_type);
            break;

        case TEST_MODE_BLUETOOTH_RW:
            rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type) + sizeof(test_mode_req_bt_addr_type);
            break;

        case TEST_MODE_WIFI_MAC_RW:
            rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type) + sizeof(test_mode_req_wifi_addr_type);
            break;

    default :
      rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type);
      break;
  }

  rsp_ptr = (DIAG_TEST_MODE_F_rsp_type *)diagpkt_alloc(DIAG_TEST_MODE_F, rsp_len);

  if (!rsp_ptr)
  	return 0;
  
  rsp_ptr->sub_cmd_code = req_ptr->sub_cmd_code;
  rsp_ptr->ret_stat_code = TEST_OK_S; // test ok

  for( nIndex = 0 ; nIndex < TESTMODE_MSTR_TBL_SIZE  ; nIndex++)
  {
    if( testmode_mstr_tbl[nIndex].cmd_code == req_ptr->sub_cmd_code)
    {
        if( testmode_mstr_tbl[nIndex].which_procesor == ARM11_PROCESSOR)
          func_ptr = testmode_mstr_tbl[nIndex].func_ptr;
      break;
    }
  }

  if( func_ptr != NULL)
    return func_ptr( &(req_ptr->test_mode_req), rsp_ptr);
  else {
  	if(req_ptr->test_mode_req.version == VER_HW) // read from kernel
  		CheckHWRev((byte *)rsp_ptr->test_mode_rsp.str_buf);
	else
    	send_to_arm9((void*)req_ptr, (void*)rsp_ptr);
  }

  return (rsp_ptr);
}
EXPORT_SYMBOL(LGF_TestMode);

void* linux_app_handler(test_mode_req_type*	pReq, DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
	diagpkt_free(pRsp);
  return 0;
}

void* not_supported_command_handler(test_mode_req_type*	pReq, DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
	pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
  return pRsp;
}

/* LCD QTEST */
PACK (void *)LGF_LcdQTest (
        PACK (void	*)req_pkt_ptr,	/* pointer to request packet  */
        uint16		pkt_len )		      /* length of request packet   */
{
	/* Returns 0 for executing lg_diag_app */
	return 0;
}
EXPORT_SYMBOL(LGF_LcdQTest);
// BEGIN: 0010557  unchol.park@lge.com 2010-11-18
// 0010557 : [Testmode] added test_mode command for LTE test 
// add call function	
void* LGF_TestModeLteModeSelection(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
#if 0
    pRsp->ret_stat_code = TEST_OK_S;

	if (diagpdev != NULL){
		update_diagcmd_state(diagpdev, "LTEMODESELETION", pReq->mode_seletion);
	}
	else
	{
		printk("\n[%s] error LteModeSelection", __func__ );
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif 
  return pRsp;

}

void* LGF_TestModeLteCall(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
#if 0
    pRsp->ret_stat_code = TEST_OK_S;

	if (diagpdev != NULL){
		update_diagcmd_state(diagpdev, "LTECALL", pReq->lte_call);
	}
	else
	{
		printk("\n[%s] error LteCall", __func__ );
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif
  return pRsp;
 
}
// BEGIN: 0010557  unchol.park@lge.com 2011-01-12
// 0010557 : [Testmode] added test_mode command for LTE test 
void* LGF_TestModeDetach(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{

#if 0
	DIAG_TEST_MODE_F_req_type req_ptr; 

	printk("\n[%s] First LteCallDetach", __func__ );

	if(pReq->lte_virtual_sim == 21)
	{
		printk("\n[%s] Second LteCallDetach", __func__ );
		pRsp->ret_stat_code = TEST_OK_S;
		
		if (diagpdev != NULL){
			update_diagcmd_state(diagpdev, "LTECALLDETACH", pReq->lte_virtual_sim);
		}
		else
		{
			printk("\n[%s] error LteCallDetach", __func__ );
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
		}
		return pRsp;
	}

	req_ptr.sub_cmd_code = 44;
	req_ptr.test_mode_req.lte_virtual_sim = pReq->lte_virtual_sim;
	printk(KERN_INFO "%s, pReq->lte_virtual_sim : %d\n", __func__, pReq->lte_virtual_sim);

	send_to_arm9((void*)&req_ptr, (void*)pRsp);
	printk(KERN_INFO "%s, pRsp->ret_stat_code : %d\n", __func__, pRsp->ret_stat_code);
#endif 
	
  	return pRsp;

}
// END: 0010557 unchol.park@lge.com 2011-01-12

// END: 0010557 unchol.park@lge.com 2010-11-18

/* [yk.kim@lge.com] 2011-01-04, change usb driver */
extern int android_set_pid(const char *val, struct kernel_param *kp);
void* LGF_TestModeChangeUsbDriver(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
	printk(KERN_DEBUG "%s, req type : %d", __func__, pReq->change_usb_driver);
	pRsp->ret_stat_code = TEST_OK_S;

	if (pReq->change_usb_driver == CHANGE_MODEM)
		android_set_pid("6315", NULL);
	else if (pReq->change_usb_driver == CHANGE_MASS)
		android_set_pid("6320", NULL);
	else
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
 
	return pRsp;

}

#if 1//def CONFIG_LGE_BATT_SOC_FOR_NPST
void* LGF_TestModeBattLevel(test_mode_req_type*	pReq, DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
  	//word battery_soc;
	int batt_thm_adc=0;
	
  	char buf[5];
  	int max17040_vcell = 0;
	int batt_complete_check = 0;
		
	int guage_level = 0;
	int battery_soc = 0;

	extern int testmode_battery_read_temperature_adc(void);
	extern int max17040_get_battery_mvolts(void);
	extern void max17040_quick_start(void);
	extern int max17040_get_battery_capacity_percent(void);
	
	pRsp->ret_stat_code = TEST_OK_S;

	switch(pReq->batt)
	{
		case BATTERY_THERM_ADC:
			batt_thm_adc = testmode_battery_read_temperature_adc();
			printk(KERN_ERR "%s, battery adc : %d\n", __func__, batt_thm_adc);
			if(batt_thm_adc > 2200)
				pRsp->ret_stat_code = TEST_FAIL_S;
			break;

		case BATTERY_VOLTAGE_LEVEL:
			max17040_vcell = max17040_get_battery_mvolts();
		
			if (max17040_vcell >= 4200)
				sprintf(buf, "%s", "4.2");
			else if (max17040_vcell >= 4100 && max17040_vcell < 4200)
				sprintf(buf, "%s", "4.1");
			else if (max17040_vcell >= 4000 && max17040_vcell < 4100)
				sprintf(buf, "%s", "4.0");
			else if (max17040_vcell >= 3900 && max17040_vcell < 4000)
				sprintf(buf, "%s", "3.9");
			else if (max17040_vcell >= 3800 && max17040_vcell < 3900)
				sprintf(buf, "%s", "3.8");
			else if (max17040_vcell >= 3700 && max17040_vcell < 3800)
				sprintf(buf, "%s", "3.7");
			else if (max17040_vcell >= 3600 && max17040_vcell < 3700)
				sprintf(buf, "%s", "3.6");
			else if (max17040_vcell >= 3500 && max17040_vcell < 3600)
				sprintf(buf, "%s", "3.5");
			else if (max17040_vcell >= 3400 && max17040_vcell < 3500)
				sprintf(buf, "%s", "3.4");
			else if (max17040_vcell >= 3300 && max17040_vcell < 3400)
				sprintf(buf, "%s", "3.3");
			else if (max17040_vcell >= 3200 && max17040_vcell < 3300)
				sprintf(buf, "%s", "3.2");
			else if (max17040_vcell >= 3100 && max17040_vcell < 3200)
				sprintf(buf, "%s", "3.1");
			else if (max17040_vcell >= 3000 && max17040_vcell < 3100)
				sprintf(buf, "%s", "3.0");
			else if (max17040_vcell >= 2900 && max17040_vcell < 3000)
				sprintf(buf, "%s", "2.9");

			sprintf((char *)pRsp->test_mode_rsp.batt_voltage, "%s", buf);
			break;

		case BATTERY_CHARGING_COMPLETE:
			testmode_discharging_mode_test();

			msleep(300);
			max17040_quick_start();
			msleep(300);
			batt_complete_check = max17040_get_battery_capacity_percent();
			msleep(100);

			if(batt_complete_check >=95)
				pRsp->test_mode_rsp.chg_stat = 0;
			else
				pRsp->test_mode_rsp.chg_stat = 1;

			if(pRsp->test_mode_rsp.chg_stat)
		  		testmode_charging_mode_test();
			break;

		case BATTERY_CHARGING_MODE_TEST:
			LGF_SendKey(KEY_POWER);
			//if_condition_is_on_air_plain_mode = 1;
			update_diagcmd_state(diagpdev, "BATTERY_CHARGING_MODE_TEST", pReq->batt);
			set_operation_mode(FALSE);
			
			testmode_discharging_mode_test();

			msleep(300);
			max17040_quick_start();
			msleep(300);
			batt_complete_check = max17040_get_battery_capacity_percent();			
			msleep(100);
			
			testmode_charging_mode_test();
			break;

		case BATTERY_FUEL_GAUGE_RESET:
			max17040_quick_start();
			msleep(300);
			max17040_get_battery_mvolts();
			break;

		case BATTERY_FUEL_GAUGE_SOC:
			testmode_discharging_mode_test();
			
			msleep(300);
			max17040_quick_start();
			msleep(300);
			guage_level = max17040_get_battery_capacity_percent();
			msleep(100);
			guage_level = max17040_get_battery_capacity_percent();
			
			if(guage_level > 100)
				guage_level = 100;
			else if (guage_level < 0)
				guage_level = 0;

			sprintf((char *)pRsp->test_mode_rsp.batt_voltage, "%d", guage_level);
			break;

		case BATTERY_FUEL_GAUGE_SOC_NPST: // this is for getting SoC in NPST
			battery_soc = (int)max17040_get_battery_capacity_percent();
			if(battery_soc > 100)
				battery_soc = 100;
			else if (battery_soc < 0)
				battery_soc = 0;
			printk(KERN_ERR "%s, battery_soc : %d\n", __func__, battery_soc);
			sprintf((char *)pRsp->test_mode_rsp.batt_voltage, "%d", battery_soc);
			printk(KERN_ERR "%s, battery_soc : %s\n", __func__, (char *)pRsp->test_mode_rsp.batt_voltage);
			break;

		default:
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
			break;	

	}
	return pRsp;
}
#endif

// BEGIN: 0009352 chanha.park@lge.com 2010-09-27
// MOD: 0009352: [BRYCE][BT] Support BT Factory Testmode.
/* TEST_MODE_BLUETOOTH_TEST */
#if 1 //#ifndef LG_BTUI_TEST_MODE
void* LGF_TestModeBlueTooth(
		test_mode_req_type*	pReq,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
	printk(KERN_ERR "[_BTUI_] [%s:%d] BTSubCmd=<%d>\n", __func__, __LINE__, pReq->bt);

	if (diagpdev != NULL){
		update_diagcmd_state(diagpdev, "BT_TEST_MODE", pReq->bt);
		if(pReq->bt==1 || pReq->bt==11) msleep(5900); //6sec timeout
		else if(pReq->bt==2) ssleep(1);
		else ssleep(3);
		pRsp->ret_stat_code = TEST_OK_S;
	}
	else
	{
		printk(KERN_ERR "[_BTUI_] [%s:%d] BTSubCmd=<%d> ERROR\n", __func__, __LINE__, pReq->bt);
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
	return pRsp;
}

byte *pReq_valid_address(byte *pstr)
{
	int pcnt=0;
	byte value_pstr=0, *pstr_tmp;

	pstr_tmp = pstr;
	do
	{
		++pcnt;
		value_pstr = *(pstr_tmp++);
	}while(!('0'<=value_pstr && value_pstr<='9')&&!('a'<=value_pstr && value_pstr<='f')&&!('A'<=value_pstr && value_pstr<='F')&&(pcnt<BT_RW_CNT));

	return (--pstr_tmp);

}

byte g_bd_addr[BT_RW_CNT];

void* LGF_TestModeBlueTooth_RW(
		test_mode_req_type*	pReq,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{

	byte *p_Req_addr;

	p_Req_addr = pReq_valid_address(pReq->bt_rw);

	if(!p_Req_addr)
	{
		pRsp->ret_stat_code = TEST_FAIL_S;
		return pRsp;
	}

	printk(KERN_ERR "[_BTUI_] [%s:%d] BTSubCmd=<%s>\n", __func__, __LINE__, p_Req_addr);

	if (diagpdev != NULL)
	{
		//250-83-0 bluetooth write
		if(strlen(p_Req_addr) > 0)
		{
			update_diagcmd_state(diagpdev, "BT_TEST_MODE_RW", 0);
			memset((void*)g_bd_addr, 0x00, BT_RW_CNT);
			memcpy((void*)g_bd_addr, p_Req_addr, BT_RW_CNT);
			msleep(5900); //6sec timeout
		}
		//250-83-1 bluetooth read
		else
		{
			update_diagcmd_state(diagpdev, "BT_TEST_MODE_RW", 1);
			if(strlen(g_bd_addr)==0) {
				pRsp->ret_stat_code = TEST_FAIL_S;
				return pRsp;
			}
			memset((void*)pRsp->test_mode_rsp.read_bd_addr, 0x00, BT_RW_CNT);
			memcpy((void*)pRsp->test_mode_rsp.read_bd_addr, g_bd_addr, BT_RW_CNT);
		}
		pRsp->ret_stat_code = TEST_OK_S;
	}
	else 
	{
		printk(KERN_ERR "[_BTUI_] [%s:%d] BTSubCmd=<%s> ERROR\n", __func__, __LINE__, pReq->bt_rw);
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
  return pRsp;

}
#endif //LG_BTUI_TEST_MODE
// END: 0009352 chanha.park@lge.com 2010-09-27


void* LGF_TestPhotoSensor(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
	/* The photosensor isn't supported in VS910 model
	*/
	pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;

#if 0
	if (diagpdev != NULL){
		update_diagcmd_state(diagpdev, "ALC", pReq->motor);
	}
	else
	{
		printk("\n[%s] error MOTOR", __func__ );
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif

  return pRsp;
}


void* LGF_TestMotor(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
#if 1
	pRsp->ret_stat_code = TEST_OK_S;

	if (diagpdev != NULL){
		update_diagcmd_state(diagpdev, "MOTOR", pReq->motor);
	}
	else
	{
		printk("\n[%s] error MOTOR", __func__ );
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif 
  return pRsp;

}

int lgf_key_lock = 0;

void* LGF_TestAcoustic(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
#if 1
    pRsp->ret_stat_code = TEST_OK_S;

	if (diagpdev != NULL){
		if(pReq->acoustic > ACOUSTIC_LOOPBACK_OFF)
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
		if(pReq->acoustic == ACOUSTIC_ON)
			lgf_key_lock = 0x55;
		else if(pReq->acoustic == ACOUSTIC_OFF)
			lgf_key_lock = 0;
		
		update_diagcmd_state(diagpdev, "ACOUSTIC", pReq->acoustic);
	}
	else
	{
		printk("\n[%s] error ACOUSTIC", __func__ );
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif 
  return pRsp;

}

void* LGF_TestModeMP3 (
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
#if 1
	pRsp->ret_stat_code = TEST_OK_S;
//	printk("\n[%s] diagpdev 0x%x", __func__, diagpdev );

	if (diagpdev != NULL){
		if(pReq->mp3_play == MP3_SAMPLE_FILE)
		{
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
		}
		else
		{
			update_diagcmd_state(diagpdev, "MP3", pReq->mp3_play);
		}
	}
	else
	{
		printk("\n[%s] error MP3", __func__ );
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif
  return pRsp;

}

void* LGF_TestModeSpeakerPhone(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
#if 1
	pRsp->ret_stat_code = TEST_OK_S;

	if (diagpdev != NULL){
/*BEGIN: 0011452 kiran.kanneganti@lge.com 2010-11-26*/
/*ADD 0011452: Noice cancellation check support for testmode*/	
//#ifdef SINGLE_MIC_PHONE		
#if 0
		if((pReq->speaker_phone == NOMAL_Mic1) || (pReq->speaker_phone == NC_MODE_ON)
			|| (pReq->speaker_phone == ONLY_MIC2_ON_NC_ON) || (pReq->speaker_phone == ONLY_MIC1_ON_NC_ON)
		)
		{
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
		}
#endif
//#else
		if(pReq->speaker_phone == NOMAL_Mic1)
		{
			update_diagcmd_state(diagpdev, "SPEAKERPHONE", pReq->speaker_phone);
		}
		else if( ONLY_MIC1_ON_NC_ON == pReq->speaker_phone )
		{	
//			lge_connect_disconnect_back_mic_path_inQTR(0);
//			lge_connect_disconnect_main_mic_path_inQTR(1);
			update_diagcmd_state(diagpdev, "SPEAKERPHONE", pReq->speaker_phone);
		}
		else if( ONLY_MIC2_ON_NC_ON == pReq->speaker_phone )
		{
//			lge_connect_disconnect_back_mic_path_inQTR(1);
//			lge_connect_disconnect_main_mic_path_inQTR(0);
			update_diagcmd_state(diagpdev, "SPEAKERPHONE", pReq->speaker_phone);
		}		
		else if( NC_MODE_ON == pReq->speaker_phone )
		{
//			lge_connect_disconnect_back_mic_path_inQTR(1);
//			lge_connect_disconnect_main_mic_path_inQTR(1);
			update_diagcmd_state(diagpdev, "SPEAKERPHONE", pReq->speaker_phone);
		}

/* END: 0011452 kiran.kanneganti@lge.com 2010-11-26 */
		else
		{
			update_diagcmd_state(diagpdev, "SPEAKERPHONE", pReq->speaker_phone);
		}
	}
	else
	{
		printk("\n[%s] error SPEAKERPHONE", __func__ );
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif
  return pRsp;
 
}

void* LGT_TestModeVolumeLevel (
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type *pRsp)
{
#if 1
	pRsp->ret_stat_code = TEST_OK_S;

	if (diagpdev != NULL){
		update_diagcmd_state(diagpdev, "VOLUMELEVEL", pReq->volume_level);
	}
	else
	{
		printk("\n[%s] error VOLUMELEVEL", __func__ );
		pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif 
  return pRsp;

}

byte key_buf[MAX_KEY_BUFF_SIZE];
boolean if_condition_is_on_key_buffering = FALSE;
int count_key_buf = 0;

boolean lgf_factor_key_test_rsp (char key_code)
{
    /* sanity check */
    if (count_key_buf>=MAX_KEY_BUFF_SIZE)
        return FALSE;

    key_buf[count_key_buf++] = (byte)key_code;
    return TRUE;
}
EXPORT_SYMBOL(lgf_factor_key_test_rsp);

void* LGT_TestModeKeyTest(test_mode_req_type* pReq, DIAG_TEST_MODE_F_rsp_type *pRsp)
{
  pRsp->ret_stat_code = TEST_OK_S;

  if(pReq->key_test_start){
	memset((void *)key_buf,0x00,MAX_KEY_BUFF_SIZE);
	count_key_buf=0;
	diag_event_log_start();
  }
  else
  {
	memcpy((void *)((DIAG_TEST_MODE_KEY_F_rsp_type *)pRsp)->key_pressed_buf, (void *)key_buf, MAX_KEY_BUFF_SIZE);
	memset((void *)key_buf,0x00,MAX_KEY_BUFF_SIZE);
	diag_event_log_end();
  }  
  return pRsp;
}

void* LGF_TestCam(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
		pRsp->ret_stat_code = TEST_OK_S;

		switch(pReq->camera)
		{
			case CAM_TEST_SAVE_IMAGE:
			//case CAM_TEST_FLASH_ON:
			//case CAM_TEST_FLASH_OFF:
				pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;

			default:
				if (diagpdev != NULL){

					update_diagcmd_state(diagpdev, "CAMERA", pReq->camera);
				}
				else
				{
					printk("\n[%s] error CAMERA", __func__ );
					pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
				}
				break;
		}
	return pRsp;
}

/* sangwoo.kang	2010.09.03
					build error debugging */
#if 1 //def CONFIG_LGE_TOUCH_TEST
void* LGF_TestModeKeyData(	test_mode_req_type* pReq ,DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
	pRsp->ret_stat_code = TEST_OK_S;

	LGF_SendKey(LGF_KeycodeTrans(pReq->key_data));

	return pRsp;
}

// BEGIN 0011665: eundeok.bae@lge.com FTM MODE FOR ONLY KERNEL BOOTING
// [KERNEL] Added source code For Sleep Mode Test, Test Mode V8.3 [250-42] 
uint8_t if_condition_is_on_air_plain_mode = 0;
extern void remote_set_operation_mode(int info);
extern void remote_set_ftm_boot(int info);
// END 0011665: eundeok.bae@lge.com FTM MODE FOR ONLY KERNEL BOOTING

// BEGIN 0012299: eundeok.bae@lge.com 2010-12-13 FTM MODE RESET
// [KERNEL] ADDED "FTM BOOT RESET" Function For Test Mode 
extern void remote_set_ftmboot_reset(uint32 info);
// END 0012299: eundeok.bae@lge.com 2010-12-13

void* LGF_PowerSaveMode(test_mode_req_type* pReq, DIAG_TEST_MODE_F_rsp_type* pRsp)
{
#if 1
	pRsp->ret_stat_code = TEST_OK_S;
	pReq->sleep_mode = (pReq->sleep_mode & 0x00FF); 	// 2011.06.21 biglake for power test after cal

	switch(pReq->sleep_mode){	
		case SLEEP_MODE_ON:
			LGF_SendKey(KEY_POWER);
			break;		
		case SLEEP_FLIGHT_MODE_ON:
			LGF_SendKey(KEY_POWER);
			//if_condition_is_on_air_plain_mode = 1;
			update_diagcmd_state(diagpdev, "SLEEP_FLIGHT_MODE_ON", pReq->sleep_mode);
			set_operation_mode(FALSE);
			break;
	  	case FLIGHT_KERNEL_MODE_ON:
			break;
		case FLIGHT_MODE_OFF:
			set_operation_mode(TRUE);
			break;
		default:
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
#endif
	return pRsp;
 
}
#endif /* CONFIG_LGE_TOUCH_TEST */

char external_memory_copy_test(void)
{

    char return_value = TEST_FAIL_S;
#if 1
	char *src = (void *)0;
	char *dest = (void *)0;
	off_t fd_offset;
	int fd;
	mm_segment_t old_fs=get_fs(); //二쇱???�븳????????�뱷???꾪빐
    set_fs(get_ds());

// BEGIN : munho.lee@lge.com 2010-12-30
// MOD: 0013315: [SD-card] SD-card drectory path is changed in the testmode
//	if ( (fd = sys_open((const char __user *) "/sdcard/_ExternalSD/SDTest.txt", O_CREAT | O_RDWR, 0) ) < 0 )

	if ( (fd = sys_open((const char __user *) "/sdcard/SDTest.txt", O_CREAT | O_RDWR, 0) ) < 0 )
	
// END : munho.lee@lge.com 2010-12-30
	{
		printk(KERN_ERR "[ATCMD_EMT] Can not access SD card\n");
		goto file_fail;
	}

	if ( (src = kmalloc(10, GFP_KERNEL)) )
	{
		sprintf(src,"TEST");
		if ((sys_write(fd, (const char __user *) src, 5)) < 0)
		{
			printk(KERN_ERR "[ATCMD_EMT] Can not write SD card \n");
			goto file_fail;
		}
		fd_offset = sys_lseek(fd, 0, 0);
	}
	if ( (dest = kmalloc(10, GFP_KERNEL)) )
	{
		if ((sys_read(fd, (char __user *) dest, 5)) < 0)
		{
			printk(KERN_ERR "[ATCMD_EMT]Can not read SD card \n");
			goto file_fail;
		}
		if ((memcmp(src, dest, 4)) == 0)
            return_value = TEST_OK_S;
		else
            return_value = TEST_FAIL_S;
	}

	kfree(src);
	kfree(dest);
file_fail:
	sys_close(fd);
    set_fs(old_fs);
// BEGIN : munho.lee@lge.com 2010-12-30
// MOD: 0013315: [SD-card] SD-card drectory path is changed in the testmode
//	sys_unlink((const char __user *)"/sdcard/_ExternalSD/SDTest.txt");

	sys_unlink((const char __user *)"/sdcard/SDTest.txt");

// END : munho.lee@lge.com 2010-12-30

#endif 
	return return_value;
}
char external_memory_after_format_file_test(int order)
{

    char return_value = TEST_FAIL_S;
	char *src = (void *)0;
    char *dest = (void *)0;
	off_t fd_offset;
	int fd = 0;
	mm_segment_t old_fs=get_fs(); //二쇱???�븳????????�뱷???꾪빐
    set_fs(get_ds());
    

    switch(order){
      case 1:
        if ( (fd = sys_open((const char __user *) "/sdcard/SDTest.txt", O_CREAT | O_RDWR, 0) ) < 0 )
    	{
    		printk(KERN_ERR "[ATCMD_EMT] Can not access SD card\n");
    		goto file_fail;
    	}

    	if ( (src = kmalloc(10, GFP_KERNEL)) )
    	{
    		sprintf(src,"TEST");
    		if ((sys_write(fd, (const char __user *) src, 5)) < 0)
    		{
    			printk(KERN_ERR "[ATCMD_EMT] Can not write SD card \n");
    			goto file_fail;
    		}
    		fd_offset = sys_lseek(fd, 0, 0);
    	}
    	if ( (dest = kmalloc(10, GFP_KERNEL)) )
    	{
    		if ((sys_read(fd, (char __user *) dest, 5)) < 0)
    		{
    			printk(KERN_ERR "[ATCMD_EMT]Can not read SD card \n");
    			goto file_fail;
    		}
    		if ((memcmp(src, dest, 4)) == 0)
                return_value = TEST_OK_S;
    		else
                return_value = TEST_FAIL_S;
    	}

    	kfree(src);
    	kfree(dest);
        break;
    
    case 2:
    if ( (fd = sys_open((const char __user *) "/sdcard/SDTest.txt", O_RDONLY, 0) ) < 0 ){
		printk(KERN_ERR "[ATCMD_EMT] Noraml! File is not exist After format SD card\n");
        return_value = TEST_OK_S;
	}        
	else{   
        printk(KERN_ERR "[ATCMD_EMT] File is exist. After format \n");
        return_value = TEST_FAIL_S;
    }
    break;
  }


file_fail:
    
	sys_close(fd);
    set_fs(old_fs);

    if(order == 2)
	    sys_unlink((const char __user *)"/sdcard/SDTest.txt");



	return return_value;
}

extern int external_memory_test;

void* LGF_ExternalSocketMemory(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
#if 1    //dy.lee
    struct statfs_local sf;    
    pRsp->ret_stat_code = TEST_FAIL_S;

    printk(KERN_ERR "[Testmode Memory Test]sdcard start\n");
    // ADD: 0013541: 0014142: [Test_Mode] To remove Internal memory information in External memory test when SD-card is not exist
    if(gpio_get_value(SYS_GPIO_SD_DET)) //?�정?�야??kernel panic 발생
    {
        if (pReq->esm == EXTERNAL_SOCKET_MEMORY_CHECK)
        {
            pRsp->test_mode_rsp.memory_check = TEST_FAIL_S;
            pRsp->ret_stat_code = TEST_OK_S;
            printk(KERN_NOTICE "[Testmode Memory Test] Can not detect SD card :TEST_FAIL_S\n");
        }
        
        printk(KERN_ERR "[Testmode Memory Test] Can not detect SD card\n");
        return pRsp;
    }



    switch( pReq->esm){
        case EXTERNAL_SOCKET_MEMORY_CHECK:
            pRsp->test_mode_rsp.memory_check = external_memory_copy_test();
            pRsp->ret_stat_code = TEST_OK_S;
            printk(KERN_NOTICE "[Testmode Memory Test] EXTERNAL_SOCKET_MEMORY_CHECK :TEST_OK_S\n");    
            break;

        case EXTERNAL_FLASH_MEMORY_SIZE:
            if (sys_statfs("/sdcard", (struct statfs *)&sf) != 0)
            {
                printk(KERN_ERR "[Testmode Memory Test] can not get sdcard infomation \n");
                break;
            }

            pRsp->test_mode_rsp.socket_memory_size = ((long long)sf.f_blocks * (long long)sf.f_bsize) >> 20; // needs Mb.
            pRsp->ret_stat_code = TEST_OK_S;
            printk(KERN_NOTICE "[Testmode Memory Test] socket_memory_size:TEST_OK_S\n");    
            break;

        case EXTERNAL_SOCKET_ERASE: 
            pRsp->test_mode_rsp.memory_check = external_memory_after_format_file_test(1);
            if(pRsp->test_mode_rsp.memory_check == TEST_FAIL_S) break;
            if (diagpdev == NULL){
                  diagpdev = diagcmd_get_dev();
                  printk("\n[%s] diagpdev is Null ", __func__ );
            }
            
            if (diagpdev != NULL)
            {
                update_diagcmd_state(diagpdev, "MMCFORMAT", 1);
                msleep(5000);
                if(external_memory_after_format_file_test(2) == TEST_OK_S){
                pRsp->ret_stat_code = TEST_OK_S;
                printk("\n[%s] FACTORY_RESET OK", __func__ );
                }
                else{
                printk("\n[%s] error FACTORY_RESET", __func__ );
                pRsp->ret_stat_code = TEST_FAIL_S;    
                }
            }
            else
            {
                printk("\n[%s] error FACTORY_RESET", __func__ );
                pRsp->ret_stat_code = TEST_FAIL_S;
            }
            break;

        case EXTERNAL_FLASH_MEMORY_USED_SIZE:
#if 0
            if (sys_statfs("/sdcard", (struct statfs *)&sf) != 0)
            {
                printk(KERN_ERR "[Testmode Memory Test] can not get sdcard information \n");
                break;
            }

            pRsp->test_mode_rsp.socket_memory_usedsize = ((long long)(sf.f_blocks - (long long)sf.f_bfree) * sf.f_bsize);
            pRsp->ret_stat_code = TEST_OK_S;
            printk(KERN_DEBUG "[Testmode Memory Test] EXTERNAL_FLASH_MEMORY_USED_SIZE information \n");
#endif
            external_memory_test = -1;
            update_diagcmd_state(diagpdev, "CALCUSEDSIZE", 0);
            msleep(1000);

            if(external_memory_test != -1)
            {
                pRsp->test_mode_rsp.socket_memory_usedsize = external_memory_test;
                pRsp->ret_stat_code = TEST_OK_S;
            }
            else
            {
                pRsp->ret_stat_code = TEST_FAIL_S;
                printk(KERN_ERR "[CALCUSEDSIZE] DiagCommandObserver returned fail or didn't return in 100ms.\n");
            }

            break;
#if 0 //not support
        case EXTERNAL_FLASH_MEMORY_CONTENTS_CHECK:
            external_memory_test = -1;
            update_diagcmd_state(diagpdev, "CHECKCONTENTS", 0);
            msleep(1000);
            
            if(external_memory_test != -1)
            {
                if(external_memory_test == 1) pRsp->test_mode_rsp.memory_check = 1;
                else pRsp->test_mode_rsp.memory_check = 0;
                pRsp->ret_stat_code = TEST_OK_S;
            }
            else
            {
                pRsp->ret_stat_code = TEST_FAIL_S;
                printk(KERN_ERR "[CHECKCONTENTS] DiagCommandObserver returned fail or didn't return in 1000ms.\n");
            }
            
            break;

        case EXTERNAL_FLASH_MEMORY_ERASE:
            external_memory_test = -1;
            update_diagcmd_state(diagpdev, "ERASEMEMORY", 0);
            msleep(5000);
            
            if(external_memory_test != -1)
            {
                if(external_memory_test == 1) pRsp->test_mode_rsp.memory_check = 1;
                else pRsp->test_mode_rsp.memory_check = 0;
                pRsp->ret_stat_code = TEST_OK_S;
            }
            else
            {
                pRsp->ret_stat_code = TEST_FAIL_S;
                printk(KERN_ERR "[ERASEMEMORY] DiagCommandObserver returned fail or didn't return in 5000ms.\n");
            }
		break;
#endif
	case EXTERNAL_SOCKET_ERASE_SDCARD_ONLY: /*0xE*/
		if (diagpdev != NULL){
			update_diagcmd_state(diagpdev, "MMCFORMAT", EXTERNAL_SOCKET_ERASE_SDCARD_ONLY);		
			msleep(5000);
			pRsp->ret_stat_code = TEST_OK_S;
		}
		else 
		{
			printk("\n[%s] error EXTERNAL_SOCKET_ERASE_SDCARD_ONLY", __func__ );
			pRsp->ret_stat_code = TEST_FAIL_S;
		}
		break;
	case EXTERNAL_SOCKET_ERASE_FAT_ONLY: /*0xF*/
		if (diagpdev != NULL){
			update_diagcmd_state(diagpdev, "MMCFORMAT", EXTERNAL_SOCKET_ERASE_FAT_ONLY);		
			msleep(5000);
			pRsp->ret_stat_code = TEST_OK_S;
		}
		else 
		{
			printk("\n[%s] error EXTERNAL_SOCKET_ERASE_FAT_ONLY", __func__ );
			pRsp->ret_stat_code = TEST_FAIL_S;
		}
		break;

	default:
        pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
        break;
	}
#endif
    return pRsp;
}

/* BEGIN: 0015566 jihoon.lee@lge.com 20110207 */
/* ADD 0015566: [Kernel] charging mode check command */
#ifdef CONFIG_LGE_CHARGING_MODE_INFO
// this will be set if "/dev/chg_logo" file is written from the chargerlogo, dependant to models
static int first_booting_chg_mode_status = -1;
void set_first_booting_chg_mode_status(int status)
{
	first_booting_chg_mode_status = status;
	printk("%s, status : %d\n", __func__, first_booting_chg_mode_status);
}

int get_first_booting_chg_mode_status(void)
{
	printk("%s, status : %d\n", __func__, first_booting_chg_mode_status);
	return first_booting_chg_mode_status;
}
#endif
/* END: 0015566 jihoon.lee@lge.com 20110207 */

// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
void * LGF_TestModeFboot (	test_mode_req_type* pReq ,DIAG_TEST_MODE_F_rsp_type	*pRsp)
{

	switch( pReq->fboot)
	{
		case FIRST_BOOTING_COMPLETE_CHECK:
			printk("[Testmode] First Boot info ?? ====> %d \n", boot_info);
			if (boot_info)
				pRsp->ret_stat_code = TEST_OK_S;
			else
				pRsp->ret_stat_code = TEST_FAIL_S;
			break;

	    default:
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
			break;
	}

    return pRsp;

}
// END: 0011366 sehyuny.kim@lge.com 2010-11-25

// BEGIN : munho.lee@lge.com 2010-11-30
// ADD: 0011620: [Test_mode] Memory format test 
void* LGF_MemoryFormatTest(	test_mode_req_type* pReq ,DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
#if 0
  struct statfs_local  sf;
  unsigned int remained = 0;
  pRsp->ret_stat_code = TEST_OK_S;
  if (sys_statfs("/data", (struct statfs *)&sf) != 0)
  {
    printk(KERN_ERR "[Testmode]can not get sdcard infomation \n");
    pRsp->ret_stat_code = TEST_FAIL_S;
  }
  else
  {	
    switch(pReq->memory_format)
    {
      case MEMORY_TOTAL_SIZE_TEST:
		  break;	
      case MEMORY_FORMAT_MEMORY_TEST:
	  	/*
		  For code of format memory
		*/		  
		  pRsp->ret_stat_code = TEST_OK_S;
          break;

      default :
          pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
          break;
    }
  }
	#endif
  return pRsp;
 
}
// END : munho.lee@lge.com 2010-11-30

void* LGF_MemoryVolumeCheck(	test_mode_req_type* pReq ,DIAG_TEST_MODE_F_rsp_type	*pRsp)
{

  struct statfs_local  sf;
  unsigned int total = 0;
  unsigned int used = 0;
  unsigned int remained = 0;
  pRsp->ret_stat_code = TEST_OK_S;

  if (sys_statfs("/data", (struct statfs *)&sf) != 0)
  {
    printk(KERN_ERR "[Testmode]can not get sdcard infomation \n");
    pRsp->ret_stat_code = TEST_FAIL_S;
  }
  else
  {

    total = (sf.f_blocks * sf.f_bsize) >> 20;
    remained = (sf.f_bavail * sf.f_bsize) >> 20;
    used = total - remained;

    switch(pReq->mem_capa)
    {
      case MEMORY_TOTAL_CAPA_TEST:
          pRsp->test_mode_rsp.mem_capa = total;
          break;

      case MEMORY_USED_CAPA_TEST:
          pRsp->test_mode_rsp.mem_capa = used;
          break;

      case MEMORY_REMAIN_CAPA_TEST:
          pRsp->test_mode_rsp.mem_capa = remained;
          break;

      default :
          pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
          break;
    }
  }

  return pRsp;

}

void* LGF_TestModeManual(test_mode_req_type* pReq ,DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
  pRsp->ret_stat_code = TEST_OK_S;
  pRsp->test_mode_rsp.manual_test = TRUE;
  return pRsp;
}
extern int db_integrity_ready;
extern int fpri_crc_ready;
extern int file_crc_ready;
extern int db_dump_ready;
extern int db_copy_ready;

typedef struct {
    char ret[32];
} testmode_rsp_from_diag_type;

extern testmode_rsp_from_diag_type integrity_ret;
void* LGF_TestModeDBIntegrityCheck(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    int i;
    unsigned int crc_val;

    memset(integrity_ret.ret, 0, 32);

    if (diagpdev != NULL)
    {
        db_integrity_ready = 0;
        fpri_crc_ready = 0;
        file_crc_ready = 0;
        db_dump_ready = 0;
        db_copy_ready = 0;

        update_diagcmd_state(diagpdev, "DBCHECK", pReq->db_check);

        switch(pReq->db_check)
        {
            case DB_INTEGRITY_CHECK:
                for (i =0; i < 10; i++)
                {
                    if (db_integrity_ready)
                        break;

                    msleep(500);
                }

                msleep(500); // wait until the return value is written to the file

                crc_val = (unsigned int)simple_strtoul(integrity_ret.ret+1,NULL,16);
                sprintf(pRsp->test_mode_rsp.str_buf, "0x%08X", crc_val);

                printk(KERN_INFO "%s\n", integrity_ret.ret);
                printk(KERN_INFO "%d\n", crc_val);
                printk(KERN_INFO "%s\n", pRsp->test_mode_rsp.str_buf);

                pRsp->ret_stat_code = TEST_OK_S;
                break;

            case FPRI_CRC_CHECK:
                for (i =0; i < 10; i++)
                {
                    if (fpri_crc_ready)
                        break;

                    msleep(500);
                }

                msleep(500); // wait until the return value is written to the file

                crc_val = (unsigned int)simple_strtoul(integrity_ret.ret+1,NULL,16);
                sprintf(pRsp->test_mode_rsp.str_buf, "0x%08X", crc_val);

                printk(KERN_INFO "%s\n", integrity_ret.ret);
                printk(KERN_INFO "%d\n", crc_val);
                printk(KERN_INFO "%s\n", pRsp->test_mode_rsp.str_buf);

                pRsp->ret_stat_code = TEST_OK_S;
                break;

            case FILE_CRC_CHECK:
                for (i =0; i < 20; i++)
                {
                    if (file_crc_ready)
                        break;

                    msleep(500);
                }

                msleep(500); // wait until the return value is written to the file

                crc_val = (unsigned int)simple_strtoul(integrity_ret.ret+1,NULL,16);
                sprintf(pRsp->test_mode_rsp.str_buf, "0x%08X", crc_val);

                printk(KERN_INFO "%s\n", integrity_ret.ret);
                printk(KERN_INFO "%d\n", crc_val);
                printk(KERN_INFO "%s\n", pRsp->test_mode_rsp.str_buf);

                pRsp->ret_stat_code = TEST_OK_S;
                break;

            case CODE_PARTITION_CRC_CHECK:
                pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
                break;

            case TOTAL_CRC_CHECK:
                pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
                break;

            case DB_DUMP_CHECK:
                for (i =0; i < 10; i++)
                {
                    if (db_dump_ready)
                        break;

                    msleep(500);
                }

                msleep(500); // wait until the return value is written to the file

                if (integrity_ret.ret[0] == '0')
                    pRsp->ret_stat_code = TEST_OK_S;
                else
                    pRsp->ret_stat_code = TEST_FAIL_S;

                break;

            case DB_COPY_CHECK:
                for (i =0; i < 10; i++)
                {
                    if (db_copy_ready)
                        break;

                    msleep(500);
                }

                msleep(500); // wait until the return value is written to the file

                if (integrity_ret.ret[0] == '0')
                    pRsp->ret_stat_code = TEST_OK_S;
                else
                    pRsp->ret_stat_code = TEST_FAIL_S;

                break;

            default :
                pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
                break;
        }
    }
    else
    {
        printk("\n[%s] error DBCHECK", __func__ );
        pRsp->ret_stat_code = TEST_FAIL_S;
    }

    printk(KERN_ERR "[_DBCHECK_] [%s:%d] DBCHECK Result=<%s>\n", __func__, __LINE__, integrity_ret.ret);

    return pRsp;
}
extern byte fota_id_read[20];
extern int fota_id_check;
void* LGF_TestModeFotaIDCheck(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
	int i;
	
	pRsp->ret_stat_code = TEST_OK_S; // LGE_FOTA_BSP miracle.kim@lge.com temp block for TEST_OK result
    if (diagpdev != NULL)
    {
        switch( pReq->fota_id_check)
        {
            case FOTA_ID_CHECK:
                fota_id_check = 1;
                update_diagcmd_state(diagpdev, "FOTAIDCHECK", 0);
                msleep(500);

                if(fota_id_check == 0)
                {
					printk("[miracle.kim] TEST_OK_S\n");
				    pRsp->ret_stat_code = TEST_OK_S;
                }
				else
				{
                   	printk("[miracle.kim] TEST_FAIL_S\n");
					pRsp->ret_stat_code = TEST_FAIL_S;
				}
                break;

			case FOTA_ID_READ:
                for(i=0; i<19; i++)
                    fota_id_read[i] = 0;

                update_diagcmd_state(diagpdev, "FOTAIDREAD", 0);
                msleep(500);

                for(i=0; i<19; i++)
                    pRsp->test_mode_rsp.fota_id_read[i] = fota_id_read[i];

                printk(KERN_ERR "%s, rsp.read_fota_id : %s\n", __func__, (char *)pRsp->test_mode_rsp.fota_id_read);
                pRsp->ret_stat_code = TEST_OK_S;
                break;

            default:
               	printk("[miracle.kim] TEST_NOT_SUPPORTED_S\n");
				pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
                break;
        }
    }
    else
        pRsp->ret_stat_code = TEST_FAIL_S;

    return pRsp;
}

extern void lm3537_backlight_off(void);
extern void lm3537_backlight_on( int level);

void* LGF_TestModeKEYLOCK(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
	pRsp->ret_stat_code = TEST_OK_S;
    if (diagpdev != NULL)
    {
        switch( pReq->req_key_lock)
        {
            case KEY_LOCK_REQ:				
				pRsp->ret_stat_code = TEST_OK_S;
				printk("[Testmode KEY_LOCK] key lock on\n");
				lgf_key_lock =0x55;
				lm3537_backlight_off();				
				break;
			case KEY_UNLOCK_REQ:
				pRsp->ret_stat_code = TEST_OK_S;
				printk("[Testmode KEY_LOCK] key lock off\n");
				lgf_key_lock =0;
				lm3537_backlight_on(55); //level 55 fix...	
				mdelay(50);
				break;
			default:
				printk("[Testmode KEY_LOCK]not support\n");
				pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
                break;				
        }
    }
	else
        pRsp->ret_stat_code = TEST_FAIL_S;
	
    return pRsp;
}

// LGE_CHANGE_S, bill.jung@lge.com, 20110808, WiFi MAC R/W Function by DIAG
void* LGF_TestModeWiFiMACRW(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
	int fd=0; 
	int i=0;
    char *src = (void *)0;	
    mm_segment_t old_fs=get_fs();
    set_fs(get_ds());

	printk(KERN_ERR "[LGF_TestModeWiFiMACRW] req_type=%d, wifi_mac_addr=[%s]\n", pReq->wifi_mac_ad.req_type, pReq->wifi_mac_ad.wifi_mac_addr);

	if (diagpdev != NULL)
	{
		if( pReq->wifi_mac_ad.req_type == 0 )
		{
			printk(KERN_ERR "[LGF_TestModeWiFiMACRW] WIFI_MAC_ADDRESS_WRITE.\n");
			
			if ( (fd = sys_open((const char __user *) "/data/misc/wifi/diag_mac", O_CREAT | O_RDWR, 0777) ) < 0 )
		    {
		    	printk(KERN_ERR "[LGF_TestModeWiFiMACRW] Can not open file.\n");
				pRsp->ret_stat_code = TEST_FAIL_S;
				goto file_fail;
		    }
				
			if ( (src = kmalloc(20, GFP_KERNEL)) )
			{
				sprintf( src,"%c%c%c%c%c%c%c%c%c%c%c%c", pReq->wifi_mac_ad.wifi_mac_addr[0],
					pReq->wifi_mac_ad.wifi_mac_addr[1], pReq->wifi_mac_ad.wifi_mac_addr[2],
					pReq->wifi_mac_ad.wifi_mac_addr[3], pReq->wifi_mac_ad.wifi_mac_addr[4],
					pReq->wifi_mac_ad.wifi_mac_addr[5], pReq->wifi_mac_ad.wifi_mac_addr[6],
					pReq->wifi_mac_ad.wifi_mac_addr[7], pReq->wifi_mac_ad.wifi_mac_addr[8],
					pReq->wifi_mac_ad.wifi_mac_addr[9], pReq->wifi_mac_ad.wifi_mac_addr[10],
					pReq->wifi_mac_ad.wifi_mac_addr[11]
					);
					
				if ((sys_write(fd, (const char __user *) src, 12)) < 0)
				{
					printk(KERN_ERR "[LGF_TestModeWiFiMACRW] Can not write file.\n");
					pRsp->ret_stat_code = TEST_FAIL_S;
					goto file_fail;
				}
			}

			for( i=0; i< 5; i++ )
			{
			msleep(500);
			}
				
			update_diagcmd_state(diagpdev, "WIFIMACWRITE", 0);
				
			pRsp->ret_stat_code = TEST_OK_S;

		}
		else if(  pReq->wifi_mac_ad.req_type == 1 )
		{
			printk(KERN_ERR "[LGF_TestModeWiFiMACRW] WIFI_MAC_ADDRESS_READ.\n");
			
			update_diagcmd_state(diagpdev, "WIFIMACREAD", 0);

			for( i=0; i< 10; i++ )
			{
				msleep(500);
			}					

			if ( (fd = sys_open((const char __user *) "/data/misc/wifi/diag_mac", O_CREAT | O_RDWR, 0777) ) < 0 )
		    {
		    	printk(KERN_ERR "[LGF_TestModeWiFiMACRW] Can not open file.\n");
				pRsp->ret_stat_code = TEST_FAIL_S;
				goto file_fail;
		    }
			
			if ( (src = kmalloc(20, GFP_KERNEL)) )
			{
				if ((sys_read(fd, (char __user *) src, 12)) < 0)
				{
					printk(KERN_ERR "[LGF_TestModeWiFiMACRW] Can not read file.\n");
					pRsp->ret_stat_code = TEST_FAIL_S;
					goto file_fail;
				}
			}

			for( i=0; i<14; i++)
			{
				pRsp->test_mode_rsp.key_pressed_buf[i] = 0;
			}

			for( i=0; i< 12; i++ )
			{
				pRsp->test_mode_rsp.read_wifi_mac_addr[i] = src[i];
			}

			sys_unlink((const char __user *)"/data/misc/wifi/diag_mac");
					
			pRsp->ret_stat_code = TEST_OK_S;
		}				
		else
		{
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
		}
	}
	else
	{
		pRsp->ret_stat_code = TEST_FAIL_S;
	}

file_fail:
	kfree(src);
	
	sys_close(fd);
	set_fs(old_fs); 
	memset(pReq, 0, 128); 
	return pRsp;
}

// LGE_CHANGE_E, bill.jung@lge.com, 20110808, WiFi MAC R/W Function by DIAG


//BEGIN hongkil.kim 20110907 for... reset... android side... prefernce..... call ui.....
void LGF_TestModeFactoryResetAndroidPrefence(void)
{
	if (diagpdev != NULL){
		update_diagcmd_state(diagpdev, "FRSTPREFERENCE", 0);
	}
	else
	{
		printk("\n[%s] error, diagpdev is null!! ", __func__ );
	}
}
//END hongkil.kim 20110907 for... reset... android side... prefernce..... call ui.....
static int test_mode_disable_input_devices = 0;
void LGF_TestModeSetDisableInputDevices(int value)
{
    test_mode_disable_input_devices = value;
}
int LGF_TestModeGetDisableInputDevices(void)
{
    return test_mode_disable_input_devices;
}
EXPORT_SYMBOL(LGF_TestModeGetDisableInputDevices);

#ifndef SKW_TEST
static unsigned char test_mode_factory_reset_status = FACTORY_RESET_START;
#define BUF_PAGE_SIZE 2048
// BEGIN: 0010090 sehyuny.kim@lge.com 2010-10-21
// MOD 0010090: [FactoryReset] Enable Recovery mode FactoryReset

#define FACTORY_RESET_STR       "FACT_RESET_"
#define FACTORY_RESET_STR_SIZE	11
#define FACTORY_RESET_BLK 1 // read / write on the first block

#define MSLEEP_CNT 100

typedef struct MmcPartition MmcPartition;

struct MmcPartition {
    char *device_index;
    char *filesystem;
    char *name;
    unsigned dstatus;
    unsigned dtype ;
    unsigned dfirstsec;
    unsigned dsize;
};


extern int lge_write_block(int secnum, unsigned char *buf, size_t size);
extern int lge_read_block(int secnum, unsigned char *buf, size_t size);
extern int lge_mmc_scan_partitions(void);
extern const MmcPartition *lge_mmc_find_partition_by_name(const char *name);

// END: 0010090 sehyuny.kim@lge.com 2010-10-21
#endif
extern const MmcPartition *lge_mmc_find_partition_by_name(const char *name);


void* LGF_TestModeFactoryReset(
		test_mode_req_type* pReq ,
		DIAG_TEST_MODE_F_rsp_type	*pRsp)
{
 
  unsigned char pbuf[50]; //no need to have huge size, this is only for the flag
  const MmcPartition *pMisc_part; 
  unsigned char startStatus = FACTORY_RESET_NA; 
  int mtd_op_result = 0;
  unsigned long factoryreset_bytes_pos_in_emmc = 0;
/* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
/* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
  DIAG_TEST_MODE_F_req_type req_ptr;

  req_ptr.sub_cmd_code = TEST_MODE_FACTORY_RESET_CHECK_TEST;
  req_ptr.test_mode_req.factory_reset = pReq->factory_reset;
/* END: 0014656 jihoon.lee@lge.com 2011024 */
  
/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
  pRsp->ret_stat_code = TEST_FAIL_S;
/* END: 0014110 jihoon.lee@lge.com 20110115 */
  
  lge_mmc_scan_partitions();
  pMisc_part = lge_mmc_find_partition_by_name("misc");
  factoryreset_bytes_pos_in_emmc = (pMisc_part->dfirstsec*512)+PTN_FRST_PERSIST_POSITION_IN_MISC_PARTITION;
  
  printk("LGF_TestModeFactoryReset> mmc info sec : 0x%x, size : 0x%x type : 0x%x frst sec: 0x%lx\n", pMisc_part->dfirstsec, pMisc_part->dsize, pMisc_part->dtype, factoryreset_bytes_pos_in_emmc);

/* BEGIN: 0013861 jihoon.lee@lge.com 20110111 */
/* MOD 0013861: [FACTORY RESET] emmc_direct_access factory reset flag access */
/* add carriage return and change flag size for the platform access */
/* END: 0013861 jihoon.lee@lge.com 20110111 */
  switch(pReq->factory_reset)
  {
    case FACTORY_RESET_CHECK :
#if 1  // def CONFIG_LGE_MTD_DIRECT_ACCESS
/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
      memset((void*)pbuf, 0, sizeof(pbuf));
      mtd_op_result = lge_read_block(factoryreset_bytes_pos_in_emmc, pbuf, FACTORY_RESET_STR_SIZE+2);

      if( mtd_op_result != (FACTORY_RESET_STR_SIZE+2) )
      {
        printk(KERN_ERR "[Testmode]lge_read_block, read data  = %d \n", mtd_op_result);
        pRsp->ret_stat_code = TEST_FAIL_S;
        break;
      }
      else
      {
        //printk(KERN_INFO "\n[Testmode]factory reset memcmp\n");
        if(memcmp(pbuf, FACTORY_RESET_STR, FACTORY_RESET_STR_SIZE) == 0) // tag read sucess
        {
          startStatus = pbuf[FACTORY_RESET_STR_SIZE] - '0';
          printk(KERN_INFO "[Testmode]factory reset backup status = %d \n", startStatus);
        }
        else
        {
          // if the flag storage is erased this will be called, start from the initial state
          printk(KERN_ERR "[Testmode] tag read failed :  %s \n", pbuf);
        }
      }  
/* END: 0014110 jihoon.lee@lge.com 20110115 */

      test_mode_factory_reset_status = FACTORY_RESET_INITIAL;
      memset((void *)pbuf, 0, sizeof(pbuf));
      sprintf(pbuf, "%s%d\n",FACTORY_RESET_STR, test_mode_factory_reset_status);
      printk(KERN_INFO "[Testmode]factory reset status = %d\n", test_mode_factory_reset_status);

      mtd_op_result = lge_erase_block(factoryreset_bytes_pos_in_emmc, FACTORY_RESET_STR_SIZE+2);	
/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
      if(mtd_op_result!= (FACTORY_RESET_STR_SIZE+2))
      {
        printk(KERN_ERR "[Testmode]lge_erase_block, error num = %d \n", mtd_op_result);
        pRsp->ret_stat_code = TEST_FAIL_S;
        break;
      }
      else
      {
        mtd_op_result = lge_write_block(factoryreset_bytes_pos_in_emmc, pbuf, FACTORY_RESET_STR_SIZE+2);
        if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
        {
          printk(KERN_ERR "[Testmode]lge_write_block, error num = %d \n", mtd_op_result);
          pRsp->ret_stat_code = TEST_FAIL_S;
          break;
        }
      }
/* END: 0014110 jihoon.lee@lge.com 20110115 */

/* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
/* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
      //send_to_arm9((void*)(((byte*)pReq) -sizeof(diagpkt_header_type) - sizeof(word)) , pRsp);
      send_to_arm9((void*)&req_ptr, (void*)pRsp);
/* END: 0014656 jihoon.lee@lge.com 2011024 */

/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
      if(pRsp->ret_stat_code != TEST_OK_S)
      {
        printk(KERN_ERR "[Testmode]send_to_arm9 response : %d\n", pRsp->ret_stat_code);
        pRsp->ret_stat_code = TEST_FAIL_S;
        break;
      }
/* END: 0014110 jihoon.lee@lge.com 20110115 */

      /*LG_FW khlee 2010.03.04 -If we start at 5, we have to go to APP reset state(3) directly */
      if((startStatus == FACTORY_RESET_COLD_BOOT_END) || (startStatus == FACTORY_RESET_HOME_SCREEN_END))
        test_mode_factory_reset_status = FACTORY_RESET_COLD_BOOT_START;
      else
        test_mode_factory_reset_status = FACTORY_RESET_ARM9_END;

      memset((void *)pbuf, 0, sizeof(pbuf));
      sprintf(pbuf, "%s%d\n",FACTORY_RESET_STR, test_mode_factory_reset_status);
      printk(KERN_INFO "[Testmode]factory reset status = %d\n", test_mode_factory_reset_status);

      mtd_op_result = lge_erase_block(factoryreset_bytes_pos_in_emmc, FACTORY_RESET_STR_SIZE+2);
/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
      if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
      {
        printk(KERN_ERR "[Testmode]lge_erase_block, error num = %d \n", mtd_op_result);
        pRsp->ret_stat_code = TEST_FAIL_S;
        break;
      }
      else
      {
         mtd_op_result = lge_write_block(factoryreset_bytes_pos_in_emmc, pbuf, FACTORY_RESET_STR_SIZE+2);
         if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
         {
          printk(KERN_ERR "[Testmode]lge_write_block, error num = %d \n", mtd_op_result);
          pRsp->ret_stat_code = TEST_FAIL_S;
          break;
         }
      }
/* END: 0014110 jihoon.lee@lge.com 20110115 */

#else /**/
      //send_to_arm9((void*)(((byte*)pReq) -sizeof(diagpkt_header_type) - sizeof(word)) , pRsp);
      send_to_arm9((void*)&req_ptr, (void*)pRsp);
#endif /*CONFIG_LGE_MTD_DIRECT_ACCESS*/

      if((startStatus == FACTORY_RESET_COLD_BOOT_END) || (startStatus == FACTORY_RESET_HOME_SCREEN_END))
      {
        if (diagpdev != NULL)
          update_diagcmd_state(diagpdev, "REBOOT", 0);
        else
        {
          printk(KERN_INFO "%s, factory reset reboot failed \n", __func__);
          pRsp->ret_stat_code = TEST_FAIL_S;
          break;
        }
      }

      printk(KERN_INFO "%s, factory reset check completed \n", __func__);
      pRsp->ret_stat_code = TEST_OK_S;

//BEGIN hongkil.kim 20110907 for... reset... android side... prefernce..... call ui.....
      LGF_TestModeFactoryResetAndroidPrefence();
//END hongkil.kim 20110907 for... reset... android side... prefernce..... call ui.....
      
      break;

    case FACTORY_RESET_COMPLETE_CHECK:

	 send_to_arm9((void*)&req_ptr, (void*)pRsp);
      if(pRsp->ret_stat_code != TEST_OK_S)
      {
        printk(KERN_ERR "[Testmode]send_to_arm9 response : %d\n", pRsp->ret_stat_code);
        pRsp->ret_stat_code = TEST_FAIL_S;
        break;
      }

       break;

    case FACTORY_RESET_STATUS_CHECK:
#if 1 // def CONFIG_LGE_MTD_DIRECT_ACCESS
      memset((void*)pbuf, 0, sizeof(pbuf));
      mtd_op_result = lge_read_block(factoryreset_bytes_pos_in_emmc, pbuf, FACTORY_RESET_STR_SIZE+2 );
/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
      if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
      {
      	 printk(KERN_ERR "[Testmode]lge_read_block, error num = %d \n", mtd_op_result);
      	 pRsp->ret_stat_code = TEST_FAIL_S;
      	 break;
      }
      else
      {
      	 if(memcmp(pbuf, FACTORY_RESET_STR, FACTORY_RESET_STR_SIZE) == 0) // tag read sucess
      	 {
      	   test_mode_factory_reset_status = pbuf[FACTORY_RESET_STR_SIZE] - '0';
      	   printk(KERN_INFO "[Testmode]factory reset status = %d \n", test_mode_factory_reset_status);
      	   pRsp->ret_stat_code = test_mode_factory_reset_status;
      	 }
      	 else
      	 {
      	   printk(KERN_ERR "[Testmode]factory reset tag fail, set initial state\n");
      	   test_mode_factory_reset_status = FACTORY_RESET_START;
      	   pRsp->ret_stat_code = test_mode_factory_reset_status;
      	   break;
      	 }
      }  
/* END: 0014110 jihoon.lee@lge.com 20110115 */
#endif /*CONFIG_LGE_MTD_DIRECT_ACCESS*/

      break;

    case FACTORY_RESET_COLD_BOOT:
// remove requesting sync to CP as all sync will be guaranteed on their own.

#if 1 // def CONFIG_LGE_MTD_DIRECT_ACCESS
      test_mode_factory_reset_status = FACTORY_RESET_COLD_BOOT_START;
      memset((void *)pbuf, 0, sizeof(pbuf));
      sprintf(pbuf, "%s%d",FACTORY_RESET_STR, test_mode_factory_reset_status);
      printk(KERN_INFO "[Testmode]factory reset status = %d\n", test_mode_factory_reset_status);
      mtd_op_result = lge_erase_block(factoryreset_bytes_pos_in_emmc,  FACTORY_RESET_STR_SIZE+2);
/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
      if(mtd_op_result!=( FACTORY_RESET_STR_SIZE+2))
      {
        printk(KERN_ERR "[Testmode]lge_erase_block, error num = %d \n", mtd_op_result);
        pRsp->ret_stat_code = TEST_FAIL_S;
        break;
      }
      else
      {
        mtd_op_result = lge_write_block(factoryreset_bytes_pos_in_emmc, pbuf,  FACTORY_RESET_STR_SIZE+2);
        if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
        {
          printk(KERN_ERR "[Testmode]lge_write_block, error num = %d \n", mtd_op_result);
          pRsp->ret_stat_code = TEST_FAIL_S;
        }
      }
/* END: 0014110 jihoon.lee@lge.com 20110115 */
#endif /*CONFIG_LGE_MTD_DIRECT_ACCESS*/
      pRsp->ret_stat_code = TEST_OK_S;
      break;

    case FACTORY_RESET_ERASE_USERDATA:
#if 1 // def CONFIG_LGE_MTD_DIRECT_ACCESS
      test_mode_factory_reset_status = FACTORY_RESET_COLD_BOOT_START;
      memset((void *)pbuf, 0, sizeof(pbuf));
      sprintf(pbuf, "%s%d",FACTORY_RESET_STR, test_mode_factory_reset_status);
      printk(KERN_INFO "[Testmode-erase userdata]factory reset status = %d\n", test_mode_factory_reset_status);
      mtd_op_result = lge_erase_block(factoryreset_bytes_pos_in_emmc , FACTORY_RESET_STR_SIZE+2);
/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
      if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
      {
        printk(KERN_ERR "[Testmode]lge_erase_block, error num = %d \n", mtd_op_result);
        pRsp->ret_stat_code = TEST_FAIL_S;
        break;
      }
      else
      {
        mtd_op_result = lge_write_block(factoryreset_bytes_pos_in_emmc, pbuf, FACTORY_RESET_STR_SIZE+2);
        if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
        {
          printk(KERN_ERR "[Testmode]lge_write_block, error num = %d \n", mtd_op_result);
          pRsp->ret_stat_code = TEST_FAIL_S;
          break;
        }
      }
/* END: 0014110 jihoon.lee@lge.com 20110115 */
#endif /*CONFIG_LGE_MTD_DIRECT_ACCESS*/
    pRsp->ret_stat_code = TEST_OK_S;
    break;
	

//   added New diag command  beacause  they want to skip facory reset when it was a factory download,
//   [250-50-4]
	case FACTORY_RESET_FORCE_CHANGE_STATUS: 

      test_mode_factory_reset_status = FACTORY_RESET_COLD_BOOT_END;
      memset((void *)pbuf, 0, sizeof(pbuf));
      sprintf(pbuf, "%s%d",FACTORY_RESET_STR, test_mode_factory_reset_status);
      printk(KERN_INFO "[Testmode-force_change]factory reset status = %d\n", test_mode_factory_reset_status);

      mtd_op_result = lge_erase_block(factoryreset_bytes_pos_in_emmc , FACTORY_RESET_STR_SIZE+2);
      if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
      {
        printk(KERN_ERR "[Testmode]lge_erase_block, error num = %d \n", mtd_op_result);
        pRsp->ret_stat_code = TEST_FAIL_S;
        break;
      }
      else
      {
        mtd_op_result = lge_write_block(factoryreset_bytes_pos_in_emmc, pbuf, FACTORY_RESET_STR_SIZE+2);
        if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+2))
        {
          printk(KERN_ERR "[Testmode]lge_write_block, error num = %d \n", mtd_op_result);
          pRsp->ret_stat_code = TEST_FAIL_S;
          break;
        }
      }
   	 pRsp->ret_stat_code = TEST_OK_S;
    	break;
		
     default:
        pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
        break;
    }
  return pRsp;

}


//HELLG ........ is this is my job????????????? 
    void* LGF_TestModeResetProduction(
            test_mode_req_type* pReq ,
            DIAG_TEST_MODE_F_rsp_type   *pRsp)
    {
     
    /* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
    /* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
      DIAG_TEST_MODE_F_req_type req_ptr;
    
      req_ptr.sub_cmd_code = TEST_MODE_RESET_PRODUCTION;
      pRsp->ret_stat_code = TEST_OK_S;         
//      req_ptr.test_mode_req.factory_reset = pReq->factory_reset;
    /* END: 0014656 jihoon.lee@lge.com 2011024 */

      printk("==============================================================\n");
      printk("LGF_TestModeResetProduction      sub command is %d\n", pReq->resetproduction_sub2);
      printk("LGF_TestModeResetProduction      req_ptr.sub_cmd_code is %d\n", req_ptr.sub_cmd_code );      
      printk("LGF_TestModeResetProduction      pRsp->sub_cmd_code is %d\n", pRsp->sub_cmd_code );            
      printk("==============================================================\n");


      if(pReq->resetproduction_sub2 == 1)
      {
        req_ptr.test_mode_req.resetproduction_sub2 = 1;
        send_to_arm9((void*)&req_ptr, (void*)pRsp);
      }
      else
      {
        req_ptr.test_mode_req.resetproduction_sub2 = 0;      
        send_to_arm9((void*)&req_ptr, (void*)pRsp);
      }

      printk("==============================================================\n");
      printk("LGF_TestModeResetProduction      pRsp->ret_stat_code  is %d\n", pRsp->ret_stat_code );
      printk("LGF_TestModeResetProduction      req_ptr.sub_cmd_code is %d\n", req_ptr.sub_cmd_code );            
      printk("LGF_TestModeResetProduction      pRsp->sub_cmd_code is %d\n", pRsp->sub_cmd_code );                  
      printk("==============================================================\n");

      if(pRsp->ret_stat_code != TEST_OK_S)      
        pRsp->ret_stat_code = TEST_FAIL_S;   
      
      return pRsp;
    
    }


void* LGF_TestModeVirtualSimTest( test_mode_req_type* pReq,  DIAG_TEST_MODE_F_rsp_type	*pRsp )
{
	DIAG_TEST_MODE_F_req_type req_ptr; 

	printk("\n[%s] First LteCallDetach", __func__ );
#if 0
	if(pReq->lte_virtual_sim == 21)
	{
		printk("\n[%s] Second LteCallDetach", __func__ );
		pRsp->ret_stat_code = TEST_OK_S;
		
		if (diagpdev != NULL){
			update_diagcmd_state(diagpdev, "LTECALLDETACH", pReq->lte_virtual_sim);
		}
		else
		{
			printk("\n[%s] error LteCallDetach", __func__ );
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
		}
		return pRsp;
	}
#endif
	req_ptr.sub_cmd_code = 44;
	req_ptr.test_mode_req.lte_virtual_sim = pReq->lte_virtual_sim;
	printk(KERN_INFO "%s, pReq->lte_virtual_sim : %d\n", __func__, pReq->lte_virtual_sim);

	send_to_arm9((void*)&req_ptr, (void*)pRsp);
	printk(KERN_INFO "%s, pRsp->ret_stat_code : %d\n", __func__, pRsp->ret_stat_code);

#if 0
	DIAG_TEST_MODE_F_req_type req_ptr;

	printk("[VSIM_kernel] LGF_TestModeVirtualSimTest() is called. "); // Metro VSIM

      pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;

	switch(pReq->lte_virtual_sim)
	{
		case VIRTUAL_SIM_ON:
			send_to_arm9((void*)&req_ptr, (void*)pRsp);
			break;

		case VIRTUAL_SIM_OFF:
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
			break;
		case VIRTUAL_SIM_STATUS:
			pRsp->ret_stat_code = TEST_OK_S;
			break;
	}
#endif
	 return pRsp;
}


//HELLG ........ is this is my job????????????? 
    
        void* LGF_TestModeIrdaFmrtFingerUIMTest(
                test_mode_req_type* pReq ,
                DIAG_TEST_MODE_F_rsp_type   *pRsp)
        {
         
        /* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
        /* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
          DIAG_TEST_MODE_F_req_type req_ptr;
        
          req_ptr.sub_cmd_code = TEST_MODE_IRDA_FMRT_FINGER_UIM_TEST;
          pRsp->ret_stat_code = TEST_OK_S;         
          pRsp->test_mode_rsp.uim_state2 = 0;
//          return pRsp;          
    //      req_ptr.test_mode_req.factory_reset = pReq->factory_reset;
        /* END: 0014656 jihoon.lee@lge.com 2011024 */
    
          printk("==============================================================\n");
          printk("LGF_TestModeResetProduction      sub command is %d\n", pReq->resetproduction_sub2);
          printk("LGF_TestModeResetProduction      req_ptr.sub_cmd_code is %d\n", req_ptr.sub_cmd_code );      
          printk("LGF_TestModeResetProduction      pRsp->sub_cmd_code is %d\n", pRsp->sub_cmd_code );            
          printk("LGF_TestModeResetProduction      pReq->irdafmrtfingerUIM_sub2 is %d\n", pReq->irdafmrtfingerUIM_sub2 );                      
          printk("==============================================================\n");
    
    
          if(pReq->irdafmrtfingerUIM_sub2 == 5)
          {
            req_ptr.test_mode_req.irdafmrtfingerUIM_sub2 = 5;
            send_to_arm9((void*)&req_ptr, (void*)pRsp);

            printk("==============================================================\n");
            printk("LGF_TestModeResetProduction      pRsp->ret_stat_code  is %d\n", pRsp->ret_stat_code );
            printk("LGF_TestModeResetProduction      req_ptr.sub_cmd_code is %d\n", req_ptr.sub_cmd_code );            
            printk("LGF_TestModeResetProduction      pRsp->sub_cmd_code is %d\n", pRsp->sub_cmd_code );              
            printk("LGF_TestModeResetProduction      pReq->irdafmrtfingerUIM_sub2 is %d\n", pReq->irdafmrtfingerUIM_sub2 );                                
            printk("LGF_TestModeResetProduction      pRsp->test_mode_rsp.uim_state is %d\n", pRsp->test_mode_rsp.uim_state2);          
            printk("==============================================================\n");


            if(pRsp->ret_stat_code == TEST_FAIL_S)      
            {
              pRsp->ret_stat_code = TEST_OK_S;   
              pRsp->test_mode_rsp.uim_state2 = 1;              
            }
            else if(pRsp->ret_stat_code == TEST_OK_S)      
            {
                pRsp->test_mode_rsp.uim_state2 = 0;
            }
            else
            {
                pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;                         
                pRsp->test_mode_rsp.uim_state2 = 1;            
            }
              
          }
          else
          {
            pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;             
          }
    
          printk("==============================================================\n");
          printk("LGF_TestModeResetProduction      pRsp->ret_stat_code  is %d\n", pRsp->ret_stat_code );
          printk("LGF_TestModeResetProduction      req_ptr.sub_cmd_code is %d\n", req_ptr.sub_cmd_code );            
          printk("LGF_TestModeResetProduction      pRsp->sub_cmd_code is %d\n", pRsp->sub_cmd_code );              
          printk("LGF_TestModeResetProduction      pReq->irdafmrtfingerUIM_sub2 is %d\n", pReq->irdafmrtfingerUIM_sub2 );                                
          printk("LGF_TestModeResetProduction      pRsp->test_mode_rsp.uim_state is %d\n", pRsp->test_mode_rsp.uim_state2);          
          printk("==============================================================\n");
    
          
          return pRsp;
        
        }



void* LGF_TestScriptItemSet(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
#if 1
/* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
/* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
  DIAG_TEST_MODE_F_req_type req_ptr;
  int mtd_op_result = 0;
  const MmcPartition *pMisc_part; 
  unsigned long factoryreset_bytes_pos_in_emmc = 0; 
//jaeo.park@lge.com [[
  udbp_req_type udbReqType;
  memset(&udbReqType,0x0,sizeof(udbp_req_type));
//]]
  

  req_ptr.sub_cmd_code = TEST_MODE_TEST_SCRIPT_MODE;
  req_ptr.test_mode_req.test_mode_test_scr_mode = pReq->test_mode_test_scr_mode;
/* END: 0014656 jihoon.lee@lge.com 2011024 */

  lge_mmc_scan_partitions();
  pMisc_part = lge_mmc_find_partition_by_name("misc");
  factoryreset_bytes_pos_in_emmc = (pMisc_part->dfirstsec*512)+PTN_FRST_PERSIST_POSITION_IN_MISC_PARTITION;
//	printk("LGF_TestScriptItemSet> mmc info sec : 0x%x, size : 0x%x type : 0x%x frst sec: 0x%lx\n", pMisc_part->dfirstsec, pMisc_part->dsize, pMisc_part->dtype, factoryreset_bytes_pos_in_emmc);

  switch(pReq->test_mode_test_scr_mode)
  {
	case TEST_SCRIPT_ITEM_SET:
	mtd_op_result = lge_erase_block(factoryreset_bytes_pos_in_emmc, (FACTORY_RESET_STR_SIZE+1) );	
	if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+1))
	  {
		 printk(KERN_ERR "[Testmode]lge_erase_block, error num = %d \n", mtd_op_result);
		 pRsp->ret_stat_code = TEST_FAIL_S;
		 break;
	 }
		 
/* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
/* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
		 //send_to_arm9((void*)(((byte*)pReq) -sizeof(diagpkt_header_type) - sizeof(word)) , pRsp);
		 send_to_arm9((void*)&req_ptr, (void*)pRsp);
		printk(KERN_INFO "%s, result : %s\n", __func__, pRsp->ret_stat_code==TEST_OK_S?"OK":"FALSE");
/* END: 0014656 jihoon.lee@lge.com 2011024 */
	  break;

//jaeo.park@lge.com for SRD cal backup
	case CAL_DATA_BACKUP:
		udbReqType.header.sub_cmd = SRD_INIT_OPERATION;
		LGE_Dload_SRD((udbp_req_type *)&udbReqType,sizeof(udbReqType));//SRD_INIT_OPERATION
		udbReqType.header.sub_cmd = USERDATA_BACKUP_REQUEST;
		LGE_Dload_SRD((udbp_req_type *)&udbReqType,sizeof(udbReqType));//USERDATA_BACKUP_REQUEST
//		printk(KERN_INFO "%s,backup_nv_counter %d\n", __func__,userDataBackUpInfo.info.srd_backup_nv_counter);
		udbReqType.header.sub_cmd = USERDATA_BACKUP_REQUEST_MDM;
		LGE_Dload_SRD((udbp_req_type *)&udbReqType,sizeof(udbReqType));//USERDATA_BACKUP_REQUEST_MDM
//		printk(KERN_INFO "%s,backup_nv_counter %d\n", __func__,userDataBackUpInfo.info.srd_backup_nv_counter);
		break;
	
	case CAL_DATA_RESTORE:
		send_to_arm9((void*)&req_ptr, (void*)pRsp);
		printk(KERN_INFO "%s, result : %s\n", __func__, pRsp->ret_stat_code==TEST_OK_S?"OK":"FALSE");
		break;
/*
	case CAL_DATA_ERASE:
	case CAL_DATA_INFO:
		diagpkt_free(pRsp);
		return 0;			
		break;
  */			
	default:
/* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
/* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
	  //send_to_arm9((void*)(((byte*)pReq) -sizeof(diagpkt_header_type) - sizeof(word)) , pRsp);
	  send_to_arm9((void*)&req_ptr, (void*)pRsp);
	  printk(KERN_INFO "%s, cmd : %d, result : %s\n", __func__, pReq->test_mode_test_scr_mode, \
											pRsp->ret_stat_code==TEST_OK_S?"OK":"FALSE");
	  if(pReq->test_mode_test_scr_mode == TEST_SCRIPT_MODE_CHECK)
	  {
		switch(pRsp->test_mode_rsp.test_mode_test_scr_mode)
		{
		  case 0:
			printk(KERN_INFO "%s, mode : %s\n", __func__, "USER SCRIPT");
			break;
		  case 1:
			printk(KERN_INFO "%s, mode : %s\n", __func__, "TEST SCRIPT");
			break;
		  default:
			printk(KERN_INFO "%s, mode : %s, returned %d\n", __func__, "NO PRL", pRsp->test_mode_rsp.test_mode_test_scr_mode);
			break;
		}
	  }
/* END: 0014656 jihoon.lee@lge.com 2011024 */
	  break;

  }  
		

// END: 0009720 sehyuny.kim@lge.com 2010-10-06

#else
// BEGIN: 0009720 sehyuny.kim@lge.com 2010-10-06
// MOD 0009720: [Modem] It add RF X-Backup feature
  int mtd_op_result = 0;

  const MmcPartition *pMisc_part; 
  unsigned long factoryreset_bytes_pos_in_emmc = 0;
/* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
/* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
  DIAG_TEST_MODE_F_req_type req_ptr;

  req_ptr.sub_cmd_code = TEST_MODE_TEST_SCRIPT_MODE;
  req_ptr.test_mode_req.test_mode_test_scr_mode = pReq->test_mode_test_scr_mode;
/* END: 0014656 jihoon.lee@lge.com 2011024 */

  lge_mmc_scan_partitions();
  pMisc_part = lge_mmc_find_partition_by_name("misc");
  factoryreset_bytes_pos_in_emmc = (pMisc_part->dfirstsec*512)+PTN_FRST_PERSIST_POSITION_IN_MISC_PARTITION;

  printk("LGF_TestScriptItemSet> mmc info sec : 0x%x, size : 0x%x type : 0x%x frst sec: 0x%lx\n", pMisc_part->dfirstsec, pMisc_part->dsize, pMisc_part->dtype, factoryreset_bytes_pos_in_emmc);

  switch(pReq->test_mode_test_scr_mode)
  {
	case TEST_SCRIPT_ITEM_SET:
#if 1 // def CONFIG_LGE_MTD_DIRECT_ACCESS
	  mtd_op_result = lge_erase_block(factoryreset_bytes_pos_in_emmc, (FACTORY_RESET_STR_SIZE+1) );
/* BEGIN: 0014110 jihoon.lee@lge.com 20110115 */
/* MOD 0014110: [FACTORY RESET] stability */
/* handle operation or rpc failure as well */
	  if(mtd_op_result!=(FACTORY_RESET_STR_SIZE+1))
	  {
		 printk(KERN_ERR "[Testmode]lge_erase_block, error num = %d \n", mtd_op_result);
		 pRsp->ret_stat_code = TEST_FAIL_S;
		 break;
/* END: 0014110 jihoon.lee@lge.com 20110115 */
	  } else
#endif /*CONFIG_LGE_MTD_DIRECT_ACCESS*/
	  // LG_FW khlee 2010.03.16 - They want to ACL on state in test script state.
	  {
		 update_diagcmd_state(diagpdev, "ALC", 1);
/* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
/* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
		 //send_to_arm9((void*)(((byte*)pReq) -sizeof(diagpkt_header_type) - sizeof(word)) , pRsp);
		 send_to_arm9((void*)&req_ptr, (void*)pRsp);
		printk(KERN_INFO "%s, result : %s\n", __func__, pRsp->ret_stat_code==TEST_OK_S?"OK":"FALSE");
/* END: 0014656 jihoon.lee@lge.com 2011024 */
	  }
	  break;
  /*			
	case CAL_DATA_BACKUP:
	case CAL_DATA_RESTORE:
	case CAL_DATA_ERASE:
	case CAL_DATA_INFO:
		diagpkt_free(pRsp);
		return 0;			
		break;
  */			
	default:
/* BEGIN: 0014656 jihoon.lee@lge.com 20110124 */
/* MOD 0014656: [LG RAPI] OEM RAPI PACKET MISMATCH KERNEL CRASH FIX */
	  //send_to_arm9((void*)(((byte*)pReq) -sizeof(diagpkt_header_type) - sizeof(word)) , pRsp);
	  send_to_arm9((void*)&req_ptr, (void*)pRsp);
	  printk(KERN_INFO "%s, cmd : %d, result : %s\n", __func__, pReq->test_mode_test_scr_mode, \
											pRsp->ret_stat_code==TEST_OK_S?"OK":"FALSE");
	  if(pReq->test_mode_test_scr_mode == TEST_SCRIPT_MODE_CHECK)
	  {
		switch(pRsp->test_mode_rsp.test_mode_test_scr_mode)
		{
		  case 0:
			printk(KERN_INFO "%s, mode : %s\n", __func__, "USER SCRIPT");
			break;
		  case 1:
			printk(KERN_INFO "%s, mode : %s\n", __func__, "TEST SCRIPT");
			break;
		  default:
			printk(KERN_INFO "%s, mode : %s, returned %d\n", __func__, "NO PRL", pRsp->test_mode_rsp.test_mode_test_scr_mode);
			break;
		}
	  }
/* END: 0014656 jihoon.lee@lge.com 2011024 */
	  break;

  }  
// END: 0009720 sehyuny.kim@lge.com 2010-10-06
#endif 
  return pRsp;

}



// BEGIN: daegeun.yoon@lge.com 2011-08-15
// MOD: #if 0 because duplicatation
#if 0
void* LGF_TestModeDBIntegrityCheck(    test_mode_req_type* pReq ,DIAG_TEST_MODE_F_rsp_type	   *pRsp)
{

	printk(KERN_ERR "[_DBCHECK_] [%s:%d] DBCHECKSubCmd=<%d>\n", __func__, __LINE__, pReq->bt);
	memset(integrity_ret.ret, 0, 32);
	if (diagpdev != NULL){
			update_diagcmd_state(diagpdev, "DBCHECK", pReq->db_check);
			switch(pReq->db_check)
			{
				case DB_INTEGRITY_CHECK:
					while ( !db_integrity_ready )
						msleep(10);
					db_integrity_ready = 0;

					msleep(100); // wait until the return value is written to the file

					{
						unsigned long crc_val;
						//crc_val = simple_strtoul(integrity_ret.ret+1,NULL,10);
						crc_val = simple_strtoul(integrity_ret.ret+1,NULL,16);
						sprintf(pRsp->test_mode_rsp.str_buf, "0x%08X", crc_val);
						
						printk(KERN_INFO "%s\n", integrity_ret.ret);
						printk(KERN_INFO "%ld\n", crc_val);
						printk(KERN_INFO "%s\n", pRsp->test_mode_rsp.str_buf);
					}

					/* MANUFACTURE requested not to check the status, just return CRC
					if ( integrity_ret.ret[0] == '0' )
						pRsp->ret_stat_code = TEST_OK_S;
					else
						pRsp->ret_stat_code = TEST_FAIL_S;
					*/
					pRsp->ret_stat_code = TEST_OK_S;
					break;
					
				case FPRI_CRC_CHECK:
					while ( !fpri_crc_ready )
						msleep(10);
					fpri_crc_ready = 0;

					msleep(100); // wait until the return value is written to the file

					{
						unsigned long crc_val;
						crc_val = simple_strtoul(integrity_ret.ret+1,NULL,10);
						sprintf(pRsp->test_mode_rsp.str_buf, "0x%08X", crc_val);
						
						printk(KERN_INFO "%s\n", integrity_ret.ret);
						printk(KERN_INFO "%ld\n", crc_val);
						printk(KERN_INFO "%s\n", pRsp->test_mode_rsp.str_buf);
					}

					/* MANUFACTURE requested not to check the status, just return CRC
					if ( integrity_ret.ret[0] == '0' )
						pRsp->ret_stat_code = TEST_OK_S;
					else
						pRsp->ret_stat_code = TEST_FAIL_S;
					*/
					
					/*
					if ( integrity_ret.ret[0] == '0' )
					{
						unsigned long crc_val;
						pRsp->ret_stat_code = TEST_OK_S;
						memcpy(pRsp->test_mode_rsp.str_buf,integrity_ret.ret, 1);
						
						crc_val = simple_strtoul(integrity_ret.ret+1,NULL,10);
						sprintf(pRsp->test_mode_rsp.str_buf + 1, "%08x", crc_val);
						
					} else {
						pRsp->ret_stat_code = TEST_FAIL_S;
					}
					*/
					pRsp->ret_stat_code = TEST_OK_S;
					break;
					
				case FILE_CRC_CHECK:
				{
					while ( !file_crc_ready )
						msleep(10);
					file_crc_ready = 0;

					msleep(100); // wait until the return value is written to the file

					{
						unsigned long crc_val;
						crc_val = simple_strtoul(integrity_ret.ret+1,NULL,10);
						sprintf(pRsp->test_mode_rsp.str_buf, "0x%08X", crc_val);
						
						printk(KERN_INFO "%s\n", integrity_ret.ret);
						printk(KERN_INFO "%ld\n", crc_val);
						printk(KERN_INFO "%s\n", pRsp->test_mode_rsp.str_buf);
					}

					/* MANUFACTURE requested not to check the status, just return CRC
					if ( integrity_ret.ret[0] == '0' )
						pRsp->ret_stat_code = TEST_OK_S;
					else
						pRsp->ret_stat_code = TEST_FAIL_S;
					*/
					pRsp->ret_stat_code = TEST_OK_S;
					break;
					
				/*
					int mtd_op_result = 0;
					char sec_buf[512];
					const MmcPartition *pSystem_part; 
					unsigned long system_bytes_pos_in_emmc = 0;
					unsigned long system_sec_remained = 0;
					
					printk(KERN_INFO"FILE_CRC_CHECK read block1\n");
					
					lge_mmc_scan_partitions();
					
					pSystem_part = lge_mmc_find_partition_by_name("system");
					if ( pSystem_part == NULL )
					{
					
						printk(KERN_INFO"NO System\n");
						return 0;
					}
					system_bytes_pos_in_emmc = (pSystem_part->dfirstsec*512);
					system_sec_remained = pSystem_part->dsize;
					memset(sec_buf, 0 , 512);

					do 
					{
						mtd_op_result = lge_read_block(system_bytes_pos_in_emmc, sec_buf, 512);
						system_bytes_pos_in_emmc += mtd_op_result;
						system_sec_remained -= 1;
						printk(KERN_INFO"FILE_CRC_CHECK> system_sec_remained %d \n", system_sec_remained);
						
					} while ( mtd_op_result != 0 && system_sec_remained != 0 );
				*/	
#if 0					
					while ( !file_crc_ready )
						msleep(10);
					file_crc_ready = 0;
#else
//					pRsp->ret_stat_code = TEST_OK_S;

#endif					
					break;
				}
				case CODE_PARTITION_CRC_CHECK:
#if 0					
					while ( !code_partition_crc_ready )
						msleep(10);
					code_partition_crc_ready = 0;
#else
					pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
					
#endif					
					break;
				case TOTAL_CRC_CHECK:
#if 0 					
					while ( !total_crc_ready )
						msleep(10);
					total_crc_ready = 0;
#else
					pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
										
#endif					

					break;
			}
	}
	else
	{
			printk("\n[%s] error DBCHECK", __func__ );
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
	}
	printk(KERN_ERR "[_DBCHECK_] [%s:%d] DBCHECK Result=<%s>\n", __func__, __LINE__, integrity_ret.ret);
	return pRsp;

}
#endif
// END: daegeun.yoon@lge.com 2011-08-15

//====================================================================
// Self Recovery Download Support  diag command 249-XX
//====================================================================
#ifdef CONFIG_LGE_DLOAD_SRD  //kabjoo.choi


PACK (void *)LGE_Dload_SRD (PACK (void *)req_pkt_ptr, uint16 pkg_len)
{

  	udbp_req_type		*req_ptr = (udbp_req_type *) req_pkt_ptr;
	udbp_rsp_type	  	*rsp_ptr = NULL;	
	uint16 rsp_len = pkg_len;
	int write_size=0 , mtd_op_result=0; 
	size_t write_size_at_once = 8192; //8KB
	int write_count = 0;
	size_t r_write_size= 0;
	int index = 0;

	rsp_ptr = (udbp_rsp_type *)diagpkt_alloc(DIAG_USET_DATA_BACKUP, rsp_len);

  	// DIAG_TEST_MODE_F_rsp_type union type is greater than the actual size, decrease it in case sensitive items
  		switch(req_ptr->header.sub_cmd)
      		{
  			case  SRD_INIT_OPERATION:				
				diag_SRD_Init(req_ptr,rsp_ptr);							
				break;
				
			case USERDATA_BACKUP_REQUEST:
						
				remote_rpc_srd_cmmand(req_ptr, rsp_ptr);  //userDataBackUpStart() ���⼭ ... shared ram ���� �ϵ���. .. 
				diag_userDataBackUp_entrySet(req_ptr,rsp_ptr,0);  //write info data ,  after rpc respons include write_sector_counter  

				//todo ..  rsp_prt->header.write_sector_counter,  how about checking  no active nv item  ; 
				// write ram data to emmc misc partition  as many as retruned setor counters 
				load_srd_shard_base=smem_alloc(SMEM_ERR_CRASH_LOG, SIZE_OF_SHARD_RAM);  //384K byte 
				
				if (load_srd_shard_base ==NULL)
				{
					((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
					break;
					// return rsp_ptr;
				}					
				  
				write_size= rsp_ptr->rsp_data.write_sector_counter *256;	 //return nv backup counters  

				if( write_size >SIZE_OF_SHARD_RAM)
				{
				 	((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;  //hue..
				 	break;
				}
				 
				printk(KERN_ERR "srd_kernel_base size == %d\n",write_size);

				write_count = (int) write_size / write_size_at_once;
				r_write_size = write_size % write_size_at_once;
				
				//khyun.kim@lge.com 2011-11-08. Because of OOD, MS840 SRD memory allocates by 8KB unit. 
				load_srd_kernel_base=kmalloc((size_t)write_size_at_once, GFP_KERNEL);
								
				printk(KERN_ERR "[SRD] write_count == %d ,r_write_count == %d \n ",write_count,r_write_size);
				
				for (index = 0; index < write_count; index++)
			 	{
			 		memset(load_srd_kernel_base,0xff,write_size_at_once);
				 	memcpy(load_srd_kernel_base,load_srd_shard_base+((index)*write_size_at_once),write_size_at_once);	
					//srd_bytes_pos_in_emmc+512 means that info data already writed at emmc first sector 
					mtd_op_result = lge_write_block(srd_bytes_pos_in_emmc+512+((index)*write_size_at_once), load_srd_kernel_base, write_size_at_once);  //512 info data 
					if(mtd_op_result!= write_size_at_once)
        			{
						((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
						kfree(load_srd_kernel_base);
						goto write_fail;
					}
			 	}
				kfree(load_srd_kernel_base);
				
				if (r_write_size)
			 	{
				 	load_srd_kernel_base=kmalloc((size_t)r_write_size, GFP_KERNEL);
					memset(load_srd_kernel_base,0xff,r_write_size);
					memcpy(load_srd_kernel_base,load_srd_shard_base+(index*write_size_at_once),r_write_size);	
					//srd_bytes_pos_in_emmc+512 means that info data already writed at emmc first sector 
					mtd_op_result = lge_write_block(srd_bytes_pos_in_emmc+512+(index*write_size_at_once), load_srd_kernel_base, r_write_size);  //512 info data 
					if(mtd_op_result!= r_write_size)
        			{
						((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
						kfree(load_srd_kernel_base);
						goto write_fail;
					}
			 	}
				kfree(load_srd_kernel_base);
				
				break;

			case USERDATA_BACKUP_REQUEST_MDM:
				//MDM backup 
				((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_SUCCESS;	
				load_srd_shard_base=smem_alloc(SMEM_ERR_CRASH_LOG, SIZE_OF_SHARD_RAM);  //384K byte 
				
				if (load_srd_shard_base ==NULL)
				{
					((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
					break;
				 	// return rsp_ptr;
				}	
				load_srd_shard_base+=1200*256 ; //mdm ram offset 
				
				remote_rpc_srd_cmmand(req_ptr, rsp_ptr);  //userDataBackUpStart() ���⼭ ... ram ���� �ϵ���. .. 
				diag_userDataBackUp_entrySet(req_ptr,rsp_ptr,1);  //write info data ,  after rpc respons include write_sector_counter  remote_rpc_srd_cmmand(req_ptr, rsp_ptr);  //userDataBackUpStart() ���⼭ ... ram ���� �ϵ���. .. 
				write_size= rsp_ptr->rsp_data.write_sector_counter *256;	 //return nv backup counters  

				if( write_size >0x15000)  //384K = mode ram (300K) + mdm (80K)
				{
				 	((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;  //hue..
				 	break;
				}

				printk(KERN_ERR "MDM_srd_kernel_base size == %d\n",write_size);

				write_count = (int) write_size / write_size_at_once;
				r_write_size = write_size % write_size_at_once;

				//khyun.kim@lge.com 2011-11-08. Because of OOD, MS840 SRD memory allocates by 8KB unit. 
				load_srd_kernel_base=kmalloc((size_t)write_size_at_once, GFP_KERNEL);				
				memset(load_srd_kernel_base,0xff,write_size_at_once);
				
				printk(KERN_ERR "[SRD] MDM_write_count == %d ,MDM_r_write_count == %d \n ",write_count,r_write_size);

				for (index = 0; index < write_count; index++)
			 	{			 		
				 	memcpy(load_srd_kernel_base,load_srd_shard_base+(index*write_size_at_once),write_size_at_once);	
					//srd_bytes_pos_in_emmc+512 means that info data already writed at emmc first sector 
					mtd_op_result = lge_write_block(srd_bytes_pos_in_emmc+0x400000+512+((index)*write_size_at_once), load_srd_kernel_base, write_size_at_once);  //512 info data 
					if(mtd_op_result!= write_size_at_once)
        			{
						((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
						kfree(load_srd_kernel_base);
						goto write_fail;
					}
			 	}
				kfree(load_srd_kernel_base);
				
				if (r_write_size)
			 	{
				 	load_srd_kernel_base=kmalloc((size_t)r_write_size, GFP_KERNEL);
					memset(load_srd_kernel_base,0xff,r_write_size);
					memcpy(load_srd_kernel_base,load_srd_shard_base+(index*write_size_at_once),r_write_size);	
					//srd_bytes_pos_in_emmc+512 means that info data already writed at emmc first sector 
					mtd_op_result = lge_write_block(srd_bytes_pos_in_emmc+0x400000+512+(index*write_size_at_once), load_srd_kernel_base, r_write_size);  //512 info data 
					if(mtd_op_result!= r_write_size)
        			{
						((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
						kfree(load_srd_kernel_base);
						goto write_fail;
					}
			 	}
				kfree(load_srd_kernel_base);				 

				break;
			

			case GET_DOWNLOAD_INFO :
				break;

			case EXTRA_NV_OPERATION :
			#ifdef LG_FW_SRD_EXTRA_NV				
				diag_extraNv_entrySet(req_ptr,rsp_ptr);
			#endif
				break;
				
			case PRL_OPERATION :
			#ifdef LG_FW_SRD_PRL				
				diag_PRL_entrySet(req_ptr,rsp_ptr);
			#endif
				break;
				
			default :
  				rsp_ptr =NULL; //(void *) diagpkt_err_rsp (DIAG_BAD_PARM_F, req_ptr, pkt_len);
				break;
		
		}
write_fail:

	/* Execption*/	
	if (rsp_ptr == NULL){
		return NULL;
	}
#if 0
	if (!diagcomm_status()){
		diagpkt_free(rsp_ptr);
		return NULL;
	}

//	return rsp_ptr;

#endif 
 

  return rsp_ptr;

}
EXPORT_SYMBOL(LGE_Dload_SRD);
#endif 


 
// END: 0010090 sehyuny.kim@lge.com 2010-10-21
/*  USAGE
  *    1. If you want to handle at ARM9 side, you have to insert fun_ptr as NULL and mark ARM9_PROCESSOR
  *    2. If you want to handle at ARM11 side , you have to insert fun_ptr as you want and mark AMR11_PROCESSOR.
  */

testmode_user_table_entry_type testmode_mstr_tbl[TESTMODE_MSTR_TBL_SIZE] =
{
/*    sub_command                                              fun_ptr                      which procesor              */
	/* 0 ~ 5 */
	{ TEST_MODE_VERSION,                  NULL,                     ARM9_PROCESSOR},
    {TEST_MODE_LCD,                       linux_app_handler,    ARM11_PROCESSOR},
	{ TEST_MODE_MOTOR,                    LGF_TestMotor,            ARM11_PROCESSOR},
	{ TEST_MODE_ACOUSTIC,                 LGF_TestAcoustic,         ARM11_PROCESSOR},
	/* 5 ~ 10 */
	{ TEST_MODE_CAM,                      LGF_TestCam,              ARM11_PROCESSOR},
	/* 11 ~ 15 */

	/* 16 ~ 20 */

	/* 21 ~ 25 */
    {TEST_MODE_KEY_TEST,                    LGT_TestModeKeyTest,    ARM11_PROCESSOR}, //56page
	{ TEST_MODE_EXT_SOCKET_TEST,          LGF_ExternalSocketMemory, ARM11_PROCESSOR},
#if 1 //#ifndef LG_BTUI_TEST_MODE
	{ TEST_MODE_BLUETOOTH_TEST,           LGF_TestModeBlueTooth,    ARM11_PROCESSOR},
#endif //LG_BTUI_TEST_MODE
#if 1//def CONFIG_LGE_BATT_SOC_FOR_NPST
	{ TEST_MODE_BATT_LEVEL_TEST, 		  LGF_TestModeBattLevel,	ARM11_PROCESSOR},
#endif
	/* 26 ~ 30 */
	{ TEST_MODE_MP3_TEST,                 LGF_TestModeMP3,          ARM11_PROCESSOR},
	/* 31 ~ 35 */
	{ TEST_MODE_ACCEL_SENSOR_TEST,        linux_app_handler,        ARM11_PROCESSOR},
//	LGE_CHANGE [hyeyoon.yang@lge.com], 2011-08-23, adding Wi-Fi for Testmode menus 
	{ TEST_MODE_WIFI_TEST,                linux_app_handler,        ARM11_PROCESSOR},
    {TEST_MODE_MANUAL_MODE_TEST,            NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_FORMAT_MEMORY_TEST,          not_supported_command_handler,    ARM11_PROCESSOR},
	/* 36 ~ 40 */
//	{ TEST_MODE_KEY_DATA_TEST,            LGF_TestModeKeyData,        ARM11_PROCESSOR},
	{ TEST_MODE_KEY_DATA_TEST,            linux_app_handler,        ARM11_PROCESSOR}, //93
// BEGIN : munho.lee@lge.com 2010-11-30
// ADD: 0011620: [Test_mode] Memory format test 
	{ TEST_MODE_FORMAT_MEMORY_TEST,		  LGF_MemoryFormatTest,		ARM11_PROCESSOR},
// END : munho.lee@lge.com 2010-11-30
	/* 41 ~ 45 */
	{ TEST_MODE_MEMORY_CAPA_TEST,         LGF_MemoryVolumeCheck,    ARM11_PROCESSOR},
#if 1 //def CONFIG_LGE_TOUCH_TEST
	{ TEST_MODE_SLEEP_MODE_TEST,          LGF_PowerSaveMode,        ARM11_PROCESSOR},
#endif /* CONFIG_LGE_TOUCH_TEST */
	{ TEST_MODE_SPEAKER_PHONE_TEST,       LGF_TestModeSpeakerPhone, ARM11_PROCESSOR},
// BEGIN: 0010557  unchol.park@lge.com 2010-11-18
// 0010557 : [Testmode] added test_mode command for LTE test 
// add call function
// BEGIN: 0010557  unchol.park@lge.com 2011-01-12
// 0010557 : [Testmode] added test_mode command for LTE test 
	//{ TEST_MODE_VIRTUAL_SIM_TEST,         LGF_TestModeDetach, 		ARM11_PROCESSOR},
	{ TEST_MODE_VIRTUAL_SIM_TEST,         LGF_TestModeVirtualSimTest, 		ARM11_PROCESSOR},
// END: 0010557 unchol.park@lge.com 2011-01-12
// END: 0010557 unchol.park@lge.com 2010-11-18
    {TEST_MODE_PHOTO_SENSER_TEST,           not_supported_command_handler,    ARM11_PROCESSOR},

	/* 46 ~ 50 */
	{ TEST_MODE_MRD_USB_TEST,             NULL,                     ARM9_PROCESSOR },
	{ TEST_MODE_PROXIMITY_SENSOR_TEST,    linux_app_handler,        ARM11_PROCESSOR },
	{ TEST_MODE_TEST_SCRIPT_MODE,         LGF_TestScriptItemSet,    ARM11_PROCESSOR },
	
	{ TEST_MODE_FACTORY_RESET_CHECK_TEST, LGF_TestModeFactoryReset, ARM11_PROCESSOR },//
	/* 51 ~	*/
	{ TEST_MODE_VOLUME_TEST,              LGT_TestModeVolumeLevel,  ARM11_PROCESSOR},
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
	{ TEST_MODE_FIRST_BOOT_COMPLETE_TEST,  LGF_TestModeFboot,        ARM11_PROCESSOR},
// END: 0011366 sehyuny.kim@lge.com 2010-11-25
// BEGIN: 0010557  unchol.park@lge.com 2010-11-05
// 0010557 : [Testmode] added test_mode command for LTE test
// add call function 2010-11-18
	{ TEST_MODE_MAX_CURRENT_CHECK,     	 NULL,							ARM9_PROCESSOR},
	{ TEST_MODE_CHANGE_RFCALMODE,     	 NULL,  						ARM9_PROCESSOR},
	{ TEST_MODE_SELECT_MIMO_ANT,       	 NULL,  						ARM9_PROCESSOR},
	{ TEST_MODE_LTE_MODE_SELECTION, 	LGF_TestModeLteModeSelection,	ARM11_PROCESSOR},
	{ TEST_MODE_LTE_CALL, 				LGF_TestModeLteCall,			ARM9_PROCESSOR},
	/* [yk.kim@lge.com] 2011-01-04, change usb driver */
	{ TEST_MODE_CHANGE_USB_DRIVER, LGF_TestModeChangeUsbDriver, ARM11_PROCESSOR},
// BEGIN: 0010557  unchol.park@lge.com 2011-01-24
// 0010557 : [Testmode] added test_mode command for LTE test
	{ TEST_MODE_GET_HKADC_VALUE, 		NULL, 							ARM9_PROCESSOR},
// END: 0010557 unchol.park@lge.com 2011-01-24
// add call function 2010-11-18
// END: 0010557 unchol.park@lge.com 2010-11-05
    {TEST_MODE_LED_TEST,                    linux_app_handler,    ARM11_PROCESSOR},
	{ TEST_MODE_PID_TEST,             	 NULL,  						ARM9_PROCESSOR},
	{ TEST_MODE_SW_VERSION, 		NULL, 						ARM9_PROCESSOR},
	{ TEST_MODE_IME_TEST, 		NULL, 						ARM9_PROCESSOR},
	{ TEST_MODE_IMPL_TEST, 		NULL, 						ARM9_PROCESSOR},
	{ TEST_MODE_SIM_LOCK_TYPE_TEST, 		NULL, 						ARM9_PROCESSOR},
	{ TEST_MODE_UNLOCK_CODE_TEST, 		NULL, 						ARM9_PROCESSOR},
	{ TEST_MODE_IDDE_TEST, 		NULL, 						ARM9_PROCESSOR},
	{ TEST_MODE_FULL_SIGNATURE_TEST, 		NULL, 						ARM9_PROCESSOR},
	{ TEST_MODE_NT_CODE_TEST, 		NULL, 						ARM9_PROCESSOR},
	{ TEST_MODE_SIM_ID_TEST, 		NULL, 						ARM9_PROCESSOR},
	/*80~	*/
	{ TEST_MODE_CAL_CHECK, 			NULL,						ARM9_PROCESSOR},
#if 1 //#ifndef LG_BTUI_TEST_MODE
	{ TEST_MODE_BLUETOOTH_RW,	LGF_TestModeBlueTooth_RW	   , ARM11_PROCESSOR},
#endif //LG_BTUI_TEST_MODE
	{ TEST_MODE_SKIP_WELCOM_TEST, 			NULL,						ARM9_PROCESSOR},
#if 1     //LGE_CHANGE, [dongp.kim@lge.com], 2010-10-09, adding Wi-Fi MAC read/write for Testmode menus 
    {TEST_MODE_WIFI_MAC_RW,                 LGF_TestModeWiFiMACRW,            ARM11_PROCESSOR},
//	{ TEST_MODE_MAC_READ_WRITE,    linux_app_handler,        ARM11_PROCESSOR },
#endif //LG_FW_WLAN_TEST 
// BEGIN: 0011366 sehyuny.kim@lge.com 2010-11-25
// MOD 0011366: [Testmode] Fix some testmode command related to firmware
	{ TEST_MODE_DB_INTEGRITY_CHECK,         LGF_TestModeDBIntegrityCheck,   ARM11_PROCESSOR},
    { TEST_MODE_NVCRC_CHECK, 		NULL,	ARM9_PROCESSOR},
// END: 0011366 sehyuny.kim@lge.com 2010-11-25

//BEGIN: seungkwan.jung
   {TEST_MODE_GYRO_SENSOR_TEST,    linux_app_handler,        ARM11_PROCESSOR },

//END:seungkwan.jung
/* BEGIN: 0015893 jihoon.lee@lge.com 20110212 */
/* ADD 0015893: [MANUFACTURE] WDC LIFETIMER CLNR LAUNCH_KIT */
//    { TEST_MODE_RESET_PRODUCTION, 		NULL,								ARM9_PROCESSOR},

    //HELLG ........ is this is my job????????????? 
    { TEST_MODE_RESET_PRODUCTION, 		LGF_TestModeResetProduction,								ARM11_PROCESSOR},

    {TEST_MODE_FOTA_ID_CHECK,               LGF_TestModeFotaIDCheck,          ARM11_PROCESSOR},
/* END: 0015893 jihoon.lee@lge.com 20110212 */
   {TEST_MODE_KEY_LOCK,			   LGF_TestModeKEYLOCK, 		 ARM11_PROCESSOR},

   {TEST_MODE_ACCELERATOR_SENSOR_TEST,    linux_app_handler,        ARM11_PROCESSOR },
   {TEST_MODE_GYRO_SENSOR_TEST_TEST,    linux_app_handler,        ARM11_PROCESSOR },
   {TEST_MODE_COMPASS_SENSOR_TEST,    linux_app_handler,        ARM11_PROCESSOR },
//Added by jaeopark 110527 for XO Cal Backup
    {TEST_MODE_XO_CAL_DATA_COPY,		NULL,						ARM9_PROCESSOR },

    //HELLG ........ is this is my job????????????? 
    {TEST_MODE_IRDA_FMRT_FINGER_UIM_TEST,       LGF_TestModeIrdaFmrtFingerUIMTest,  ARM11_PROCESSOR }
};

