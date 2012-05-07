#include <linux/module.h>
#include <lg_diagcmd.h>
#include <linux/input.h>
#include <linux/syscalls.h>

#include <lg_fw_diag_communication.h>
#include <lg_diag_testmode.h>
#include <mach/qdsp5v2/audio_def.h>
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

#include <mach/board_lge.h>
#include <lg_backup_items.h>

#include <linux/gpio.h>
#include <linux/mfd/pmic8058.h>
#include <mach/irqs.h>

/* test_sch_secureboot_start  */
#include <mach/scm-io.h>
#include <mach/msm_iomap.h>
#include <mach/scm.h>
#include <linux/random.h>
/* test_sch_secureboot_end  */

#define PMIC_GPIO_SDC3_DET 22
#define PM8058_GPIO_BASE NR_MSM_GPIOS
#define PM8058_GPIO_PM_TO_SYS(pm_gpio) (pm_gpio + PM8058_GPIO_BASE)

static struct diagcmd_dev *diagpdev;

extern PACK(void *) diagpkt_alloc (diagpkt_cmd_code_type code, unsigned int length);
extern PACK(void *) diagpkt_free (PACK(void *)pkt);
extern void send_to_arm9( void * pReq, void * pRsp);
extern testmode_user_table_entry_type testmode_mstr_tbl[TESTMODE_MSTR_TBL_SIZE];
extern int diag_event_log_start(void);
extern int diag_event_log_end(void);
extern void set_operation_mode(boolean isOnline);
extern struct input_dev* get_ats_input_dev(void);
extern unsigned int LGF_KeycodeTrans(word input);
extern void LGF_SendKey(word keycode);
extern int boot_info;
extern int testmode_result;

extern void remote_rpc_srd_cmmand(void * pReq, void * pRsp );
extern void *smem_alloc(unsigned id, unsigned size);


extern PACK (void *)LGE_Dload_SRD (PACK (void *)req_pkt_ptr, uint16 pkg_len);
extern void diag_SRD_Init(udbp_req_type * req_pkt, udbp_rsp_type * rsp_pkt);
extern void diag_userDataBackUp_entrySet(udbp_req_type * req_pkt, udbp_rsp_type * rsp_pkt, script_process_type MODEM_MDM );
extern boolean writeBackUpNVdata( char * ram_start_address , unsigned int size);

#ifdef CONFIG_LGE_DLOAD_SRD  //kabjoo.choi
#define SIZE_OF_SHARD_RAM  0x60000  //384K

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

extern int get_touch_ts_fw_version(char *fw_ver);
extern int lge_bd_rev;

void CheckHWRev(byte *pStr)
{
    char *rev_str[] = {"evb1", "evb2", "A", "B", "C", "D",
        "E", "F", "G", "1.0", "1.1", "1.2",
        "revserved"};

    strcpy((char *)pStr ,(char *)rev_str[lge_bd_rev]);
}

PACK (void *)LGF_TestMode (
        PACK (void	*)req_pkt_ptr, /* pointer to request packet */
        uint16 pkt_len )        /* length of request packet */
{
    DIAG_TEST_MODE_F_req_type *req_ptr = (DIAG_TEST_MODE_F_req_type *) req_pkt_ptr;
    DIAG_TEST_MODE_F_rsp_type *rsp_ptr;
    unsigned int rsp_len=0;
    testmode_func_type func_ptr= NULL;
    int nIndex = 0;

    diagpdev = diagcmd_get_dev();

    // DIAG_TEST_MODE_F_rsp_type union type is greater than the actual size, decrease it in case sensitive items
    switch(req_ptr->sub_cmd_code)
    {
        case TEST_MODE_FACTORY_RESET_CHECK_TEST:
            rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type);
            break;

        case TEST_MODE_TEST_SCRIPT_MODE:
            rsp_len = sizeof(DIAG_TEST_MODE_F_rsp_type) - sizeof(test_mode_rsp_type) + sizeof(test_mode_req_test_script_mode_type);
            break;

        //REMOVE UNNECESSARY RESPONSE PACKET FOR EXTERNEL SOCKET ERASE
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

        case TEST_MODE_MANUAL_TEST_MODE:
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

    printk(KERN_ERR "[LGF_TestMode] rsp_len: %d, sub_cmd_code: %d \n", rsp_len, req_ptr->sub_cmd_code);

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
    else
    {
        if(req_ptr->test_mode_req.version == VER_HW)
            CheckHWRev((byte *)rsp_ptr->test_mode_rsp.str_buf);
        else if(req_ptr->test_mode_req.version == VER_TOUCH_FW)
            get_touch_ts_fw_version((byte *)rsp_ptr->test_mode_rsp.str_buf);
        else
            send_to_arm9((void*)req_ptr, (void*)rsp_ptr);
    }

    return (rsp_ptr);
}
EXPORT_SYMBOL(LGF_TestMode);

void* linux_app_handler(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    diagpkt_free(pRsp);
    return 0;
}

void* not_supported_command_handler(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
    return pRsp;
}

#define GET_INODE_FROM_FILEP(filp) \
    (filp)->f_path.dentry->d_inode

static int android_readwrite_file(const char *filename, char *rbuf, const char *wbuf, size_t length)
{
    int ret = 0;
    struct file *filp = (struct file *)-ENOENT;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    do {
        int mode = (wbuf) ? O_RDWR : O_RDONLY;
        filp = filp_open(filename, mode, S_IRUSR);
        if (IS_ERR(filp) || !filp->f_op) {
            printk(KERN_ERR "%s: file %s filp_open error\n", __FUNCTION__, filename);
            ret = -ENOENT;
            break;
        }

        if (length==0) {
            /* Read the length of the file only */
            struct inode    *inode;

            inode = GET_INODE_FROM_FILEP(filp);
            if (!inode) {
                printk(KERN_ERR "%s: Get inode from %s failed\n", __FUNCTION__, filename);
                ret = -ENOENT;
                break;
            }
            ret = i_size_read(inode->i_mapping->host);
            break;
        }

        if (wbuf) {
            if ( (ret=filp->f_op->write(filp, wbuf, length, &filp->f_pos)) < 0) {
                printk(KERN_ERR "%s: Write %u bytes to file %s error %d\n", __FUNCTION__, 
                                length, filename, ret);
                break;
            }
        } else {
            if ( (ret=filp->f_op->read(filp, rbuf, length, &filp->f_pos)) < 0) {
                printk(KERN_ERR "%s: Read %u bytes from file %s error %d\n", __FUNCTION__,
                                length, filename, ret);
                break;
            }
        }
    } while (0);

    if (!IS_ERR(filp)) {
        filp_close(filp, NULL);
    }
    set_fs(oldfs);

    return ret;
}

char external_memory_copy_test(void)
{
    char return_value = TEST_FAIL_S;
    char *src = (void *)0;
    char *dest = (void *)0;
    off_t fd_offset;
    int fd;
    mm_segment_t old_fs=get_fs();
    set_fs(get_ds());

    if ( (fd = sys_open((const char __user *) "/sdcard/SDTest.txt", O_CREAT | O_RDWR, 0) ) < 0 )
    {
        printk(KERN_ERR "[Testmode Memory Test] Can not access SD card\n");
        goto file_fail;
    }

    if ( (src = kmalloc(10, GFP_KERNEL)) )
    {
        sprintf(src,"TEST");
        if ((sys_write(fd, (const char __user *) src, 5)) < 0)
        {
            printk(KERN_ERR "[Testmode Memory Test] Can not write SD card \n");
            goto file_fail;
        }

        fd_offset = sys_lseek(fd, 0, 0);
    }

    if ( (dest = kmalloc(10, GFP_KERNEL)) )
    {
        if ((sys_read(fd, (char __user *) dest, 5)) < 0)
        {
            printk(KERN_ERR "[Testmode Memory Test] Can not read SD card \n");
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
    sys_unlink((const char __user *)"/sdcard/SDTest.txt");

    return return_value;
}

extern int external_memory_test;

void* LGF_ExternalSocketMemory(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    int i;
    struct statfs_local sf;
    pRsp->ret_stat_code = TEST_FAIL_S;

    // ADD: 0013541: 0014142: [Test_Mode] To remove Internal memory information in External memory test when SD-card is not exist
    //if(gpio_get_value(PM8058_GPIO_PM_TO_SYS(PMIC_GPIO_SDC3_DET - 1)))
    if(external_memory_copy_test())
    {
        if (pReq->esm == EXTERNAL_SOCKET_MEMORY_CHECK)
        {
            pRsp->test_mode_rsp.memory_check = TEST_FAIL_S;
            pRsp->ret_stat_code = TEST_OK_S;
        }
        
        printk(KERN_ERR "[Testmode Memory Test] Can not detect SD card\n");
        return pRsp;
    }

    switch( pReq->esm){
        case EXTERNAL_SOCKET_MEMORY_CHECK:
            pRsp->test_mode_rsp.memory_check = external_memory_copy_test();
            pRsp->ret_stat_code = TEST_OK_S;
            break;

        case EXTERNAL_FLASH_MEMORY_SIZE:
            if (sys_statfs("/sdcard", (struct statfs *)&sf) != 0)
            {
                printk(KERN_ERR "[Testmode Memory Test] can not get sdcard infomation \n");
                pRsp->ret_stat_code = TEST_FAIL_S;
                break;
            }

            pRsp->test_mode_rsp.socket_memory_size = ((long long)sf.f_blocks * (long long)sf.f_bsize) >> 20; // needs Mb.
            pRsp->ret_stat_code = TEST_OK_S;
            break;

        case EXTERNAL_SOCKET_ERASE:
            testmode_result = -1;

            if (diagpdev != NULL)
            {
                update_diagcmd_state(diagpdev, "MMCFORMAT", 1);
            }
            else
            {
                printk("\n[%s] error EXTERNAL_SOCKET_ERASE", __func__ );
                pRsp->ret_stat_code = TEST_FAIL_S;
                break;
            }

            for (i =0; i < 20; i++)
            {
                if (testmode_result !=-1)
                    break;

                msleep(500);
            }

            if(testmode_result != -1)
            {
                pRsp->ret_stat_code = TEST_OK_S;
            }
            else
            {
                pRsp->ret_stat_code = TEST_FAIL_S;
                printk(KERN_ERR "[MMCFORMAT] DiagCommandObserver returned fail or didn't return in 10000ms.\n");
            }

            break;

        case EXTERNAL_FLASH_MEMORY_USED_SIZE:
            external_memory_test = -1;

            if (diagpdev != NULL)
            {
                update_diagcmd_state(diagpdev, "CALCUSEDSIZE", 0);
            }
            else
            {
                printk("\n[%s] error EXTERNAL_FLASH_MEMORY_USED_SIZE", __func__ );
                pRsp->ret_stat_code = TEST_FAIL_S;
                break;
            }

            for (i =0; i < 10; i++)
            {
                if (external_memory_test !=-1)
                    break;

                msleep(200);
            }

            if(external_memory_test != -1)
            {
                pRsp->test_mode_rsp.socket_memory_usedsize = external_memory_test;
                pRsp->ret_stat_code = TEST_OK_S;
            }
            else
            {
                pRsp->ret_stat_code = TEST_FAIL_S;
                printk(KERN_ERR "[CALCUSEDSIZE] DiagCommandObserver returned fail or didn't return in 2000ms.\n");
            }

            break;

        case EXTERNAL_FLASH_MEMORY_CONTENTS_CHECK:
            external_memory_test = -1;

            if (diagpdev != NULL)
            {
                update_diagcmd_state(diagpdev, "CHECKCONTENTS", 0);
            }
            else
            {
                printk("\n[%s] error EXTERNAL_FLASH_MEMORY_CONTENTS_CHECK", __func__ );
                pRsp->ret_stat_code = TEST_FAIL_S;
                break;
            }

            for (i =0; i < 10; i++)
            {
                if (external_memory_test !=-1)
                    break;

                msleep(200);
            }

            if(external_memory_test != -1)
            {
                if(external_memory_test == 1)
                    pRsp->test_mode_rsp.memory_check = TEST_OK_S;
                else 
                    pRsp->test_mode_rsp.memory_check = TEST_FAIL_S;

                pRsp->ret_stat_code = TEST_OK_S;
            }
            else
            {
                pRsp->ret_stat_code = TEST_FAIL_S;
                printk(KERN_ERR "[CHECKCONTENTS] DiagCommandObserver returned fail or didn't return in 2000ms.\n");
            }
            
            break;

        case EXTERNAL_FLASH_MEMORY_ERASE:
            external_memory_test = -1;

            if (diagpdev != NULL)
            {
                update_diagcmd_state(diagpdev, "ERASEMEMORY", 0);
            }
            else
            {
                printk("\n[%s] error EXTERNAL_FLASH_MEMORY_ERASE", __func__ );
                pRsp->ret_stat_code = TEST_FAIL_S;
                break;
            }


            for (i =0; i < 10; i++)
            {
                if (external_memory_test !=-1)
                    break;

                msleep(500);
            }

            if(external_memory_test != -1)
            {
                if(external_memory_test == 1)
                    pRsp->test_mode_rsp.memory_check = TEST_OK_S;
                else
                    pRsp->test_mode_rsp.memory_check = TEST_FAIL_S;

                pRsp->ret_stat_code = TEST_OK_S;
            }
            else
            {
                pRsp->ret_stat_code = TEST_FAIL_S;
                printk(KERN_ERR "[ERASEMEMORY] DiagCommandObserver returned fail or didn't return in 5000ms.\n");
            }
            
            break;

        case EXTERNAL_SOCKET_ERASE_SDCARD_ONLY: /*0xE*/
            if (diagpdev != NULL)
            {
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
            if (diagpdev != NULL)
            {
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

    return pRsp;
}

void* LGF_TestModeBattLevel(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
#ifdef CONFIG_LGE_BATT_SOC_FOR_NPST
    int battery_soc = 0;
    extern int max17040_get_battery_capacity_percent(void);

    pRsp->ret_stat_code = TEST_OK_S;

    printk(KERN_ERR "%s, pRsp->ret_stat_code : %d\n", __func__, pReq->batt);
    if(pReq->batt == BATTERY_FUEL_GAUGE_SOC_NPST)
    {
        battery_soc = (int)max17040_get_battery_capacity_percent();
    }
    else
    {
        pRsp->ret_stat_code = TEST_FAIL_S;
    }

    if(battery_soc > 100)
        battery_soc = 100;
    else if (battery_soc < 0)
        battery_soc = 0;

    printk(KERN_ERR "%s, battery_soc : %d\n", __func__, battery_soc);

    sprintf((char *)pRsp->test_mode_rsp.batt_voltage, "%d", battery_soc);

    printk(KERN_ERR "%s, battery_soc : %s\n", __func__, (char *)pRsp->test_mode_rsp.batt_voltage);
#endif

    return pRsp;
}

/* ============== test_sch_secureboot_start ======================*/ 
void* LGF_TestOTPBlowCommand(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
	int scm_result = 0;
	int i;
	int secure_boot_region_value_lsb = 0;
	int secure_boot_region_value_msb = 0;
	int oem_config_region_value_lsb = 0;
	int oem_config_region_value_msb = 0;
	int read_permission_region_value_lsb = 0;
	int read_permission_region_value_msb = 0;
	int write_permission_region_value_lsb = 0;
	int write_permission_region_value_msb = 0;
	int secondary_key_region_value_lsb = 0;
	int secondary_key_region_value_msb = 0;

	#define SEC_HW_LSB_MASK				0xC1FF83FF
	#define SEC_HW_MSB_MASK				0x007FE0FF
	
	typedef struct 
	{
		unsigned int Row_Addr; 
		unsigned int Row_LSB_Val; 
		unsigned int Row_MSB_Val; 
	}blow_data_type; 

	blow_data_type blow_data_List[] = 
	{
		/* ADDRESS		LSB							MSB*/
		{0x700310,		0x20 /* auth enable */,			0x0}, 		/* auth enable , QC table, QC public key entry 0 */
		{0x700220,		0x31 /* OEM_ID */ ,			0x23},		/* RPM DEBUG DISABLE/SC_SPIDEN_DISABLE/SC_DBGEN_DISABLE */ 		
		{0x7000A8,		0x03000000,					0x0}, 		/* Read permission for 2nd HW key disabled ,blow after readback check */
		{0x7000B0,		0x51100000,					0x0} 		/* write permission for 2nd HW key/OEM_PK_HASH/OEM_CONFIG/OEM_SEC_BOOT. */
	};
	
	struct {
		unsigned int address;		/* physical address */
		unsigned int LSB;			/* blow LSB value */
		unsigned int MSB;			/* blow MSB value */
		unsigned int bus_clk_khz;	/* clock */
	} blow_cmd_buf;	

	secure_boot_region_value_lsb= secure_readl(MSM_QFPROM_BASE+0x310);
	secure_boot_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x314);
	printk(KERN_ERR "secure boot region : Address[0x%X] LSB[0x%X] : MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x310, secure_boot_region_value_lsb, secure_boot_region_value_msb);
	
	oem_config_region_value_lsb = secure_readl(MSM_QFPROM_BASE+0x220);
	oem_config_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x224);
	printk(KERN_ERR "oem config region : Address[0x%X] LSB[0x%X] MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x220, oem_config_region_value_lsb, oem_config_region_value_msb);
	
	read_permission_region_value_lsb = secure_readl(MSM_QFPROM_BASE+0x0A8);
	read_permission_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x2AC);
	printk(KERN_ERR "read permission region : Address[0x%X] LSB[0x%X] MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x0A8, read_permission_region_value_lsb, read_permission_region_value_msb);

	write_permission_region_value_lsb = secure_readl(MSM_QFPROM_BASE+0x0B0);
	write_permission_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x0B4);
	printk(KERN_ERR "write permission region : Address[0x%X] LSB[0x%X] MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x0B0, write_permission_region_value_lsb, write_permission_region_value_msb);

	pRsp->ret_stat_code = TEST_FAIL_S;

	for(i=0;i<7;i++)
	{
		secondary_key_region_value_lsb = secure_readl(MSM_QFPROM_BASE+0x268+(8 * i));
		secondary_key_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x26C+(8 * i));
//		printk(KERN_ERR "secondary H/W key region : Address[0x%X] LSB[0x%X] MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x268+(8 * i), secondary_key_region_value_lsb, secondary_key_region_value_msb);
	}
	
	switch(pReq->otp_command)
	{
		case OTP_WRITE:
		{
			printk(KERN_ERR "Write Command \n");

			/* write permission check */
			if ((((write_permission_region_value_lsb & blow_data_List[3].Row_LSB_Val) == blow_data_List[3].Row_LSB_Val) && 
		    		((write_permission_region_value_msb & blow_data_List[3].Row_MSB_Val) == blow_data_List[3].Row_MSB_Val)))
			{
				printk(KERN_ERR " write permission device \n");
				pRsp->ret_stat_code = TEST_FAIL_S;
				break;
			}

			/* Secondary H/W Key blow */
			for(i=0;i<7;i++)
			{
				/* first random generate */
				secondary_key_region_value_lsb = 0;
				secondary_key_region_value_msb = 0;
				
				get_random_bytes(&secondary_key_region_value_lsb, 4);
				get_random_bytes(&secondary_key_region_value_msb, 4);
				//printk(KERN_ERR "generate secondary H/W key : LSB[0x%X] MSB[0x%X]  \n", secondary_key_region_value_lsb, secondary_key_region_value_msb);

				/* blow command */
				blow_cmd_buf.address = (uint32)MSM_QFPROM_PHYS+0x268+(8 * i);	
				blow_cmd_buf.LSB  = secondary_key_region_value_lsb & SEC_HW_LSB_MASK;
				blow_cmd_buf.MSB  = secondary_key_region_value_msb & SEC_HW_MSB_MASK;
				blow_cmd_buf.bus_clk_khz = 54875;

				printk(KERN_ERR "generate secondary H/W key : LSB[0x%X] MSB[0x%X]  \n", blow_cmd_buf.LSB, blow_cmd_buf.MSB);
				
				scm_result = scm_call(254, 3, &blow_cmd_buf, sizeof(blow_cmd_buf), NULL, 0);
			}
			
			/* Secure boot region blow */
			i=0;
			blow_cmd_buf.address = blow_data_List[i].Row_Addr;	
			blow_cmd_buf.LSB  = blow_data_List[i].Row_LSB_Val;
			blow_cmd_buf.MSB  = blow_data_List[i].Row_MSB_Val;
			blow_cmd_buf.bus_clk_khz = 54875;
			scm_result = scm_call(254, 3, &blow_cmd_buf, sizeof(blow_cmd_buf), NULL, 0);

			/* OEM Config region blow */
			i=1;
			blow_cmd_buf.address = blow_data_List[i].Row_Addr;	
			blow_cmd_buf.LSB  = blow_data_List[i].Row_LSB_Val;
			blow_cmd_buf.MSB  = blow_data_List[i].Row_MSB_Val;
			blow_cmd_buf.bus_clk_khz = 54875;
			scm_result = scm_call(254, 3, &blow_cmd_buf, sizeof(blow_cmd_buf), NULL, 0);

			/* Read Permission region blow */
			i=2;
			blow_cmd_buf.address = blow_data_List[i].Row_Addr;	
			blow_cmd_buf.LSB  = blow_data_List[i].Row_LSB_Val;
			blow_cmd_buf.MSB  = blow_data_List[i].Row_MSB_Val;
			blow_cmd_buf.bus_clk_khz = 54875;
			//scm_result = scm_call(254, 3, &blow_cmd_buf, sizeof(blow_cmd_buf), NULL, 0);

			/* Write Permission region blow */
			i=3;
			blow_cmd_buf.address = blow_data_List[i].Row_Addr;	
			blow_cmd_buf.LSB  = blow_data_List[i].Row_LSB_Val;
			blow_cmd_buf.MSB  = blow_data_List[i].Row_MSB_Val;
			blow_cmd_buf.bus_clk_khz = 54875;
			//scm_result = scm_call(254, 3, &blow_cmd_buf, sizeof(blow_cmd_buf), NULL, 0);

			pRsp->ret_stat_code = TEST_OK_S;
		}
		break;
		
		case OTP_READ:
		{
			printk(KERN_ERR "Read Command \n");

			i=0;
			if (!(((secure_boot_region_value_lsb & blow_data_List[i].Row_LSB_Val) == blow_data_List[i].Row_LSB_Val) && 
		    		((secure_boot_region_value_msb & blow_data_List[i].Row_MSB_Val) == blow_data_List[i].Row_MSB_Val)))
			{
				printk(KERN_ERR " secure boot region not blow \n");
				break;
			}

			i=1;
			if (!(((oem_config_region_value_lsb & blow_data_List[i].Row_LSB_Val) == blow_data_List[i].Row_LSB_Val) && 
		    		((oem_config_region_value_msb & blow_data_List[i].Row_MSB_Val) == blow_data_List[i].Row_MSB_Val)))
			{
				printk(KERN_ERR " oem config region not blow \n");
				break;
			}

			i=2;
			if (!(((read_permission_region_value_lsb & blow_data_List[i].Row_LSB_Val) == blow_data_List[i].Row_LSB_Val) && 
		    		((read_permission_region_value_msb & blow_data_List[i].Row_MSB_Val) == blow_data_List[i].Row_MSB_Val)))
			{
				printk(KERN_ERR "read permission region not blow \n");
				break;
			}

			i=3;
			if (!(((write_permission_region_value_lsb & blow_data_List[i].Row_LSB_Val) == blow_data_List[i].Row_LSB_Val) && 
		    		((write_permission_region_value_msb & blow_data_List[i].Row_MSB_Val) == blow_data_List[i].Row_MSB_Val)))
			{
				printk(KERN_ERR " write permission region not blow \n");
				break;
			}

			pRsp->ret_stat_code = TEST_OK_S;
		}
		break;

		default:
		{
			printk(KERN_ERR "Unknown command \n");
			pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
		}
		break;
	}

	return pRsp;
}
/* ============== test_sch_secureboot_end ======================*/ 

/* ============== test_wv_provisioning_start ======================*/
void* LGF_TestWVProvisioningCommand(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    int result = 0;
    char *command = "UNKNOWN";

    const char *index_filepath = "/drm/widevine/index.txt";
    const char *result_filepath = "/drm/WV_OK";
    const char *envp[] = {
      "HOME=/",
      "TERM=linux",
      NULL,
    };

    printk(KERN_ERR "[WV] : sub2 = %d / type = %d\n", pReq->wv_command.sub2, pReq->wv_command.type);

    // Type of WV command is 21
    if (pReq->wv_command.type != 21)
    {
        printk(KERN_ERR "[WV] : Unsupported type = %d\n", pReq->wv_command.type);
        pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
        return pRsp;
    }
    else
    {
        // Blind command, remove previous result fist
        mm_segment_t old_fs = get_fs();
        set_fs(KERNEL_DS);
        sys_unlink((const char __user *)result_filepath);
        set_fs(old_fs);
    }

    pRsp->ret_stat_code = TEST_OK_S;

    switch(pReq->wv_command.sub2) 
    {
        case WV_ERASE:
        {
            char *argv[] = {
              "wvprovision",
              "cmd_erase",
              NULL,
            };

            printk(KERN_ERR "WV_ERASE : start \n");
            result = call_usermodehelper("/system/bin/wvprovision", argv, (char**)envp, UMH_WAIT_PROC);
            command = "WV_ERASE";
        }
        break;

        case WV_WRITE:
        {
            char szBuf[256] = {0,};
            char *argv[] = {
              "wvprovision",
              "cmd_write",
              szBuf,
              NULL,
            };

            strncpy(szBuf, pReq->wv_command.data, 256);
            printk(KERN_ERR "WV_WRITE : start / data = %s\n", pReq->wv_command.data);
            result = call_usermodehelper("/system/bin/wvprovision", argv, (char**)envp, UMH_WAIT_PROC);
            command = "WV_WRITE";
        }
        break;

        case WV_CHECK:
        {
            char szBuf[256] = {0,};
            char *argv[] = {
              "wvprovision",
              "cmd_check",
              szBuf,
              NULL,
            };

            strncpy(szBuf, pReq->wv_command.data, 256);
            printk(KERN_ERR "WV_CHECK : start / data = %s\n", pReq->wv_command.data);
            result = call_usermodehelper("/system/bin/wvprovision", argv, (char**)envp, UMH_WAIT_PROC);
            command = "WV_CHECK";
        }
        break;

        case WV_WINDEX:
        {
            char szBuf[256] = {0,};
            char *argv[] = {
              "wvprovision",
              "cmd_windex",
              szBuf,
              NULL,
            };

            snprintf(szBuf, 256, "%u", ((unsigned int*)pReq->wv_command.data)[0]);\
            printk(KERN_ERR "WV_WINDEX : start / data = %u\n", ((unsigned int*)pReq->wv_command.data)[0]);
            result = call_usermodehelper("/system/bin/wvprovision", argv, (char**)envp, UMH_WAIT_PROC);
            command = "WV_WINDEX";
        }
        break;

        case WV_RINDEX:
        {
            unsigned int uindex = 0;
            int fd;
            mm_segment_t old_fs = get_fs();

            printk(KERN_ERR "WV_RINDEX : start \n");

            set_fs(KERNEL_DS);
            fd = sys_open((const char __user *)index_filepath, O_RDONLY, 0);
            if (fd < 0)
            {
              set_fs(old_fs);
              // OK with index 0
              memcpy(pRsp->test_mode_rsp.str_buf, &uindex, 4);

              printk(KERN_ERR "WV_RINDEX : Not exist index file\n");
              printk(KERN_ERR "WV_RINDEX : end  0\n");
              return pRsp;
            }

            // Read index
            sys_read(fd, (void*)&uindex, 4);
            sys_close(fd);
            set_fs(old_fs);
            pRsp->test_mode_rsp.wv_index = uindex;
            printk(KERN_ERR "WV_RINDEX : index = %u\n", uindex);
            printk(KERN_ERR "WV_RINDEX : end  0\n");

            return pRsp;
        }
        break;

        default:
        {
            printk(KERN_ERR "Unknown command \n");
            pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
            return pRsp;
        }
        break;
    }

    if (result == 0)
    {
        int fd;
	    mm_segment_t old_fs = get_fs();

        // Checking the resulf of call_usermodehelper() is insufficient.
        // So supplement the result using dummy ok file.
        set_fs(KERNEL_DS);
        fd = sys_open((const char __user *)result_filepath, O_RDONLY, 0);
        if (fd < 0)
        {
            printk(KERN_ERR "%s : OK file doesn't exist\n", command);
            result = -1;
        }
        else
        {
	        sys_close(fd);
            sys_unlink((const char __user *)result_filepath);
        }
        set_fs(old_fs);
    }

    if (result != 0)
    {
        pRsp->ret_stat_code = TEST_FAIL_S;
    }

    printk(KERN_ERR "%s : end  %x \n", command, result);

    return pRsp;
}
/* ============== test_wv_provisioning_end ======================*/

void* LGF_TestModeKeyData(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{

    pRsp->ret_stat_code = TEST_OK_S;

    LGF_SendKey(LGF_KeycodeTrans(pReq->key_data));

    return pRsp;
}

extern struct device *get_atcmd_dev(void);

void* LGF_TestModeSleepMode(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    char *envp[3];
    char *atcmd_name = "AT_NAME=AT%FLIGHT";
    char *atcmd_state = "AT_STATE==1";
    struct device * dev = NULL;

    pRsp->ret_stat_code = TEST_FAIL_S;

    switch(pReq->sleep_mode)
    {
        case SLEEP_FLIGHT_MODE_ON:
            dev = get_atcmd_dev();

            if (dev)
            {
                envp[0] = atcmd_name;
                envp[1] = atcmd_state;
                envp[2] = NULL;

                kobject_uevent_env(&dev->kobj, KOBJ_CHANGE, envp);
                pRsp->ret_stat_code = TEST_OK_S;
            }
            break;

        default:
            pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
            break;
    }

    return pRsp;
}

void* LGF_TestModeVirtualSimTest(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    pRsp->ret_stat_code = TEST_OK_S;
    return pRsp;
}

void* LGF_TestModeFBoot(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    switch( pReq->fboot)
    {
        case FIRST_BOOTING_COMPLETE_CHECK:
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

void* LGF_TestModeFOTA(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    int i;

    if (diagpdev != NULL)
    {
        switch( pReq->fota)
        {
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

				if( (src[i]>='0' && src[i]<= '9') || (src[i]>='a' && src[i]<= 'f') || (src[i]>='A' && src[i]<= 'F') )
				{}
				else
				{
					pRsp->ret_stat_code = TEST_FAIL_S;
					goto file_fail;
			}
			}

			printk(KERN_ERR "[LGF_TestModeWiFiMACRW] WIFI_MAC_ADDRESS_READ Result : %c%c%c%c%c%c%c%c%c%c%c%c", pRsp->test_mode_rsp.read_wifi_mac_addr[0],
					pRsp->test_mode_rsp.read_wifi_mac_addr[1], pRsp->test_mode_rsp.read_wifi_mac_addr[2],
					pRsp->test_mode_rsp.read_wifi_mac_addr[3], pRsp->test_mode_rsp.read_wifi_mac_addr[4],
					pRsp->test_mode_rsp.read_wifi_mac_addr[5], pRsp->test_mode_rsp.read_wifi_mac_addr[6],
					pRsp->test_mode_rsp.read_wifi_mac_addr[7], pRsp->test_mode_rsp.read_wifi_mac_addr[8],
					pRsp->test_mode_rsp.read_wifi_mac_addr[9], pRsp->test_mode_rsp.read_wifi_mac_addr[10],
					pRsp->test_mode_rsp.read_wifi_mac_addr[11]
			);
			

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
	
	return pRsp;
}
// LGE_CHANGE_E, bill.jung@lge.com, 20110808, WiFi MAC R/W Function by DIAG

void* LGF_TestModePowerReset(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    if (diagpdev != NULL)
    {
        update_diagcmd_state(diagpdev, "REBOOT", 0);
        pRsp->ret_stat_code = TEST_OK_S;
    }
    else
        pRsp->ret_stat_code = TEST_FAIL_S;

    return pRsp;
}

void* LGF_Testmode_ext_device_cmd(test_mode_req_type *pReq, DIAG_TEST_MODE_F_rsp_type *pRsp)
{
    if (diagpdev != NULL)
    {
        switch (pReq->ext_device_cmd)
        {
            case EXT_CARD_AUTO_TEST:
                testmode_result = 1;
                update_diagcmd_state(diagpdev, "EXT_CARD_AUTO_TEST", 0);
                msleep(500);

                if (testmode_result != -1)
                {
                    pRsp->ret_stat_code = TEST_OK_S;
                    pRsp->test_mode_rsp.uim_state = testmode_result;
                }
                else
                    pRsp->ret_stat_code = TEST_FAIL_S;
                break;

            default:
                pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
                break;
        }
    }
    else
        pRsp->ret_stat_code = TEST_FAIL_S;

    return pRsp;
}

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

void* LGF_TestModeKeyLockUnlock(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    char buf[32];
    int len;
    pRsp->ret_stat_code = TEST_FAIL_S;

    switch(pReq->key_lock_unlock)
    {
        case KEY_LOCK:
            LGF_TestModeSetDisableInputDevices(1);

            len = sprintf(buf, "%d", 0);
            android_readwrite_file("/sys/class/leds/lcd-backlight/brightness", NULL, buf, len);

            pRsp->ret_stat_code = TEST_OK_S;
            break;

        case KEY_UNLOCK:
            LGF_TestModeSetDisableInputDevices(0);

            len = sprintf(buf, "%d", 100);
            android_readwrite_file("/sys/class/leds/lcd-backlight/brightness", NULL, buf, len);

            pRsp->ret_stat_code = TEST_OK_S;
            break;

        default:
            pRsp->ret_stat_code = TEST_NOT_SUPPORTED_S;
            break;
    }

    return pRsp;
}

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
// END: 0010090 sehyuny.kim@lge.com 2010-10-21
#endif

extern const MmcPartition *lge_mmc_find_partition_by_name(const char *name);

void* LGF_TestModeFactoryReset(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
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
//  printk("LGF_TestScriptItemSet> mmc info sec : 0x%x, size : 0x%x type : 0x%x frst sec: 0x%lx\n", pMisc_part->dfirstsec, pMisc_part->dsize, pMisc_part->dtype, factoryreset_bytes_pos_in_emmc);

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

//20110920 johny.kim@lge.com MLT
void* LGF_TestModeMLTEnableSet(test_mode_req_type * pReq, DIAG_TEST_MODE_F_rsp_type * pRsp)
{
    char *src = (void *)0;
    char *dest = (void *)0;
    off_t fd_offset;
    int fd;

    mm_segment_t old_fs=get_fs();
    set_fs(get_ds());

    pRsp->ret_stat_code = TEST_FAIL_S;

    if (diagpdev != NULL)
    {
        if ( (fd = sys_open((const char __user *) "/mpt/enable", O_CREAT | O_RDWR, 0) ) < 0 )
        {
            printk(KERN_ERR "[Testmode MPT] Can not access MPT\n");
            goto file_fail;
        }
#if 0
		if(pReq->mlt_enable == 2)
		{
			if ( (dest = kmalloc(5, GFP_KERNEL)) )
			{
				if ((sys_read(fd, (char __user *) dest, 2)) < 0)
				{
					printk(KERN_ERR "[Testmode MPT] Can not read MPT \n");
					goto file_fail;
				}

				if ((memcmp("1", dest, 2)) == 0)
				{
					pRsp->test_mode_rsp.mlt_enable = 1;
					pRsp->ret_stat_code = TEST_OK_S;
				}
				else if ((memcmp("0", dest, 2)) == 0)
				{
					pRsp->test_mode_rsp.mlt_enable = 0;
					pRsp->ret_stat_code = TEST_OK_S;
				}
				else
				{
					//pRsp->test_mode_rsp = 1;
					pRsp->ret_stat_code = TEST_FAIL_S;
				}
			}
		}
		else
#endif
		{
			if ( (src = kmalloc(5, GFP_KERNEL)) )
			{
				sprintf(src, "%d", pReq->mlt_enable);
				if ((sys_write(fd, (const char __user *) src, 2)) < 0)
				{
					printk(KERN_ERR "[Testmode MPT] Can not write MPT \n");
					goto file_fail;
				}

				fd_offset = sys_lseek(fd, 0, 0);
			}

			if ( (dest = kmalloc(5, GFP_KERNEL)) )
			{
				if ((sys_read(fd, (char __user *) dest, 2)) < 0)
				{
					printk(KERN_ERR "[Testmode MPT] Can not read MPT \n");
					goto file_fail;
				}

				if ((memcmp(src, dest, 2)) == 0)
					pRsp->ret_stat_code = TEST_OK_S;
				else
					pRsp->ret_stat_code = TEST_FAIL_S;
			}
		}
			
        file_fail:
          kfree(src);
          kfree(dest);
          sys_close(fd);
          set_fs(old_fs);
//          sys_unlink((const char __user *)"/mpt/enable");
    }

    return pRsp;
}
//20110920 johny.kim@lge.com MLT

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
	rsp_ptr = (udbp_rsp_type *)diagpkt_alloc(DIAG_USET_DATA_BACKUP, rsp_len);

  	// DIAG_TEST_MODE_F_rsp_type union type is greater than the actual size, decrease it in case sensitive items
  		switch(req_ptr->header.sub_cmd)
      		{
  			case  SRD_INIT_OPERATION:				
				diag_SRD_Init(req_ptr,rsp_ptr);							
				break;
				
			case USERDATA_BACKUP_REQUEST:
						
				remote_rpc_srd_cmmand(req_ptr, rsp_ptr);  //userDataBackUpStart() 여기서 ... shared ram 저장 하도록. .. 
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

				 load_srd_kernel_base=kmalloc((size_t)write_size, GFP_KERNEL);
				  	
				 memcpy(load_srd_kernel_base,load_srd_shard_base,write_size);	
				 //srd_bytes_pos_in_emmc+512 means that info data already writed at emmc first sector 
				 mtd_op_result = lge_write_block(srd_bytes_pos_in_emmc+512, load_srd_kernel_base, write_size);  //512 info data 

				
        			if(mtd_op_result!= write_size)
        			{
				((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
				kfree(load_srd_kernel_base);
				break;
				//return rsp_ptr;
                   
        			}
				kfree(load_srd_kernel_base);
				#if 0
			  	if ( !writeBackUpNVdata( load_srd_base , write_size))
			  	{
					((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
				 	 return rsp_ptr;
			  	}
				#endif 

				 
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
				
				remote_rpc_srd_cmmand(req_ptr, rsp_ptr);  //userDataBackUpStart() 여기서 ... ram 저장 하도록. .. 
				diag_userDataBackUp_entrySet(req_ptr,rsp_ptr,1);  //write info data ,  after rpc respons include write_sector_counter  remote_rpc_srd_cmmand(req_ptr, rsp_ptr);  //userDataBackUpStart() 여기서 ... ram 저장 하도록. .. 
				write_size= rsp_ptr->rsp_data.write_sector_counter *256;	 //return nv backup counters  

				 if( write_size >0x15000)  //384K = mode ram (300K) + mdm (80K)
				 {
				 	((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;  //hue..
				 	break;
				 }
				  load_srd_kernel_base=kmalloc((size_t)write_size, GFP_KERNEL);
				  memcpy(load_srd_kernel_base,load_srd_shard_base,write_size);	
				  
				 mtd_op_result = lge_write_block(srd_bytes_pos_in_emmc+0x400000+512, load_srd_kernel_base, write_size);  //not sector address > 4M byte offset  

				if(mtd_op_result!= write_size)
        			{
				((udbp_rsp_type*)rsp_ptr)->header.err_code = UDBU_ERROR_CANNOT_COMPLETE;	
				kfree(load_srd_kernel_base);
				break;
				//return rsp_ptr;
                   
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

	/* Execption*/	
	if (rsp_ptr == NULL){
		return NULL;
	}

  return rsp_ptr;
}
EXPORT_SYMBOL(LGE_Dload_SRD);
#endif 

/*  USAGE
 *  1. If you want to handle at ARM9 side, you have to insert fun_ptr as NULL and mark ARM9_PROCESSOR
 *  2. If you want to handle at ARM11 side , you have to insert fun_ptr as you want and mark AMR11_PROCESSOR.
 */

testmode_user_table_entry_type testmode_mstr_tbl[TESTMODE_MSTR_TBL_SIZE] =
{
    /* sub_command                          fun_ptr                           which procesor*/
    /* 0 ~ 10 */
    {TEST_MODE_VERSION,                     NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_LCD,                         not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_MOTOR,                       not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_ACOUSTIC,                    not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_CAM,                         not_supported_command_handler,    ARM11_PROCESSOR},
    /* 11 ~ 20 */
    {TEST_MODE_IRDA_FMRT_FINGER_UIM_TEST,   LGF_Testmode_ext_device_cmd,      ARM11_PROCESSOR},
    /* 21 ~ 30 */
    {TEST_MODE_KEY_TEST,                    not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_EXT_SOCKET_TEST,             LGF_ExternalSocketMemory,         ARM11_PROCESSOR},
    {TEST_MODE_BLUETOOTH_TEST,              not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_BATT_LEVEL_TEST,             LGF_TestModeBattLevel,            ARM11_PROCESSOR},
    {TEST_MODE_MP3_TEST,                    not_supported_command_handler,    ARM11_PROCESSOR},
    /* 31 ~ 40 */
    {TEST_MODE_ACCEL_SENSOR_TEST,           not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_WIFI_TEST,                   not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_MANUAL_TEST_MODE,            NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_FORMAT_MEMORY_TEST,          not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_KEY_DATA_TEST,               LGF_TestModeKeyData,              ARM11_PROCESSOR},
    /* 41 ~ 50 */
    {TEST_MODE_MEMORY_CAPA_TEST,            not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_SLEEP_MODE_TEST,             LGF_TestModeSleepMode,            ARM11_PROCESSOR},
    {TEST_MODE_SPEAKER_PHONE_TEST,          not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_VIRTUAL_SIM_TEST,            LGF_TestModeVirtualSimTest,       ARM11_PROCESSOR},
    {TEST_MODE_PHOTO_SENSER_TEST,           not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_MRD_USB_TEST,                NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_PROXIMITY_SENSOR_TEST,       not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_TEST_SCRIPT_MODE,            LGF_TestScriptItemSet,            ARM11_PROCESSOR},
    {TEST_MODE_FACTORY_RESET_CHECK_TEST,    LGF_TestModeFactoryReset,         ARM11_PROCESSOR},
    /* 51 ~60 */
    {TEST_MODE_VOLUME_TEST,                 not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_FIRST_BOOT_COMPLETE_TEST,    LGF_TestModeFBoot,                ARM11_PROCESSOR},
    {TEST_MODE_MAX_CURRENT_CHECK,           NULL,                             ARM9_PROCESSOR},
    /* 61 ~70 */
    {TEST_MODE_CHANGE_RFCALMODE,            NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_SELECT_MIMO_ANT,             NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_LTE_MODE_SELECTION,          not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_LTE_CALL,                    not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_CHANGE_USB_DRIVER,           not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_GET_HKADC_VALUE,             NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_LED_TEST,                    not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_PID_TEST,                    NULL,                             ARM9_PROCESSOR},
    /* 71 ~ 80 */
    {TEST_MODE_SW_VERSION,                  NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_IME_TEST,                    NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_IMPL_TEST,                   NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_SIM_LOCK_TYPE_TEST,          NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_UNLOCK_CODE_TEST,            NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_IDDE_TEST,                   NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_FULL_SIGNATURE_TEST,         NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_NT_CODE_TEST,                NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_SIM_ID_TEST,                 NULL,                             ARM9_PROCESSOR},
    /* 81 ~ 90*/
    {TEST_MODE_CAL_CHECK,                   NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_BLUETOOTH_RW,                NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_SKIP_WELCOM_TEST,            not_supported_command_handler,    ARM11_PROCESSOR},
    {TEST_MODE_WIFI_MAC_RW,                 LGF_TestModeWiFiMACRW,            ARM11_PROCESSOR},
    /* 91 ~ */
    {TEST_MODE_DB_INTEGRITY_CHECK,          LGF_TestModeDBIntegrityCheck,     ARM11_PROCESSOR},
    {TEST_MODE_NVCRC_CHECK,                 NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_RESET_PRODUCTION,            NULL,                             ARM9_PROCESSOR},
    {TEST_MODE_FOTA,                        LGF_TestModeFOTA,                 ARM11_PROCESSOR},
    {TEST_MODE_POWER_RESET,                 LGF_TestModePowerReset,           ARM11_PROCESSOR},
    {TEST_MODE_KEY_LOCK_UNLOCK,             LGF_TestModeKeyLockUnlock,        ARM11_PROCESSOR},
    {TEST_MODE_XO_CAL_DATA_COPY,            NULL,                             ARM9_PROCESSOR},
//20110920 johny.kim@lge.com MLT
    {TEST_MODE_MLT_ENABLE,                  LGF_TestModeMLTEnableSet,         ARM11_PROCESSOR},
//20110920 johny.kim@lge.com MLT
    /* ============== test_sch_secureboot_start ======================*/
    {TEST_MODE_BLOW_COMMAND,           	    LGF_TestOTPBlowCommand,           ARM11_PROCESSOR},
    /* ============== test_sch_secureboot_end ======================*/
    /* ============== test_wv_provisioning_start ======================*/
    {TEST_MODE_WV_PROVISIONING_COMMAND,     LGF_TestWVProvisioningCommand,    ARM11_PROCESSOR},
    /* ============== test_wv_provisioning_end ======================*/
};

static ssize_t get_qfuse_blow_status ( struct device *dev, struct device_attribute *attr, char *buf)
{
	int i;
	int secure_boot_region_value_lsb = 0;
	int secure_boot_region_value_msb = 0;
	int oem_config_region_value_lsb = 0;
	int oem_config_region_value_msb = 0;
	int read_permission_region_value_lsb = 0;
	int read_permission_region_value_msb = 0;
	int write_permission_region_value_lsb = 0;
	int write_permission_region_value_msb = 0;
	
	typedef struct 
	{
		unsigned int Row_Addr; 
		unsigned int Row_LSB_Val; 
		unsigned int Row_MSB_Val; 
	}blow_data_type; 

	blow_data_type blow_data_List[] = 
	{
		/* ADDRESS		LSB							MSB*/
		{0x700310,		0x20 /* auth enable */,			0x0}, 		/* auth enable , QC table, QC public key entry 0 */
		{0x700220,		0x31 /* OEM_ID */ ,			0x23},		/* RPM DEBUG DISABLE/SC_SPIDEN_DISABLE/SC_DBGEN_DISABLE */ 		
		{0x7000A8,		0x03000000,					0x0}, 		/* Read permission for 2nd HW key disabled ,blow after readback check */
		{0x7000B0,		0x51100000,					0x0} 		/* write permission for 2nd HW key/OEM_PK_HASH/OEM_CONFIG/OEM_SEC_BOOT. */
	};
	
	if ( buf == NULL ) return 0;	
	printk(KERN_ERR "get_qfuse_blow_status Read Command \n");
	

	secure_boot_region_value_lsb= secure_readl(MSM_QFPROM_BASE+0x310);
	secure_boot_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x314);
	printk(KERN_ERR "secure boot region : Address[0x%X] LSB[0x%X] : MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x310, secure_boot_region_value_lsb, secure_boot_region_value_msb);
	
	oem_config_region_value_lsb = secure_readl(MSM_QFPROM_BASE+0x220);
	oem_config_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x224);
	printk(KERN_ERR "oem config region : Address[0x%X] LSB[0x%X] MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x220, oem_config_region_value_lsb, oem_config_region_value_msb);
	
	read_permission_region_value_lsb = secure_readl(MSM_QFPROM_BASE+0x0A8);
	read_permission_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x2AC);
	printk(KERN_ERR "read permission region : Address[0x%X] LSB[0x%X] MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x0A8, read_permission_region_value_lsb, read_permission_region_value_msb);

	write_permission_region_value_lsb = secure_readl(MSM_QFPROM_BASE+0x0B0);
	write_permission_region_value_msb = secure_readl(MSM_QFPROM_BASE+0x0B4);
	printk(KERN_ERR "write permission region : Address[0x%X] LSB[0x%X] MSB[0x%X]  \n", (unsigned int)MSM_QFPROM_BASE+0x0B0, write_permission_region_value_lsb, write_permission_region_value_msb);
	
	i=0;
	if (!(((secure_boot_region_value_lsb & blow_data_List[i].Row_LSB_Val) == blow_data_List[i].Row_LSB_Val) && 
		((secure_boot_region_value_msb & blow_data_List[i].Row_MSB_Val) == blow_data_List[i].Row_MSB_Val)))
	{
		printk(KERN_ERR " secure boot region not blow \n");
		buf[0] = '0';
		return sizeof(buf);
	}
	
	i=1;
	if (!(((oem_config_region_value_lsb & blow_data_List[i].Row_LSB_Val) == blow_data_List[i].Row_LSB_Val) && 
		((oem_config_region_value_msb & blow_data_List[i].Row_MSB_Val) == blow_data_List[i].Row_MSB_Val)))
	{
		printk(KERN_ERR " oem config region not blow \n");
		buf[0] = '0';
		return sizeof(buf);
	}
	
	i=2;
	if (!(((read_permission_region_value_lsb & blow_data_List[i].Row_LSB_Val) == blow_data_List[i].Row_LSB_Val) && 
		((read_permission_region_value_msb & blow_data_List[i].Row_MSB_Val) == blow_data_List[i].Row_MSB_Val)))
	{
		printk(KERN_ERR "read permission region not blow \n");
		buf[0] = '0';
		return sizeof(buf);
	}
	
	i=3;
	if (!(((write_permission_region_value_lsb & blow_data_List[i].Row_LSB_Val) == blow_data_List[i].Row_LSB_Val) && 
		((write_permission_region_value_msb & blow_data_List[i].Row_MSB_Val) == blow_data_List[i].Row_MSB_Val)))
	{
		printk(KERN_ERR " write permission region not blow \n");
		buf[0] = '0';
		return sizeof(buf);
	}	
	
	printk(KERN_INFO "get_qfuse_blow_status: SUCCESS \n");
	buf[0] = '1';
	return sizeof(buf);
}

static ssize_t set_qfuse_blow_status(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int r = 0;

    	return r;
}

DEVICE_ATTR(qfuse_status, 0644, get_qfuse_blow_status, set_qfuse_blow_status );

static int qfuse_status_probe(struct platform_device *pdev)
{
	int err;
	err = device_create_file(&pdev->dev, &dev_attr_qfuse_status);
	if (err < 0)
		printk("%s : Cannot create the sysfs\n", __func__);

	return 0;
}

static struct platform_device qfuse_status_device = {
	.name = "qfuse_status_check",
	.id		= -1,
};

static struct platform_driver qfuse_status_driver = {
	.probe = qfuse_status_probe,
	.driver = {
		.name = "qfuse_status_check",
	},
};

int __init qfuse_status_init(void)
{
	printk("%s\n", __func__);
	platform_device_register(&qfuse_status_device);

	return platform_driver_register(&qfuse_status_driver);
}


module_init(qfuse_status_init);
MODULE_DESCRIPTION("for easy check of SD card status in kernel");
MODULE_AUTHOR("KIMSUNGMIN(smtk.kim@lge.com>");
MODULE_LICENSE("GPL");
