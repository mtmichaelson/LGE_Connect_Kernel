#ifndef _LGE_ETA_EVENT_LOG_H_
#define _LGE_ETA_EVENT_LOG_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/sizes.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#endif

#define ETA_EVENT_LOG_IOC_MAGIC 'l'
#define ETA_EVENT_LOG_IOC_CHANGE_LOG_MASK _IOW(ETA_EVENT_LOG_IOC_MAGIC, 0, unsigned int)

struct eta_event_log_type{
	unsigned char log_id;
	unsigned short log_len;
	unsigned int x_hold;
	unsigned int y_code;
	unsigned char action;
};

enum {
	ETA_EVENT_LOG_ID_KEY = 1,
	ETA_EVENT_LOG_ID_TOUCH = 2,
	ETA_EVENT_LOG_ID_MAX,
};

enum {
	ETA_TOUCH_MOVETO = 0, /*Move the pointer to the specified location*/
	ETA_TOUCH_MOVEBY = 1, /*Move the pointer by the specified values*/
	ETA_TOUCH_TAB = 2, /*Tab at the current location*/
	ETA_TOUCH_DOUBLETAB = 3, /*Double tab at the current location*/
	ETA_TOUCH_DOWN = 4, /*Touch down at the current location*/
	ETA_TOUCH_UP = 5, /*Touch up at the current location*/
	ETA_TOUCH_DEFAULT = 0xff,
};
#endif /*_LGE_ETA_EVENT_LOG_H_*/

