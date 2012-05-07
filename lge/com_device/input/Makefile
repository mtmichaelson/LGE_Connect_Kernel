#platform.team@lge.com	2011.01
#
# Makefile for the sensor drivers.
#

# Each configuration option enables a list of files.

EXTRA_CFLAGS += -Ilge/include

obj-$(CONFIG_LGE_SENSOR_ACCELEROMETER)	+= k3dh.o
obj-$(CONFIG_LGE_SENSOR_GYROSCOPE)	+= k3g.o
obj-$(CONFIG_LGE_SENSOR_DCOMPASS)	+= ami306.o
obj-$(CONFIG_LGE_SENSOR_PROXIMITY)	+= apds9900.o
obj-$(CONFIG_LGE_TOUCHSCREEN_SYNAPTICS_RMI4_I2C) += touch_synaptics.o lge_touch_core.o
obj-$(CONFIG_LGE_TOUCH_SYNAPTICS_FW_UPGRADE) += touch_synaptics_fw_upgrade.o
obj-$(CONFIG_LGE_HEADSET_DETECTION_FSA8008) += fsa8008.o
obj-$(CONFIG_LGE_NFC_NXP_PN544PN65N)	+= nfc_nxp_pn544pn65n.o
