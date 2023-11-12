#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/slab.h>

#define READ_BYTE_SIZE		0x200
#define WRITE_BYTE_SIZE         0x200
#define SECTOR_SIZE             0x200

#define USB_VENDOR_ID           0x174c
#define USB_PRODUCT_ID          0x1153
#define MINOR_BASE              192
#define MAX_TRANSFER            (PAGE_SIZE - 512)
#define WRITES_IN_FLIGHT        8
#define ESIZE                   1
#define CSW_BUF_OFFSET          0x500

#define CMD_INQUIRY		0x1
#define CMD_RESET		0x2
#define CMD_READ		0x3
#define CMD_WRITE               0x4
#define CMD_SIZE_RESET          0x8

#define CBW_SIZE                0x1F
#define CBWCB_MAXSIZE   	0x10
#define CSW_SIZE                0x0D

#define CBW_SIGNATURE           0x43425355
#define CBW_FLAG_IN             (1 << 7)
#define CBW_FLAG_OUT            0
#define CBW_LUN                 0

#define CBW_CMD_INQUIRY_TAG     	0
#define CBW_CMD_INQUIRY_TXLENGTH	0x4C
#define CBW_CMD_INQUIRY_CMDLEN  	0x6

#define CBW_CMD_READ_TAG    	0
#define CBW_CMD_READ_TXLENGTH	READ_BYTE_SIZE
#define CBW_CMD_READ_CMDLEN 	0x0A

#define CBW_CMD_WRITE_TAG       0
#define CBW_CMD_WRITE_TXLENGTH  WRITE_BYTE_SIZE
#define CBW_CMD_WRITE_CMDLEN    0x0A

#define CMD_INQUIRY_OPCODE      0x12
#define CMD_INQUIRY_CE_ZERO     0
#define CMD_INQUIRY_PC_ZERO     0
#define CMD_INQUIRY_AL_H        0
#define CMD_INQUIRY_AL_L        0x4C
#define CMD_INQUIRY_CONTROL     0

#define CMD_READ_OPCODE		0x28
#define CMD_READ_RDPROTECT	0
#define CMD_READ_GNUM		0
#define CMD_READ_TXLENGTH_H	0
#define CMD_READ_TXLENGTH_L	(READ_BYTE_SIZE / SECTOR_SIZE)
#define CMD_READ_CONTROL	0

#define CMD_WRITE_OPCODE        0x2A
#define CMD_WRITE_WRPROTECT     0
#define CMD_WRITE_GNUM          0
#define CMD_WRITE_TXLENGTH_H    0
#define CMD_WRITE_TXLENGTH_L    (WRITE_BYTE_SIZE / SECTOR_SIZE)
#define CMD_WRITE_CONTROL       0

#define CMD_RESET_TYPE          0b00100001
#define CMD_RESET_REQUEST       0b11111111
#define CMD_RESET_VALUE         0
#define CMD_RESET_INDEX_IN      (1 << 7)
#define CMD_RESET_LENGTH        0

struct usb_bulk_storage {
        struct usb_device       *udev;
        struct usb_interface    *interface;
        struct semaphore        limit_sem;
        struct usb_anchor       submitted;
        struct urb              *bulk_in_urb;
        unsigned char           *bulk_in_buffer;
        size_t                  bulk_in_size;
        size_t                  bulk_in_filled;
        size_t                  bulk_in_copied;
        __u8                    bulk_in_endpointAddr;
        __u8                    bulk_out_endpointAddr;
        int                     errors;
        bool                    ongoing_read;
        spinlock_t              err_lock;
        struct kref             kref;
        struct mutex            io_mutex;
        unsigned long           disconnected:1;
        wait_queue_head_t       bulk_in_wait;
};

#define to_usa_dev(d) container_of(d, struct usb_bulk_storage, kref)

struct reset {
        u8 request_type;
        u8 request;
        u16 value;
        u16 index;
        u16 length;
};

struct cbwcb_inquiry {
        u8 opecode;
        u8 cmddt_evpd;
        u8 page_code;
        u8 allocation_length_h;
        u8 allocation_length_l;
        u8 control;
};

struct cbwcb_read {
		u8 opecode;
		u8 rdprotect;
		u8 lba_h;
		u8 lba_mh;
		u8 lba_ml;
		u8 lba_l;
		u8 gnum;
		u8 txlength_h;
		u8 txlength_l;
		u8 control;
};

struct cbwcb_write {
		u8 opecode;
		u8 wrprotect;
		u8 lba_h;
		u8 lba_mh;
		u8 lba_ml;
		u8 lba_l;
		u8 gnum;
		u8 txlength_h;
		u8 txlength_l;
		u8 control;
};

struct cbw {
        u32 signature;
        u32 tag;
        u32 txlength;
        u8 flags;
        u8 lun;
        u8 cbwcb_length;
        u8 cbwcb[CBWCB_MAXSIZE];
};


