#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/slab.h>

#define USB_VENDOR_ID           0x174c
#define USB_PRODUCT_ID          0x1153
#define MINOR_BASE              192
#define MAX_TRANSFER            (PAGE_SIZE - 512)
#define WRITES_IN_FLIGHT        8
#define ESIZE                   1
#define CSW_BUF_OFFSET          0x500

#define CMD_NUM_INQUIRY         1
#define CMD_NUM_RESET           2
#define CMD_SIZE_RESET          0x8

#define CBW_SIZE                0x1F
#define CMD_INQUIRY_CBWCB_SIZE  0x10
#define CSW_SIZE                0x0D

#define CBW_SIGNATURE           0x43425355
#define CBW_CMD_VERIFY_TAG      0
#define CBW_CMD_VERIFY_DATA     0x60
#define CBW_FLAG_IN             (1 << 7)
#define CBW_LUN                 0
#define CBW_CMD_VERIFY_CMDLEN   0x6

#define CMD_INQUIRY_OPCODE      0x12
#define CMD_INQUIRY_CE_ZERO     0
#define CMD_INQUIRY_PC_ZERO     0
#define CMD_INQUIRY_AL_H        0x5
#define CMD_INQUIRY_AL_L        0
#define CMD_INQUIRY_CONT        0

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
        u8 bmrequest_type;
        u8 brequest;
        u16 wvalue;
        u16 windex;
        u16 wlength;
};

struct cbwcb {
        u8 opecode;
        u8 cmddt_evpd;
        u8 page_code;
        u8 allocation_length_h;
        u8 allocation_length_l;
        u8 control;
};


struct cbw {
        u32 dcbw_signature;
        u32 dcbw_tag;
        u32 dcbw_txlength;
        u8 bmcbw_flags;
        u8 bcbw_lun;
        u8 bcbwcb_length;
        u8 cbwcb[CMD_INQUIRY_CBWCB_SIZE];
};


