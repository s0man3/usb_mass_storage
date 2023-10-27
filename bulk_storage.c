#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/slab.h>

#define USB_VENDOR_ID   0x174c
#define USB_PRODUCT_ID  0x1153
#define MINOR_BASE      192

#define CBW_SIZE        0x20
#define CSW_SIZE        0x20
#define INQUIRY_BODY    0x60

#define MAX_TRANSFER            (PAGE_SIZE - 512)
#define WRITES_IN_FLIGHT        8

#define ESIZE 1
#define CSW_BUF_OFFSET 0x100

#define DCBWSIGNATURE 0x43425355
#define DCBWTAG_VERIFY 0
#define DCBW_VERIFY_DATA 0x60
#define BCBW_FLAG_IN (1 << 7)
#define BCBW_LUN 0
#define BCBW_VERIFY_COM_LENGTH 0x6

#define INQUIRY_OPCODE 0x12
#define CMDDT_EVPD_ZERO 0
#define PAGE_CODE_ZERO 0
#define VERIFY_ALLCATION_LENGTH 0x100
#define CBWCB_CONTROL 0


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

static struct usb_driver bulk_storage_driver;
static void bulk_storage_draw_down(struct usb_bulk_storage *dev);

static const struct usb_device_id bulk_storage_idtable[] = {
        { USB_DEVICE(USB_VENDOR_ID, USB_PRODUCT_ID) },
        {},
};
MODULE_DEVICE_TABLE(usb, bulk_storage_idtable);

#define to_usa_dev(d) container_of(d, struct usb_bulk_storage, kref)

struct cbwcb {
        u8 opecode;
        u8 cmddt_evpd;
        u8 page_code;
        u16 allocation_length;
        u8 control;
};


struct cbw {
        u32 dCBWSignature;
        u32 dCBWTag;
        u32 dCBWDataTransferLength;
        u8 bmCBWFlags;
        u8 bCBWLUN;
        u8 bCBWCBLength;
        struct cbwcb CBWCB;
};

static void bulk_storage_delete(struct kref *kref)
{
        struct usb_bulk_storage *dev = to_usa_dev(kref);
        usb_free_urb(dev->bulk_in_urb);
        usb_put_intf(dev->interface);
        usb_put_dev(dev->udev);
        kfree(dev->bulk_in_buffer);
        kfree(dev);
}

static void bulk_storage_write_callback(struct urb *urb)
{
        struct usb_bulk_storage *dev;
        unsigned long flags;

        dev = urb->context;

        if (urb->status) {
                if(!(urb->status== -ENOENT ||
                   urb->status == -ECONNRESET ||
                   urb->status == -ESHUTDOWN))
                        dev_err(&dev->interface->dev,
                                "%s - nonzero write bulk status received: %d\n",
                                __func__, urb->status);
                spin_lock_irqsave(&dev->err_lock, flags);
                dev->errors = urb->status;
                spin_unlock_irqrestore(&dev->err_lock, flags);
        }

        usb_free_coherent(urb->dev, urb->transfer_buffer_length,
                        urb->transfer_buffer, urb->transfer_dma);
        up(&dev->limit_sem);
}

static void make_inquiry_cbwcb(struct cbwcb *CBWCB)
{
        CBWCB->opecode = INQUIRY_OPCODE;
        CBWCB->cmddt_evpd = CMDDT_EVPD_ZERO;
        CBWCB->page_code = PAGE_CODE_ZERO;
        CBWCB->allocation_length =  VERIFY_ALLCATION_LENGTH;
        CBWCB->control = CBWCB_CONTROL;
}

static void make_inquiry_cbw(char *buf) {
        struct cbw *cbw;
        cbw = (struct cbw*)buf;
        
        cbw->dCBWSignature = DCBWSIGNATURE;
        cbw->dCBWTag = DCBWTAG_VERIFY;
        cbw->dCBWDataTransferLength = DCBW_VERIFY_DATA;
        cbw->bmCBWFlags = BCBW_FLAG_IN;
        cbw->bCBWLUN = BCBW_LUN;
        cbw->bCBWCBLength = BCBW_VERIFY_COM_LENGTH;
        make_inquiry_cbwcb(&cbw->CBWCB);
}

static ssize_t send_inquiry(struct usb_bulk_storage *dev, struct file *file)
{
        int retval = 0;
        struct urb *urb = NULL;
        char *buf = NULL;
        size_t writesize = CBW_SIZE;

        if (!(file->f_flags & O_NONBLOCK)) {
                if (down_interruptible(&dev->limit_sem)) {
                        retval = -ERESTARTSYS;
                        goto exit;
                }
        } else {
                if (down_trylock(&dev->limit_sem)) {
                        retval = -EAGAIN;
                        goto exit;
                }
        }

        spin_lock_irq(&dev->err_lock);
        retval = dev->errors;
        if (retval < 0) {
                dev->errors = 0;
                retval = (retval == -EPIPE) ? retval : -EIO;
        }
        spin_lock_irq(&dev->err_lock);
        if (retval < 0)
                goto error;

        urb = usb_alloc_urb(0, GFP_KERNEL);
        if (!urb) {
                retval = -ENOMEM;
                goto error;
        }

        buf = usb_alloc_coherent(dev->udev, writesize, GFP_KERNEL,
                                 &urb->transfer_dma);
        if (!buf) {
                retval = -ENOMEM;
                goto error;
        }

        make_inquiry_cbw(buf);

        mutex_lock(&dev->io_mutex);
        if (dev->disconnected) {
                mutex_unlock(&dev->io_mutex);
                retval = -ENODEV;
                goto error;
        }

        usb_fill_bulk_urb(urb, dev->udev,
                          usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
                          buf, writesize, bulk_storage_write_callback, dev);
        urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
        usb_anchor_urb(urb, &dev->submitted);

        retval = usb_submit_urb(urb, GFP_KERNEL);
        mutex_unlock(&dev->io_mutex);
        if (retval) {
                dev_err(&dev->interface->dev,
                        "%s - failed submitting write urb, error %d\n",
                        __func__, retval);
                goto error_unanchor;
        }

        usb_free_urb(urb);
        
        return writesize;

error_unanchor:
        usb_unanchor_urb(urb);
error:
        if (urb) {
                usb_free_coherent(dev->udev, writesize, buf, urb->transfer_dma);
                usb_free_urb(urb);
        }
        up(&dev->limit_sem);

exit:
        return retval;
}

static void bulk_storage_read_callback(struct urb *urb)
{
        struct usb_bulk_storage *dev;
        unsigned long flags;

        dev = urb->context;

        spin_lock_irqsave(&dev->err_lock, flags);
        if (urb->status) {
                if (!(urb->status == -ENOENT ||
                    urb->status == -ECONNRESET ||
                    urb->status == -ESHUTDOWN))
                        dev_err(&dev->interface->dev,
                                "%s - nonzero write bulk status received: %d\n",
                                __func__, urb->status);
                dev->errors = urb->status;
        } else {
                dev->bulk_in_filled = urb->actual_length;
        }
        dev->ongoing_read = 0;
        spin_unlock_irqrestore(&dev->err_lock, flags);
        wake_up_interruptible(&dev->bulk_in_wait);
}

static ssize_t do_read_io(struct usb_bulk_storage *dev, size_t count)
{
        int rv;

        usb_fill_bulk_urb(dev->bulk_in_urb,
                          dev->udev,
                          usb_rcvbulkpipe(dev->udev, dev->bulk_in_endpointAddr),
                          dev->bulk_in_buffer,
                          min(dev->bulk_in_size, count),
                          bulk_storage_read_callback,
                          dev);
        spin_lock_irq(&dev->err_lock);
        dev->ongoing_read = 1;
        spin_unlock_irq(&dev->err_lock);

        dev->bulk_in_filled = 0;
        dev->bulk_in_copied = 0;

        rv = usb_submit_urb(dev->bulk_in_urb, GFP_KERNEL);
        if (rv < 0) {
                dev_err(&dev->interface->dev,
                        "%s - failed submitting read urb, error %d\n",
                        __func__, rv);
                rv = (rv == -ENOMEM) ? rv : -EIO;
                spin_lock_irq(&dev->err_lock);
                dev->ongoing_read = 0;
                spin_unlock_irq(&dev->err_lock);
        }

        return rv;
}

static ssize_t do_read(struct usb_bulk_storage *dev, struct file *file, char *buffer, size_t count)
{
        int rv;
        bool ongoing_io;

        rv = mutex_lock_interruptible(&dev->io_mutex);
        if (rv < 0)
                return rv;

        if (dev->disconnected) {
                rv = -ENODEV;
                goto exit;
        }

        spin_lock_irq(&dev->err_lock);
        ongoing_io = dev->ongoing_read;
        spin_unlock_irq(&dev->err_lock);

        if (ongoing_io) {
                if (file->f_flags & O_NONBLOCK) {
                        rv = -EAGAIN;
                        goto exit;
                }

                rv = wait_event_interruptible(dev->bulk_in_wait, (!dev->ongoing_read));
                if (rv < 0)
                        goto exit;
        }

        rv = dev->errors;
        if (rv < 0) {
                dev->errors = 0;
                rv = (rv == -EPIPE) ? rv : -EIO;
                goto exit;
        }

        spin_lock_irq(&dev->err_lock);
        ongoing_io = dev->ongoing_read;
        spin_unlock_irq(&dev->err_lock);

        if (ongoing_io) {
                if (file->f_flags & O_NONBLOCK) {
                        rv = -EAGAIN;
                        goto exit;
                }

                rv = wait_event_interruptible(dev->bulk_in_wait, (!dev->ongoing_read));
                if (rv < 0)
                        goto exit;
        }
        
        rv = do_read_io(dev, count);
        if (rv < 0)
                goto exit;

        if (copy_to_user(buffer, dev->bulk_in_buffer, INQUIRY_BODY))
                rv = -EFAULT;
        else
                rv = INQUIRY_BODY;
        
exit:
        mutex_unlock(&dev->io_mutex);
        return rv;
}


static ssize_t read_body(struct usb_bulk_storage *dev, struct file *file, char *buffer)
{
        return do_read(dev, file, buffer, INQUIRY_BODY);
}

static ssize_t read_csw(struct usb_bulk_storage *dev, struct file *file, char *buffer)
{
        return do_read(dev, file, buffer + CSW_BUF_OFFSET, CSW_SIZE);
}

static ssize_t bulk_storage_read(struct file *file, char *buffer, size_t count,
                                loff_t *ppos)
{
        struct usb_bulk_storage *dev = file->private_data;
        int retval;

        if (count < 0x200) {
                retval = -ESIZE;
                goto exit;
        }

        retval = send_inquiry(dev, file);
        retval = read_body(dev, file, buffer);
        retval = read_csw(dev, file, buffer + CSW_BUF_OFFSET);

exit:
        return retval;
}

static ssize_t bulk_storage_write(struct file *file, const char *user_buffer,
                                   size_t count, loff_t *ppos)
{
        pr_info("bulk_storage: write is not implemented yet");
        return 0x10;
}

static int bulk_storage_open(struct inode *inode, struct file *file)
{
        struct usb_bulk_storage *dev;
        struct usb_interface  *interface;
        int subminor;
        int retval = 0;

        subminor = iminor(inode);

        interface = usb_find_interface(&bulk_storage_driver, subminor);
        if (!interface) {
                pr_err("%s - error, can't find device for minor %d\n",
                        __func__, subminor);
                retval = -ENODEV;
                goto exit;
        }

        dev = usb_get_intfdata(interface);
        if (!dev) {
                retval = -ENODEV;
                goto exit;
        }

        retval = usb_autopm_get_interface(interface);
        if (retval) {
                pr_info("Bulk_storage_open: 5 - retval is 0 / success\n");
                goto exit;
        }

        kref_get(&dev->kref);

        file->private_data = dev;

exit:
        return retval;
}

static int bulk_storage_release(struct inode *inode, struct file *file)
{
        struct usb_bulk_storage *dev;
        dev = file->private_data;
        if (dev == NULL)
                return -ENODEV;

        usb_autopm_put_interface(dev->interface);

        kref_put(&dev->kref, bulk_storage_delete);
        return 0;
}

static const struct file_operations bulk_storage_fops = {
        .owner =        THIS_MODULE,
        .read =         bulk_storage_read,
        .write =        bulk_storage_write,
        .open =         bulk_storage_open,
        .release =      bulk_storage_release,
};

struct usb_class_driver bulk_storage_class = {
        .name = "sahci%d",
        .fops = &bulk_storage_fops,
        .minor_base = MINOR_BASE,
};

static int bulk_storage_probe(struct usb_interface *interface,
                             const struct usb_device_id *id)
{
        int retval;
        struct usb_bulk_storage *dev;
        struct usb_endpoint_descriptor *bulk_in, *bulk_out;

        dev = kzalloc(sizeof(*dev), GFP_KERNEL);
        if (!dev)
                return -ENOMEM;

        kref_init(&dev->kref);
        sema_init(&dev->limit_sem, WRITES_IN_FLIGHT);
        mutex_init(&dev->io_mutex);
        spin_lock_init(&dev->err_lock);
        init_usb_anchor(&dev->submitted);
        init_waitqueue_head(&dev->bulk_in_wait);
        
        dev->udev = usb_get_dev(interface_to_usbdev(interface));
        dev->interface = usb_get_intf(interface);

        retval = usb_find_common_endpoints(interface->cur_altsetting,
                        &bulk_in, &bulk_out, NULL, NULL);
        if (retval) {
                dev_err(&interface->dev,
                        "Could not find both bulk-in and bulk-out endpoints\n");
                goto error;
        }

        dev->bulk_in_size = usb_endpoint_maxp(bulk_in);
        dev->bulk_in_endpointAddr = bulk_in->bEndpointAddress;
        dev->bulk_in_buffer = kmalloc(dev->bulk_in_size, GFP_KERNEL);
        if (!dev->bulk_in_buffer) {
                retval = -ENOMEM;
                goto error;
        }
        dev->bulk_in_urb = usb_alloc_urb(0, GFP_KERNEL);
        if (!dev->bulk_in_urb) {
                retval = -ENOMEM;
                goto error;
        }

        dev->bulk_out_endpointAddr = bulk_out->bEndpointAddress;

        usb_set_intfdata(interface, dev);

        retval = usb_register_dev(interface, &bulk_storage_class);
        if (retval) {
                dev_err(&interface->dev,
                        "Not able to get a minor for this device.\n");
                usb_set_intfdata(interface, NULL);
                goto error;
        }

        pr_info("bulk_storage: probe completed without err\n");
        return 0;

error:
        kref_put(&dev->kref, bulk_storage_delete);
        return retval;
}

static void bulk_storage_disconnect(struct usb_interface *interface)
{
        struct usb_bulk_storage *dev;
        int minor = interface->minor;

        dev = usb_get_intfdata(interface);

        usb_deregister_dev(interface, &bulk_storage_class);

        mutex_lock(&dev->io_mutex);
        dev->disconnected = 1;
        mutex_unlock(&dev->io_mutex);
        
        usb_kill_urb(dev->bulk_in_urb);
        usb_kill_anchored_urbs(&dev->submitted);

        kref_put(&dev->kref, bulk_storage_delete);

        dev_info(&interface->dev, "USB simple ahci #%d now disconnected", minor);
}

static void bulk_storage_draw_down(struct usb_bulk_storage *dev)
{
        int time;

        time = usb_wait_anchor_empty_timeout(&dev->submitted, 1000);
        if (!time)
                usb_kill_anchored_urbs(&dev->submitted);
        usb_kill_urb(dev->bulk_in_urb);
}

static int bulk_storage_suspend(struct usb_interface *intf, pm_message_t message)
{
        struct usb_bulk_storage *dev = usb_get_intfdata(intf);

        if (!dev)
                return 0;
        bulk_storage_draw_down(dev);
        return 0;
}

static int bulk_storage_resume(struct usb_interface *intf)
{
        return 0;
}

static int bulk_storage_pre_reset(struct usb_interface *intf)
{
        struct usb_bulk_storage *dev = usb_get_intfdata(intf);

        mutex_lock(&dev->io_mutex);
        bulk_storage_draw_down(dev);
        return 0;
}

static int bulk_storage_post_reset(struct usb_interface *intf)
{
        struct usb_bulk_storage *dev = usb_get_intfdata(intf);

        dev->errors = -EPIPE;
        mutex_unlock(&dev->io_mutex);

        return 0;
}


static struct usb_driver bulk_storage_driver = {
        .name =         "bulk_storage_driver",
        .probe =        bulk_storage_probe,
        .disconnect =   bulk_storage_disconnect,
        .suspend =      bulk_storage_suspend,
        .resume =       bulk_storage_resume,
        .pre_reset =    bulk_storage_pre_reset,
        .post_reset =   bulk_storage_post_reset,
        .id_table =     bulk_storage_idtable,
        .supports_autosuspend = 1,
};

module_usb_driver(bulk_storage_driver);
MODULE_AUTHOR("Soma Nakata");
MODULE_LICENSE("Dual BSD/GPL");
